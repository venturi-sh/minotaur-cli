/**
 * Access to a scanned repository, for the agents. Read-only unless opened
 * writable, which only the fix agent does, on a worktree of its own.
 *
 * Everything the agent can see goes through here, which makes this the
 * boundary that matters: the repository is untrusted input, the paths come
 * from a model, and anything read may be sent to a model provider. So every
 * path is resolved through `realpath` and must stay under the root, symlinks
 * included, and files that tend to hold credentials are refused outright.
 *
 * Each observation is recorded as an input with a hash of what was seen. A
 * cached verdict is only reused while every input still hashes the same, which
 * is what makes the cache honest about what the verdict was based on.
 */

import { createHash } from 'node:crypto';
import { lstat, mkdir, readdir, readFile, realpath, stat, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

import { isSensitiveFile, type AssessmentInput } from '../core/index.js';

export interface WorkspaceLimits {
  /** Characters returned by one read. */
  maxReadChars: number;
  /** Files larger than this are neither read nor searched. */
  maxFileBytes: number;
  /** Matches returned by one search. */
  maxGrepMatches: number;
  /** Files visited by one search, so a huge repository cannot stall a step. */
  maxGrepFiles: number;
  /** Entries returned by one directory listing. */
  maxListEntries: number;
}

export const DEFAULT_LIMITS: WorkspaceLimits = {
  maxReadChars: 20_000,
  maxFileBytes: 1_000_000,
  maxGrepMatches: 60,
  maxGrepFiles: 20_000,
  maxListEntries: 200,
};

/**
 * Directories searched only when asked for by path. Installed dependencies
 * swamp a search for "is this package used by the application", and version
 * control internals are never evidence of anything.
 */
const SKIPPED_DIRS = new Set([
  'node_modules',
  '.venv',
  'venv',
  '__pycache__',
  '.tox',
  'dist',
  'build',
  '.next',
  'target',
  '.gradle',
  '.idea',
]);

/** Never searched, even when named. */
const NEVER_SEARCHED = new Set(['.git']);

/**
 * A search opts into the skipped directories by naming one in its path
 * filter, such as `.venv/` or `node_modules/lodash/`. `site-packages` counts,
 * since it only exists inside a virtualenv.
 */
function namesSkippedDir(pathContains: string | undefined): boolean {
  if (!pathContains) return false;
  return pathContains.split('/').some((segment) => SKIPPED_DIRS.has(segment) || segment === 'site-packages');
}

/**
 * Files a fix may never write. A scanner's ignore file would make a finding
 * disappear without fixing anything, and so would git's own files.
 */
const NEVER_WRITTEN = new Set([
  '.git',
  '.semgrepignore',
  '.opengrepignore',
  '.trivyignore',
  '.trivyignore.yaml',
  '.checkov.yml',
  '.checkov.yaml',
  '.gitleaksignore',
  '.secretlintignore',
]);

export interface WritableOptions {
  /**
   * Repository-relative paths that stay read-only, in addition to the built-in
   * ones. A path ending in `/` covers everything under it.
   */
  readOnly?: readonly string[];
}

export { isSensitiveFile };

export class WorkspaceAccessError extends Error {}

export interface GrepMatch {
  path: string;
  line: number;
  text: string;
}

export interface GrepOptions {
  /** Restrict the search to paths containing this substring, such as `src/` or `.py`. */
  pathContains?: string | undefined;
  ignoreCase?: boolean | undefined;
}

export class Workspace {
  private readonly observed = new Map<string, string>();
  private readonly written = new Set<string>();
  private readonly denied: ReadonlySet<string>;

  private constructor(
    readonly root: string,
    private readonly limits: WorkspaceLimits,
    denied: readonly string[],
    private readonly writable: WritableOptions | null,
  ) {
    this.denied = new Set(denied.map((path) => normalizeRelative(path)));
  }

  /**
   * `denied` lists repository-relative paths to refuse in addition to the
   * built-in sensitive files, typically every path a secret finding points at.
   * Without `writable`, every write is refused.
   */
  static async open(
    root: string,
    options: { limits?: Partial<WorkspaceLimits>; denied?: readonly string[]; writable?: WritableOptions } = {},
  ): Promise<Workspace> {
    return new Workspace(await realpath(root), { ...DEFAULT_LIMITS, ...options.limits }, options.denied ?? [], options.writable ?? null);
  }

  /** Files written so far, repository-relative and sorted. */
  changedFiles(): string[] {
    return [...this.written].sort();
  }

  /** Writes a whole file, creating it and its directories when missing. */
  async writeFile(path: string, content: string): Promise<{ path: string; lines: number }> {
    const { absolute, rel } = await this.resolveWrite(path);
    if (Buffer.byteLength(content) > this.limits.maxFileBytes) throw new WorkspaceAccessError(`too large to write: ${path}`);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, 'utf8');
    this.written.add(rel);
    return { path: rel, lines: content.split('\n').length };
  }

  /**
   * Replaces one exact piece of text. It must occur once, so the edit lands
   * where the model meant it to and nowhere else.
   */
  async replaceInFile(path: string, oldText: string, newText: string): Promise<{ path: string; line: number }> {
    if (oldText.length === 0) throw new WorkspaceAccessError('oldText is empty; use write_file to create a file');
    const { absolute, rel } = await this.resolveWrite(path);
    const text = await this.readText(absolute).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') throw new WorkspaceAccessError(`no such file: ${path}`);
      throw error;
    });
    const at = text.indexOf(oldText);
    if (at < 0) throw new WorkspaceAccessError(`oldText does not occur in ${rel}; read the file again and copy the text exactly`);
    const count = text.split(oldText).length - 1;
    if (count > 1) throw new WorkspaceAccessError(`oldText occurs ${count} times in ${rel}; include more of the surrounding lines`);
    await writeFile(absolute, text.slice(0, at) + newText + text.slice(at + oldText.length), 'utf8');
    this.written.add(rel);
    return { path: rel, line: text.slice(0, at).split('\n').length };
  }

  /** Everything read or searched so far, for caching. */
  inputs(): AssessmentInput[] {
    return [...this.observed.entries()]
      .map(([path, sha256]) => ({ path, sha256 }))
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  async readFile(
    path: string,
    range: { startLine?: number | undefined; endLine?: number | undefined } = {},
  ): Promise<{ path: string; startLine: number; endLine: number; totalLines: number; content: string; truncated: boolean }> {
    const { absolute, rel } = await this.resolve(path);
    const text = await this.readText(absolute);
    this.observed.set(rel, sha256(text));

    const lines = text.split('\n');
    const startLine = clampLine(range.startLine ?? 1, lines.length);
    const endLine = Math.max(startLine, clampLine(range.endLine ?? lines.length, lines.length));

    let content = '';
    let last = startLine - 1;
    for (let index = startLine - 1; index < endLine; index += 1) {
      const next = `${index + 1}: ${lines[index] ?? ''}\n`;
      if (content.length + next.length > this.limits.maxReadChars) break;
      content += next;
      last = index + 1;
    }

    return {
      path: rel,
      startLine,
      endLine: last,
      totalLines: lines.length,
      content,
      truncated: last < endLine,
    };
  }

  /** Reads lines without recording an input, for checking citations after the fact. */
  async lines(path: string, startLine: number, endLine: number): Promise<string[] | undefined> {
    try {
      const { absolute } = await this.resolve(path);
      const lines = (await this.readText(absolute)).split('\n');
      if (startLine < 1 || endLine > lines.length || endLine < startLine) return undefined;
      return lines.slice(startLine - 1, endLine);
    } catch {
      return undefined;
    }
  }

  async grep(pattern: string, options: GrepOptions = {}): Promise<{ matches: GrepMatch[]; truncated: boolean }> {
    let regex: RegExp;
    try {
      regex = new RegExp(pattern, options.ignoreCase ? 'i' : '');
    } catch (error) {
      throw new WorkspaceAccessError(`invalid pattern: ${(error as Error).message}`);
    }

    const matches: GrepMatch[] = [];
    let truncated = false;
    let visited = 0;

    for await (const rel of this.walk('', namesSkippedDir(options.pathContains))) {
      if (options.pathContains && !rel.includes(options.pathContains)) continue;
      visited += 1;
      if (visited > this.limits.maxGrepFiles) {
        truncated = true;
        break;
      }

      const text = await this.readText(join(this.root, rel)).catch(() => undefined);
      if (text === undefined || text.includes('\u0000')) continue;

      const lines = text.split('\n');
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? '';
        // Long lines are minified bundles, and a pathological pattern against
        // one is the easiest way to stall the event loop.
        if (line.length > 2_000) continue;
        if (!regex.test(line)) continue;
        matches.push({ path: rel, line: index + 1, text: line.trim().slice(0, 200) });
        if (matches.length >= this.limits.maxGrepMatches) {
          truncated = true;
          break;
        }
      }
      if (truncated) break;
    }

    this.observed.set(grepKey(pattern, options), sha256(JSON.stringify(matches)));
    return { matches, truncated };
  }

  async listDir(path: string): Promise<{ path: string; entries: string[]; truncated: boolean }> {
    const { absolute, rel } = await this.resolve(path || '.', { allowDirectory: true });
    const dirents = await readdir(absolute, { withFileTypes: true });

    const entries = dirents
      .filter((entry) => !(entry.isFile() && this.isDenied(join(rel, entry.name))))
      .map((entry) => (entry.isDirectory() ? `${entry.name}/` : entry.name))
      .sort();

    const shown = entries.slice(0, this.limits.maxListEntries);
    this.observed.set(`list:${rel || '.'}`, sha256(JSON.stringify(entries)));
    return { path: rel || '.', entries: shown, truncated: shown.length < entries.length };
  }

  /**
   * Recomputes every recorded input against the current tree. True only when
   * each one would have been observed identically, so a verdict built on them
   * still describes this code.
   */
  async unchanged(inputs: readonly AssessmentInput[]): Promise<boolean> {
    if (inputs.length === 0) return false;
    const probe = await Workspace.open(this.root, { limits: this.limits, denied: [...this.denied] });

    for (const input of inputs) {
      try {
        if (input.path.startsWith('grep:')) {
          const { pattern, pathContains, ignoreCase } = JSON.parse(input.path.slice('grep:'.length)) as {
            pattern: string;
            pathContains?: string;
            ignoreCase?: boolean;
          };
          await probe.grep(pattern, { pathContains, ignoreCase });
        } else if (input.path.startsWith('list:')) {
          await probe.listDir(input.path.slice('list:'.length));
        } else {
          await probe.readFile(input.path);
        }
      } catch {
        return false;
      }
    }

    const now = new Map(probe.inputs().map((input) => [input.path, input.sha256]));
    return inputs.every((input) => now.get(input.path) === input.sha256);
  }

  private async resolve(
    path: string,
    options: { allowDirectory?: boolean } = {},
  ): Promise<{ absolute: string; rel: string }> {
    if (isAbsolute(path)) throw new WorkspaceAccessError('paths must be relative to the repository root');

    let absolute: string;
    try {
      absolute = await realpath(resolve(this.root, path));
    } catch {
      throw new WorkspaceAccessError(`no such file: ${path}`);
    }

    if (absolute !== this.root && !absolute.startsWith(this.root + sep)) {
      throw new WorkspaceAccessError(`outside the repository: ${path}`);
    }

    const rel = normalizeRelative(relative(this.root, absolute));
    const info = await stat(absolute);

    if (info.isDirectory()) {
      if (!options.allowDirectory) throw new WorkspaceAccessError(`is a directory: ${path}`);
      return { absolute, rel };
    }
    if (this.isDenied(rel)) throw new WorkspaceAccessError(`refused, may contain credentials: ${path}`);
    if (info.size > this.limits.maxFileBytes) throw new WorkspaceAccessError(`too large to read: ${path}`);
    return { absolute, rel };
  }

  /**
   * Where a write goes, which may not exist yet. The nearest existing
   * directory is resolved through `realpath`, so a symlinked directory cannot
   * lead out of the root, and an existing symlink is never written through.
   */
  private async resolveWrite(path: string): Promise<{ absolute: string; rel: string }> {
    if (!this.writable) throw new WorkspaceAccessError('this workspace is read-only');
    if (isAbsolute(path)) throw new WorkspaceAccessError('paths must be relative to the repository root');
    const lexical = normalizeRelative(relative(this.root, resolve(this.root, path)));
    this.refuseWrite(lexical, path);

    let parent = dirname(join(this.root, lexical));
    while (!(await lstat(parent).catch(() => null))) parent = dirname(parent);
    const realParent = await realpath(parent);
    if (realParent !== this.root && !realParent.startsWith(this.root + sep)) throw new WorkspaceAccessError(`outside the repository: ${path}`);
    const absolute = join(realParent, relative(parent, join(this.root, lexical)));
    // A symlinked directory inside the root can still rename the path, so the rules apply to where it lands too.
    const rel = normalizeRelative(relative(this.root, absolute));
    this.refuseWrite(rel, path);

    const existing = await lstat(absolute).catch(() => null);
    if (existing?.isSymbolicLink()) throw new WorkspaceAccessError(`refused: ${path} is a symbolic link`);
    if (existing?.isDirectory()) throw new WorkspaceAccessError(`is a directory: ${path}`);
    return { absolute, rel };
  }

  private refuseWrite(rel: string, path: string): void {
    if (rel === '' || rel === '..' || rel.startsWith('../')) throw new WorkspaceAccessError(`outside the repository: ${path}`);
    if (rel.split('/').some((segment) => NEVER_WRITTEN.has(segment))) {
      throw new WorkspaceAccessError(`refused: ${path} is a git or scanner ignore file, which a fix may not change`);
    }
    const readOnly = this.writable?.readOnly ?? [];
    if (readOnly.some((entry) => (entry.endsWith('/') ? rel.startsWith(entry) : rel === entry))) {
      throw new WorkspaceAccessError(`refused: ${path} is Minotaur's own configuration, which a fix may not change`);
    }
    if (this.isDenied(rel)) throw new WorkspaceAccessError(`refused, may contain credentials: ${path}`);
  }

  private isDenied(rel: string): boolean {
    return isSensitiveFile(rel) || this.denied.has(normalizeRelative(rel));
  }

  private async readText(absolute: string): Promise<string> {
    const info = await stat(absolute);
    if (info.size > this.limits.maxFileBytes) throw new WorkspaceAccessError('too large to read');
    return readFile(absolute, 'utf8');
  }

  private async *walk(dir: string, intoSkipped: boolean): AsyncGenerator<string> {
    const entries = await readdir(join(this.root, dir), { withFileTypes: true }).catch(() => []);
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const rel = dir ? `${dir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (NEVER_SEARCHED.has(entry.name)) continue;
        if (SKIPPED_DIRS.has(entry.name) && !intoSkipped) continue;
        yield* this.walk(rel, intoSkipped);
      } else if (entry.isFile()) {
        if (this.isDenied(rel)) continue;
        yield rel;
      }
      // Symlinks are skipped while walking: following them is how a search
      // escapes the repository, and reading one by path goes through realpath.
    }
  }
}

function grepKey(pattern: string, options: GrepOptions): string {
  return `grep:${JSON.stringify({
    pattern,
    ...(options.pathContains ? { pathContains: options.pathContains } : {}),
    ...(options.ignoreCase ? { ignoreCase: true } : {}),
  })}`;
}

function normalizeRelative(path: string): string {
  return path.split(sep).join('/').replace(/^\.\//, '');
}

function clampLine(line: number, total: number): number {
  return Math.min(Math.max(1, Math.floor(line)), Math.max(1, total));
}

export function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}
