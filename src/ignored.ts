/**
 * Which paths git ignores. Findings there stay out of the list, and scanners
 * that would otherwise walk them are told to skip them. A report can still
 * name an ignored file, and a secret in one still keeps that file from the model.
 */

import { spawn } from 'node:child_process';

/** A path no ignore rule names, so it is only ignored when the whole directory is. */
const PROBE = '.minotaur-probe-3f9a1c2e';

/**
 * The given repository-relative paths that git ignores. Null when the directory
 * is not in a git work tree, or is itself ignored by an enclosing repository,
 * since the person asked to scan it anyway.
 */
export async function gitIgnored(root: string, paths: readonly string[]): Promise<Set<string> | null> {
  const output = await checkIgnore(root, [PROBE, ...paths]);
  if (output === null) return null;
  const ignored = new Set(output.split('\0').filter(Boolean));
  if (ignored.has(PROBE)) return null;
  return ignored;
}

export interface IgnoredPaths {
  dirs: string[];
  files: string[];
}

/**
 * Ignored files and directories, with a fully ignored directory named once
 * rather than every file inside it. Null outside a work tree.
 */
export async function ignoredPaths(root: string): Promise<IgnoredPaths | null> {
  const listed = await gitOutput(root, ['ls-files', '--others', '--ignored', '--exclude-standard', '--directory', '-z']);
  if (listed === null) return null;
  const dirs: string[] = [];
  const files: string[] = [];
  for (const path of listed.split('\0').filter(Boolean)) {
    if (path.endsWith('/')) dirs.push(path.slice(0, -1));
    else files.push(path);
  }
  dirs.sort();
  files.sort();
  return { dirs, files };
}

/**
 * Flags that keep a scanner out of gitignored paths. Opengrep and Semgrep
 * already consult `.gitignore`, so they need none.
 */
export function scannerSkipArgs(scanner: string, ignored: IgnoredPaths): string[] {
  if (scanner !== 'trivy') return [];
  return [...ignored.dirs.flatMap((dir) => ['--skip-dirs', dir]), ...ignored.files.flatMap((file) => ['--skip-files', file])];
}

/** `git check-ignore` exits 1 when nothing is ignored and 128 outside a work tree. */
function checkIgnore(cwd: string, paths: readonly string[]): Promise<string | null> {
  return new Promise((resolve) => {
    const child = spawn('git', ['check-ignore', '-z', '--stdin'], { cwd, stdio: ['pipe', 'pipe', 'ignore'] });
    const chunks: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    child.on('error', () => resolve(null));
    child.on('close', (code) => resolve(code === 0 || code === 1 ? Buffer.concat(chunks).toString('utf8') : null));
    child.stdin.on('error', () => resolve(null));
    child.stdin.end(paths.map((path) => `${path}\0`).join(''));
  });
}

function gitOutput(cwd: string, args: readonly string[]): Promise<string | null> {
  return new Promise((resolve) => {
    const child = spawn('git', args, { cwd, stdio: ['ignore', 'pipe', 'ignore'] });
    const chunks: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    child.on('error', () => resolve(null));
    child.on('close', (code) => resolve(code === 0 ? Buffer.concat(chunks).toString('utf8') : null));
  });
}
