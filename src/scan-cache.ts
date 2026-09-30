/**
 * The last scan of each repository, reused while nothing it depends on has
 * changed: the commit, the sources and the scanners, and on the working tree
 * the files git ignores too (a secret there still protects the file). Entries
 * also expire, because a scanner's vulnerability database moves on even when
 * the code does not.
 */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, realpath, rename, stat, writeFile } from 'node:fs/promises';
import { delimiter, isAbsolute, join, resolve } from 'node:path';

import { localScannerByName } from './scanners/index.js';
import { z } from 'zod';

import type { Target } from './commit.js';
import type { SourceConfig } from './config.js';
import { MANAGED_TOOLS, OPENGREP_RULES } from './managed.js';
import { findingsFileSchema } from './output.js';
import type { CollectResult, LocalFinding } from './sources.js';

const FORMAT = 3;
export const SCAN_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export interface CachedScan {
  result: CollectResult;
  createdAt: number;
}

const entrySchema = z.object({
  format: z.literal(FORMAT),
  root: z.string(),
  key: z.string(),
  createdAt: z.number(),
  findings: findingsFileSchema.shape.findings,
  sources: z.array(
    z.object({
      source: z.string(),
      status: z.enum(['ok', 'failed', 'skipped']),
      findings: z.number(),
      durationMs: z.number(),
      error: z.string().optional(),
    }),
  ),
  ignored: z.number(),
  protectedPaths: z.array(z.string()),
});

/**
 * A digest of everything the scan result depends on, or null when git cannot
 * list the ignored files. `tree` is where the scan runs, as `treeFor` gives it.
 */
export async function scanKey(
  target: Target,
  tree: string,
  sources: readonly SourceConfig[],
  includeIgnored: boolean,
): Promise<string | null> {
  const hash = createHash('sha256');
  const { repo, copy, prefix } = target;
  hash.update(JSON.stringify({ format: FORMAT, repo, commit: target.commit.sha, copy, prefix, includeIgnored, sources, tools: pinnedTools() }));
  if (!copy) {
    const ignoredList = await git(target.top, ['ls-files', '--others', '--ignored', '--exclude-standard', '-z']);
    if (ignoredList === null) return null;
    for (const path of ignoredList.split('\0').filter(Boolean)) {
      const info = await lstat(join(target.top, path)).catch(() => null);
      hash.update(`${path}\0${info?.size ?? -1}\0${info?.mtimeMs ?? -1}\0`);
    }
  }
  for (const source of sources) hash.update(`${await sourceStamp(tree, source)}\0`);
  return hash.digest('hex');
}

/** The cached scan for this key, unless it is missing, damaged or older than `maxAgeMs`. */
export async function readCachedScan(
  dir: string,
  root: string,
  key: string,
  now = Date.now(),
  maxAgeMs = SCAN_MAX_AGE_MS,
): Promise<CachedScan | null> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(entryPath(dir, root), 'utf8'));
  } catch {
    return null;
  }
  const parsed = entrySchema.safeParse(raw);
  if (!parsed.success) return null;
  const entry = parsed.data;
  if (entry.root !== root || entry.key !== key || now - entry.createdAt > maxAgeMs || entry.createdAt > now) return null;
  return {
    createdAt: entry.createdAt,
    result: {
      findings: entry.findings,
      sources: entry.sources.map(({ error, ...outcome }) => (error === undefined ? outcome : { ...outcome, error })),
      ignored: entry.ignored,
      protectedPaths: entry.protectedPaths,
    },
  };
}

/** Replaces the repository's cached scan. A scan where a source failed is not kept, so the next run tries again. */
export async function writeCachedScan(dir: string, root: string, key: string, result: CollectResult, now = Date.now()): Promise<boolean> {
  if (result.sources.some((source) => source.status === 'failed')) return false;
  const entry = {
    format: FORMAT,
    root,
    key,
    createdAt: now,
    findings: result.findings.map(withoutSecretSnippet),
    sources: result.sources,
    ignored: result.ignored,
    protectedPaths: result.protectedPaths,
  };
  // Findings quote code, so the cache is readable by this user only.
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const path = entryPath(dir, root);
  const staging = `${path}.${process.pid}.tmp`;
  await writeFile(staging, JSON.stringify(entry), { mode: 0o600 });
  await rename(staging, path);
  return true;
}

export function scanCacheDir(cache: string): string {
  return join(cache, 'scans');
}

/** "12 minutes ago", for saying how old a cached scan is. */
export function describeAge(ms: number): string {
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 1) return 'less than a minute ago';
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  return `${Math.floor(hours / 24)} days ago`;
}

function entryPath(dir: string, root: string): string {
  return join(dir, `${createHash('sha256').update(root).digest('hex').slice(0, 16)}.json`);
}

function withoutSecretSnippet(finding: LocalFinding): LocalFinding {
  if (finding.kind !== 'secret' || !finding.location?.snippet) return finding;
  const { snippet: _snippet, ...location } = finding.location;
  return { ...finding, location };
}

function pinnedTools() {
  return {
    tools: Object.fromEntries(Object.entries(MANAGED_TOOLS).map(([name, tool]) => [name, tool.version])),
    rules: OPENGREP_RULES.sha256,
  };
}

/** Which scanner binary would run, or which report would be read, and its size and age. */
async function sourceStamp(root: string, source: SourceConfig): Promise<string> {
  if ('report' in source) {
    const path = isAbsolute(source.report) ? source.report : resolve(root, source.report);
    return `${path}:${await fileStamp(path)}`;
  }
  const binary = localScannerByName(source.scanner)?.native?.binary ?? source.scanner;
  for (const dir of (process.env['PATH'] ?? '').split(delimiter).filter(Boolean)) {
    const path = await realpath(join(dir, binary)).catch(() => null);
    if (path) return `${path}:${await fileStamp(path)}`;
  }
  return `${binary}:managed`;
}

async function fileStamp(path: string): Promise<string> {
  const info = await stat(path).catch(() => null);
  return info ? `${info.size}:${info.mtimeMs}` : 'missing';
}

function git(cwd: string, args: readonly string[]): Promise<string | null> {
  return new Promise((done) => {
    const child = spawn('git', args, { cwd, stdio: ['ignore', 'pipe', 'ignore'] });
    const chunks: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    child.on('error', () => done(null));
    child.on('close', (code) => done(code === 0 ? Buffer.concat(chunks).toString('utf8') : null));
  });
}
