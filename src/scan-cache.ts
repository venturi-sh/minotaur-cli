/**
 * The last scan of each repository, reused while nothing it depends on has
 * changed: the commit, the sources and the scanners. The working tree is never
 * part of that. Entries also expire, because a scanner's vulnerability
 * database moves on even when the code does not.
 */

import { createHash } from 'node:crypto';
import { mkdir, readFile, realpath, rename, stat, writeFile } from 'node:fs/promises';
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
 * A digest of everything the scan result depends on. `tree` is the clean copy
 * of the commit where the scan runs, as `treeFor` gives it.
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
  const entry = await loadEntry(dir, root);
  if (!entry || entry.key !== key || now - entry.createdAt > maxAgeMs || entry.createdAt > now) return null;
  return toCached(entry);
}

/**
 * The cached scan when running the same scanners again would produce the same
 * key. `installed` is what is on PATH; a scanner that was not part of the
 * cached run needs a fresh look at the tree, so this returns null. A scan that
 * only finished some of its sources stores the key of the full list, which this
 * rebuild does not reproduce, so this returns null and the caller runs the rest.
 */
export async function matchCachedScan(
  dir: string,
  target: Target,
  tree: string,
  includeIgnored: boolean,
  installed: readonly string[],
  now = Date.now(),
  maxAgeMs = SCAN_MAX_AGE_MS,
): Promise<CachedScan | null> {
  const entry = await loadEntry(dir, target.repo);
  if (!entry || now - entry.createdAt > maxAgeMs || entry.createdAt > now) return null;
  const names = entry.sources.map((source) => source.source);
  if (names.some((name) => !localScannerByName(name))) return null;
  if (sourcesChanged(names, installed)) return null;
  const key = await scanKey(
    target,
    tree,
    names.map((scanner) => ({ scanner })),
    includeIgnored,
  );
  if (key !== entry.key) return null;
  return toCached(entry);
}

/**
 * Replaces the repository's cached scan with the sources that finished.
 * A failed source is left out, so the next run retries it and keeps the rest.
 * Nothing is written when every source failed.
 */
export async function writeCachedScan(dir: string, root: string, key: string, result: CollectResult, now = Date.now()): Promise<boolean> {
  const sources = result.sources.filter((source) => source.status !== 'failed');
  if (sources.length === 0) return false;
  const entry = {
    format: FORMAT,
    root,
    key,
    createdAt: now,
    findings: result.findings.map(withoutSecretSnippet),
    sources,
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

type Entry = z.infer<typeof entrySchema>;

async function loadEntry(dir: string, root: string): Promise<Entry | null> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(entryPath(dir, root), 'utf8'));
  } catch {
    return null;
  }
  const parsed = entrySchema.safeParse(raw);
  if (!parsed.success || parsed.data.root !== root) return null;
  return parsed.data;
}

function toCached(entry: Entry): CachedScan {
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

/**
 * True when a scanner on PATH was not part of the cached run, or Semgrep and
 * Opengrep have swapped. Either one can change which sources run.
 */
function sourcesChanged(cached: readonly string[], installed: readonly string[]): boolean {
  const have = new Set(cached);
  const semgrep = installed.includes('semgrep');
  if (semgrep && have.has('opengrep')) return true;
  if (!semgrep && have.has('semgrep')) return true;
  return installed.some((name) => name !== 'semgrep' && !have.has(name));
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
