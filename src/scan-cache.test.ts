import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveTarget } from './commit.js';
import type { SourceConfig } from './config.js';
import { describeAge, matchCachedScan, readCachedScan, scanKey, writeCachedScan } from './scan-cache.js';
import { toLocal, type CollectResult } from './sources.js';

const REPORT = [{ report: 'report.sarif' }];

function result(overrides: Partial<CollectResult> = {}): CollectResult {
  return {
    findings: toLocal([
      {
        fingerprint: 'a'.repeat(64),
        kind: 'secret',
        severity: 'critical',
        title: 'AWS key',
        vulnerabilityIds: [],
        references: [],
        location: { path: 'config/local.json', startLine: 2, snippet: 'AKIA1234567890ABCDEF' },
        tool: { name: 'trivy', version: '1' },
        tools: [],
      },
    ]),
    sources: [{ source: 'trivy', status: 'ok', findings: 1, durationMs: 5 }],
    ignored: 0,
    protectedPaths: ['config/local.json'],
    ...overrides,
  };
}

describe('scan cache', () => {
  let repo: string;
  let cache: string;
  const run = (...args: string[]) => execFileSync('git', args, { cwd: repo, stdio: 'ignore' });

  beforeEach(async () => {
    repo = await realpath(await mkdtemp(join(tmpdir(), 'minotaur-cache-repo-')));
    cache = join(await mkdtemp(join(tmpdir(), 'minotaur-cache-')), 'scans');
    run('init', '-q');
    await writeFile(join(repo, '.gitignore'), 'node_modules/\n.env\n');
    await writeFile(join(repo, 'app.js'), 'one\n');
    await writeFile(join(repo, 'report.sarif'), '{}');
    run('add', '.');
    run('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'init');
  });

  afterEach(async () => {
    await rm(repo, { recursive: true, force: true });
    await rm(join(cache, '..'), { recursive: true, force: true });
  });

  const keyOf = async (sources: SourceConfig[] = REPORT, includeIgnored = false, ref?: string) =>
    scanKey(await resolveTarget(repo, ref), repo, sources, includeIgnored);

  it('gives the same key while nothing changes', async () => {
    const key = await keyOf();
    expect(key).toMatch(/^[0-9a-f]{64}$/);
    expect(await keyOf()).toBe(key);
  });

  it('changes the key with the commit and the sources, not with ignored or uncommitted files', async () => {
    const baseline = await keyOf();
    const withIgnored = await keyOf(REPORT, true);
    expect(withIgnored).not.toBe(baseline);
    expect(await keyOf([{ scanner: 'trivy' }])).not.toBe(baseline);

    await writeFile(join(repo, '.env'), 'TOKEN=1\n');
    await mkdir(join(repo, 'node_modules', 'pkg'), { recursive: true });
    await writeFile(join(repo, 'node_modules', 'pkg', 'index.js'), 'x\n');
    expect(await keyOf()).toBe(baseline);
    // Ignored files are not in the commit copy, so --include-ignored does not see them either.
    expect(await keyOf(REPORT, true)).toBe(withIgnored);
    await writeFile(join(repo, '.env'), 'TOKEN=2\n');
    expect(await keyOf(REPORT, true)).toBe(withIgnored);

    await writeFile(join(repo, 'report.sarif'), '{"runs":[]}');
    run('add', '.');
    run('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'next');
    expect(await keyOf()).not.toBe(baseline);
  });

  it('keeps the key of a commit while uncommitted changes come and go, since they are not scanned', async () => {
    const key = await keyOf();
    await writeFile(join(repo, 'app.js'), 'two\n');
    expect(await keyOf()).toBe(key);
    await writeFile(join(repo, 'app.js'), 'owt\n');
    await writeFile(join(repo, 'new.js'), 'x\n');
    expect(await keyOf()).toBe(key);
    expect(await keyOf(REPORT, false, 'HEAD')).toBe(key);
  });

  it('reads back what it wrote, without secret snippets, for this user only', async () => {
    const key = (await keyOf())!;
    expect(await writeCachedScan(cache, repo, key, result(), 1_000)).toBe(true);

    const cached = await readCachedScan(cache, repo, key, 2_000);
    expect(cached?.createdAt).toBe(1_000);
    expect(cached?.result.protectedPaths).toEqual(['config/local.json']);
    expect(cached?.result.findings[0]?.location).toEqual({ path: 'config/local.json', startLine: 2 });

    const [file] = await readdir(cache);
    expect(await readFile(join(cache, file!), 'utf8')).not.toContain('AKIA');
    expect((await stat(join(cache, file!))).mode & 0o777).toBe(0o600);
  });

  it('misses on another key, an expired entry, or a damaged file', async () => {
    const key = (await keyOf())!;
    await writeCachedScan(cache, repo, key, result(), 1_000);
    expect(await readCachedScan(cache, repo, 'other', 2_000)).toBeNull();
    expect(await readCachedScan(cache, repo, key, 1_000 + 25 * 60 * 60 * 1000)).toBeNull();

    const [file] = await readdir(cache);
    await writeFile(join(cache, file!), '{"format":1');
    expect(await readCachedScan(cache, repo, key, 2_000)).toBeNull();
  });

  it('reuses a scan of the same commit when an ignored file changes, unless a new scanner is installed', async () => {
    const target = await resolveTarget(repo, undefined);
    const sources: SourceConfig[] = [{ scanner: 'trivy' }, { scanner: 'opengrep' }];
    const key = (await scanKey(target, repo, sources, false))!;
    const saved = result({
      sources: [
        { source: 'trivy', status: 'ok', findings: 1, durationMs: 1 },
        { source: 'opengrep', status: 'ok', findings: 0, durationMs: 1 },
      ],
    });
    expect(await writeCachedScan(cache, repo, key, saved, 1_000)).toBe(true);

    const hit = await matchCachedScan(cache, target, repo, false, [], 2_000);
    expect(hit?.createdAt).toBe(1_000);
    expect(hit?.result.findings).toHaveLength(1);
    expect(await matchCachedScan(cache, target, repo, false, ['grype'], 2_000)).toBeNull();

    await writeFile(join(repo, '.env'), 'TOKEN=1\n');
    expect((await matchCachedScan(cache, target, repo, false, [], 2_000))?.createdAt).toBe(1_000);
  });

  it('keeps the sources that finished when a later one failed', async () => {
    const failed = result({
      sources: [
        { source: 'trivy', status: 'ok', findings: 1, durationMs: 5 },
        { source: 'opengrep', status: 'failed', findings: 0, durationMs: 5, error: 'boom' },
      ],
    });
    expect(await writeCachedScan(cache, repo, 'key', failed, 1_000)).toBe(true);
    const cached = await readCachedScan(cache, repo, 'key', 2_000);
    expect(cached?.result.sources).toEqual([{ source: 'trivy', status: 'ok', findings: 1, durationMs: 5 }]);
    expect(cached?.result.findings).toHaveLength(1);
  });

  it('writes nothing when every source failed', async () => {
    const failed = result({
      findings: [],
      protectedPaths: [],
      sources: [{ source: 'opengrep', status: 'failed', findings: 0, durationMs: 5, error: 'boom' }],
    });
    expect(await writeCachedScan(cache, repo, 'key', failed)).toBe(false);
    expect(await readCachedScan(cache, repo, 'key')).toBeNull();
  });

  it('does not treat a scan that only finished some sources as the whole scan', async () => {
    const target = await resolveTarget(repo, undefined);
    const sources: SourceConfig[] = [{ scanner: 'trivy' }, { scanner: 'opengrep' }];
    const key = (await scanKey(target, repo, sources, false))!;
    expect(await writeCachedScan(cache, repo, key, result(), 1_000)).toBe(true);

    expect(await matchCachedScan(cache, target, repo, false, [], 2_000)).toBeNull();
    const cached = await readCachedScan(cache, repo, key, 2_000);
    expect(cached?.result.sources.map((source) => source.source)).toEqual(['trivy']);
  });

  it('says how old a scan is', () => {
    expect(describeAge(30_000)).toBe('less than a minute ago');
    expect(describeAge(60_000)).toBe('1 minute ago');
    expect(describeAge(12 * 60_000)).toBe('12 minutes ago');
    expect(describeAge(3 * 60 * 60_000)).toBe('3 hours ago');
    expect(describeAge(3 * 24 * 60 * 60_000)).toBe('3 days ago');
  });
});
