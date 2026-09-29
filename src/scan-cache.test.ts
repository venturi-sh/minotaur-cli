import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveTarget } from './commit.js';
import type { SourceConfig } from './config.js';
import { describeAge, readCachedScan, scanKey, writeCachedScan } from './scan-cache.js';
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
    await writeFile(join(repo, '.gitignore'), 'build/\n');
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

  it('changes the key with the commit, the sources, the ignored-file option and ignored files', async () => {
    const keys = new Set([await keyOf()]);
    keys.add(await keyOf(REPORT, true));
    keys.add(await keyOf([{ scanner: 'trivy' }]));

    await mkdir(join(repo, 'build'));
    await writeFile(join(repo, 'build', 'secret.json'), '{}');
    keys.add(await keyOf());
    const later = new Date(Date.now() + 60_000);
    await utimes(join(repo, 'build', 'secret.json'), later, later);
    keys.add(await keyOf());

    await writeFile(join(repo, 'report.sarif'), '{"runs":[]}');
    run('add', '.');
    run('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'next');
    keys.add(await keyOf());
    expect(keys.size).toBe(6);
  });

  it('keeps the key of a commit while uncommitted changes come and go, since they are not scanned', async () => {
    await writeFile(join(repo, 'app.js'), 'two\n');
    const key = await keyOf();
    await writeFile(join(repo, 'app.js'), 'owt\n');
    await writeFile(join(repo, 'new.js'), 'x\n');
    expect(await keyOf()).toBe(key);
    expect(await keyOf(REPORT, false, 'HEAD')).toBe(key);
  });

  it('has no key outside a git work tree', async () => {
    const plain = await realpath(await mkdtemp(join(tmpdir(), 'minotaur-plain-')));
    try {
      expect(await scanKey(await resolveTarget(plain, undefined), plain, REPORT, false)).toBeNull();
    } finally {
      await rm(plain, { recursive: true, force: true });
    }
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

  it('does not keep a scan where a source failed', async () => {
    const failed = result({
      sources: [
        { source: 'trivy', status: 'ok', findings: 1, durationMs: 5 },
        { source: 'opengrep', status: 'failed', findings: 0, durationMs: 5, error: 'boom' },
      ],
    });
    expect(await writeCachedScan(cache, repo, 'key', failed)).toBe(false);
    expect(await readCachedScan(cache, repo, 'key')).toBeNull();
  });

  it('says how old a scan is', () => {
    expect(describeAge(30_000)).toBe('less than a minute ago');
    expect(describeAge(60_000)).toBe('1 minute ago');
    expect(describeAge(12 * 60_000)).toBe('12 minutes ago');
    expect(describeAge(3 * 60 * 60_000)).toBe('3 hours ago');
    expect(describeAge(3 * 24 * 60 * 60_000)).toBe('3 days ago');
  });
});
