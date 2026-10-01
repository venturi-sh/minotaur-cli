import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { MANAGED_TOOLS, OPENGREP_RULES, cacheDir, cachedTools, ensureRules, ensureTool, type Artifact, type ManagedTool } from './managed.js';
import { collectFindings, defaultSources } from './sources.js';

let work: string;
let cache: string;
beforeEach(async () => {
  work = await realpath(await mkdtemp(join(tmpdir(), 'minotaur-managed-')));
  cache = join(work, 'cache');
});
afterEach(() => rm(work, { recursive: true, force: true }));

const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');

/** A fetch that serves fixed bytes by URL and counts what was asked for. */
function fakeFetch(files: Record<string, Buffer>) {
  const requested: string[] = [];
  const impl = (async (input: string | URL | Request) => {
    const url = String(input);
    requested.push(url);
    const body = files[url];
    return body ? new Response(new Uint8Array(body)) : new Response('missing', { status: 404 });
  }) as typeof fetch;
  return { impl, requested };
}

async function tarball(entries: Record<string, string>, prefix = ''): Promise<Buffer> {
  const dir = join(work, `pack-${Math.random().toString(36).slice(2)}`);
  for (const [name, content] of Object.entries(entries)) {
    const path = join(dir, prefix, name);
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, content);
    if (!name.includes('.')) await chmod(path, 0o755);
  }
  const archive = `${dir}.tar.gz`;
  execFileSync('tar', ['-czf', archive, '-C', dir, prefix || '.']);
  return readFile(archive);
}

function tool(name: string, artifact: Artifact): Record<string, ManagedTool> {
  return { [name]: { name, version: '9.9.9', artifacts: { 'linux-x64': artifact, 'darwin-arm64': artifact } } };
}

describe('the pinned downloads', () => {
  it('cover every platform for both scanners, each with a checksum', () => {
    for (const managed of Object.values(MANAGED_TOOLS)) {
      expect(Object.keys(managed.artifacts)).toEqual(expect.arrayContaining(['darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64', 'win32-x64']));
      for (const artifact of Object.values(managed.artifacts)) {
        expect(artifact.url).toMatch(/^https:\/\/github\.com\//);
        expect(artifact.url).toContain(managed.version);
        expect(artifact.sha256).toMatch(/^[0-9a-f]{64}$/);
      }
    }
    expect(OPENGREP_RULES.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('cacheDir', () => {
  it('follows each platform, and MINOTAUR_CACHE_DIR wins', () => {
    expect(cacheDir({ MINOTAUR_CACHE_DIR: '/x' }, 'linux')).toBe('/x');
    expect(cacheDir({ XDG_CACHE_HOME: '/xdg' }, 'linux')).toBe('/xdg/minotaur');
    expect(cacheDir({}, 'darwin')).toMatch(/Library\/Caches\/minotaur$/);
  });
});

describe('cachedTools', () => {
  it('names a managed scanner only when that version is already in the cache', async () => {
    const artifact: Artifact = { url: 'https://example.test/fake', sha256: 'a'.repeat(64), bytes: 1 };
    const tools = tool('opengrep', artifact);
    expect(await cachedTools({ cacheDir: cache, platform: 'darwin-arm64', tools })).toEqual([]);
    await mkdir(join(cache, 'opengrep-9.9.9'), { recursive: true });
    await writeFile(join(cache, 'opengrep-9.9.9', 'opengrep'), '');
    expect(await cachedTools({ cacheDir: cache, platform: 'darwin-arm64', tools })).toEqual(['opengrep']);
    expect(await cachedTools({ cacheDir: cache, platform: 'win32-x64', tools })).toEqual([]);
  });
});

describe('ensureTool', () => {
  it('downloads once, checks the checksum, and unpacks the executable', async () => {
    const archive = await tarball({ fake: '#!/bin/sh\necho hi\n', LICENSE: 'x' });
    const artifact: Artifact = { url: 'https://example.test/fake.tar.gz', sha256: sha256(archive), bytes: archive.length, archive: 'tar.gz' };
    const { impl, requested } = fakeFetch({ [artifact.url]: archive });
    const messages: string[] = [];
    const options = { cacheDir: cache, platform: 'linux-x64' as const, fetch: impl, tools: tool('fake', artifact), onDownload: (m: string) => messages.push(m) };

    const path = await ensureTool('fake', options);
    expect(path).toBe(join(cache, 'fake-9.9.9', 'fake'));
    expect(execFileSync(path).toString()).toBe('hi\n');
    expect(await ensureTool('fake', options)).toBe(path);
    expect(requested).toHaveLength(1);
    expect(messages).toEqual([`Downloading fake 9.9.9 (0 MB) into ${cache}, once.`]);
    expect((await readdir(cache)).sort()).toEqual(['fake-9.9.9']);
  });

  it('installs nothing when the checksum does not match', async () => {
    const binary = Buffer.from('#!/bin/sh\necho tampered\n');
    const artifact: Artifact = { url: 'https://example.test/fake', sha256: 'a'.repeat(64), bytes: binary.length };
    const { impl } = fakeFetch({ [artifact.url]: binary });

    await expect(ensureTool('fake', { cacheDir: cache, platform: 'linux-x64', fetch: impl, tools: tool('fake', artifact) })).rejects.toThrow(
      /does not match its pinned checksum/,
    );
    expect(await readdir(cache)).toEqual([]);
  });

  it('explains a failed download and a platform with no build', async () => {
    const artifact: Artifact = { url: 'https://example.test/gone', sha256: 'a'.repeat(64), bytes: 1 };
    const { impl } = fakeFetch({});
    await expect(ensureTool('fake', { cacheDir: cache, platform: 'linux-x64', fetch: impl, tools: tool('fake', artifact) })).rejects.toThrow(
      /could not download https:\/\/example.test\/gone: HTTP 404/,
    );
    await expect(ensureTool('trivy', { cacheDir: cache, platform: null })).rejects.toThrow(/no download of it/);
    await expect(ensureTool('checkov', { cacheDir: cache })).rejects.toThrow(/not a scanner Minotaur can download/);
  });
});

describe('ensureRules', () => {
  it('unpacks the rules and drops the files that are not rules', async () => {
    const archive = await tarball(
      {
        'javascript/eval.yaml': 'rules: []\n',
        'yaml/k8s.yaml': 'rules: []\n',
        'yaml/k8s.test.yaml': 'kind: Pod\n',
        '.pre-commit-config.yaml': 'repos: []\n',
        'semgrep.yml': 'x: 1\n',
        'scripts/run.py': 'print(1)\n',
      },
      'opengrep-rules-abc',
    );
    const rules: Artifact = { url: 'https://example.test/rules.tgz', sha256: sha256(archive), bytes: archive.length, archive: 'tar.gz' };
    const { impl } = fakeFetch({ [rules.url]: archive });

    const dir = await ensureRules({ cacheDir: cache, fetch: impl, rules });
    expect(dir).toMatch(/\/opengrep-rules$/);
    expect((await readdir(dir)).sort()).toEqual(['javascript', 'yaml']);
    expect(await readdir(join(dir, 'yaml'))).toEqual(['k8s.yaml']);
  });
});

describe('scanning with a downloaded scanner', () => {
  it('fetches opengrep and its rules, and runs it on the code', async () => {
    const repo = join(work, 'repo');
    await mkdir(repo);
    await writeFile(join(repo, 'app.js'), 'eval(req.query.code);\n');

    // Stands in for opengrep: reports one finding under the rules directory it was given.
    const fake = Buffer.from(
      [
        '#!/bin/sh',
        'config=""; for arg in "$@"; do case "$prev" in --config) [ -z "$config" ] && config="$arg";; esac; prev="$arg"; last="$arg"; done',
        'id=$(echo "$config" | tr / .).browser.security.eval-detected',
        `printf '{"results":[{"check_id":"%s","path":"%s/app.js","start":{"line":1},"end":{"line":1},"extra":{"severity":"ERROR","lines":"eval(req.query.code);"}}],"errors":[]}' "$id" "$last"`,
        '',
      ].join('\n'),
    );
    const binary: Artifact = { url: 'https://example.test/opengrep', sha256: sha256(fake), bytes: fake.length };
    const archive = await tarball({ 'javascript/eval.yaml': 'rules: []\n' }, 'opengrep-rules-abc');
    const rules: Artifact = { url: 'https://example.test/rules.tgz', sha256: sha256(archive), bytes: archive.length, archive: 'tar.gz' };
    const { impl } = fakeFetch({ [binary.url]: fake, [rules.url]: archive });

    // Only the system tools the download and the stand-in need, so no real scanner is found.
    const bin = join(work, 'bin');
    await mkdir(bin);
    for (const name of ['tar', 'tr', 'gzip']) {
      const real = execFileSync('/bin/sh', ['-c', `command -v ${name}`]).toString().trim();
      if (real) await symlink(real, join(bin, name));
    }
    const path = process.env['PATH'];
    process.env['PATH'] = bin;
    try {
      expect(await defaultSources(repo)).toEqual([{ scanner: 'trivy' }, { scanner: 'opengrep' }]);
      const result = await collectFindings(repo, [{ scanner: 'opengrep' }], {
        managed: { cacheDir: cache, platform: 'darwin-arm64', fetch: impl, tools: tool('opengrep', binary), rules },
      });
      expect(result.sources[0]).toMatchObject({ status: 'ok', findings: 1 });
      expect(result.findings[0]).toMatchObject({
        ruleId: 'javascript.browser.security.eval-detected',
        tool: { name: 'opengrep' },
        location: { path: 'app.js', startLine: 1 },
      });
    } finally {
      process.env['PATH'] = path;
    }
  });

  it('skips opengrep when there is no code it has rules for', async () => {
    const repo = join(work, 'docs');
    await mkdir(repo);
    await writeFile(join(repo, 'README.md'), '# hi\n');
    const result = await collectFindings(repo, [{ scanner: 'opengrep' }], { managed: { cacheDir: cache } });
    expect(result.sources[0]).toMatchObject({ status: 'skipped', error: 'no code in a language the Opengrep rules cover' });
  });
});
