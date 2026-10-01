import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { Finding } from './core/index.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { ignoredPaths, scannerSkipArgs } from './ignored.js';
import { collectFindings, resolveFinding, scanCovers, secretPaths, toLocal } from './sources.js';

function finding(overrides: Partial<Finding> & Pick<Finding, 'fingerprint'>): Finding {
  return {
    kind: 'sast',
    severity: 'medium',
    title: 't',
    vulnerabilityIds: [],
    references: [],
    tool: { name: 'semgrep', version: '1' },
    tools: [],
    ...overrides,
  };
}

const fp = (prefix: string) => prefix.padEnd(64, '0');

describe('toLocal', () => {
  it('adds short ids, drops raw payloads and sorts the worst first', () => {
    const local = toLocal([
      finding({ fingerprint: fp('aa'), severity: 'low', raw: { big: true } }),
      finding({ fingerprint: fp('bb'), severity: 'critical' }),
    ]);
    expect(local.map((item) => [item.id, item.severity])).toEqual([
      ['bb000000', 'critical'],
      ['aa000000', 'low'],
    ]);
    expect(local[1]).not.toHaveProperty('raw');
  });
});

describe('resolveFinding', () => {
  const findings = toLocal([finding({ fingerprint: fp('abcd1') }), finding({ fingerprint: fp('abcd2') })]);

  it('accepts any unique prefix', () => {
    expect(resolveFinding(findings, 'ABCD1').fingerprint).toBe(fp('abcd1'));
  });

  it('explains missing, ambiguous and too-short ids', () => {
    expect(() => resolveFinding(findings, 'ffff')).toThrow(/no finding with id ffff/);
    expect(() => resolveFinding(findings, 'abcd')).toThrow(/matches 2 findings/);
    expect(() => resolveFinding(findings, 'ab')).toThrow(/at least 4/);
  });
});

describe('secretPaths', () => {
  it('collects the files secret findings point at', () => {
    const findings = toLocal([
      finding({ fingerprint: fp('1'), kind: 'secret', location: { path: 'config/deploy.py' } }),
      finding({ fingerprint: fp('2'), location: { path: 'app.js' } }),
    ]);
    expect(secretPaths(findings)).toEqual(new Set(['config/deploy.py']));
  });
});

describe('collectFindings', () => {
  let root: string;
  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'minotaur-sources-')));
    await writeFile(join(root, 'app.js'), 'eval(req.query.code);\n');
  });
  afterEach(() => rm(root, { recursive: true, force: true }));

  const report = (path: string) =>
    JSON.stringify({
      results: [{ check_id: 'eval-detected', path, start: { line: 1 }, end: { line: 1 }, extra: { severity: 'ERROR' } }],
      errors: [],
      paths: { scanned: [path] },
    });

  it('merges sources, deduplicates and reports each one', async () => {
    await writeFile(join(root, 'a.json'), report(join(root, 'app.js')));
    await writeFile(join(root, 'b.json'), report('app.js'));
    const seen: string[] = [];
    const result = await collectFindings(root, [{ report: 'a.json' }, { report: join(root, 'b.json') }], {
      onSource: (outcome) => seen.push(`${outcome.source}:${outcome.status}:${outcome.findings}`),
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.location?.path).toBe('app.js');
    expect(seen).toEqual(['a.json:ok:1', `${join(root, 'b.json')}:ok:1`]);
  });

  it('passes on the findings so far after each source that found any', async () => {
    await writeFile(join(root, 'other.js'), 'eval(x);\n');
    await writeFile(join(root, 'a.json'), report('app.js'));
    await writeFile(join(root, 'b.json'), report('other.js'));
    const partials: string[][] = [];
    const result = await collectFindings(root, [{ report: 'a.json' }, { report: 'missing.json' }, { report: 'b.json' }], {
      onFindings: (partial) => partials.push(partial.findings.map((item) => item.location?.path ?? '')),
    });
    expect(partials).toEqual([['app.js'], ['app.js', 'other.js']]);
    expect(result.findings).toHaveLength(2);
  });

  it('keeps going when one source fails, and fails when all do', async () => {
    await writeFile(join(root, 'a.json'), report('app.js'));
    const partial = await collectFindings(root, [{ report: 'a.json' }, { report: 'missing.json' }]);
    expect(partial.findings).toHaveLength(1);
    expect(partial.sources[1]).toMatchObject({ status: 'failed' });

    await expect(collectFindings(root, [{ report: 'missing.json' }, { scanner: 'nonsense' }])).rejects.toThrow(
      /every source failed/,
    );
  });

  it('reports a scanner that is not installed', async () => {
    await writeFile(join(root, 'a.json'), report('app.js'));
    const result = await collectFindings(root, [{ report: 'a.json' }, { scanner: 'checkov' }]);
    const checkov = result.sources.find((outcome) => outcome.source === 'checkov');
    // Checkov may genuinely be installed on a developer machine; either way the run must not fail.
    expect(['ok', 'failed']).toContain(checkov?.status);
  });

  it('tells Trivy to skip gitignored paths, and leaves Opengrep to git', async () => {
    execFileSync('git', ['init', '-q'], { cwd: root });
    await writeFile(join(root, '.gitignore'), 'node_modules/\n.env\n');
    await mkdir(join(root, 'node_modules', 'pkg'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'pkg', 'index.js'), 'x\n');
    await writeFile(join(root, '.env'), 'TOKEN=1\n');
    const ignored = await ignoredPaths(root);
    expect(ignored).toEqual({ dirs: ['node_modules'], files: ['.env'] });
    expect(scannerSkipArgs('trivy', ignored!)).toEqual(['--skip-dirs', 'node_modules', '--skip-files', '.env']);
    expect(scannerSkipArgs('opengrep', ignored!)).toEqual([]);
    expect(await ignoredPaths(join(root, 'missing'))).toBeNull();
  });

  it('leaves out findings in files git ignores, but keeps their secrets protecting them', async () => {
    execFileSync('git', ['init', '-q'], { cwd: root });
    await writeFile(join(root, '.gitignore'), 'dist/\nlocal.json\n');
    const run = (tool: string, ruleId: string, uris: string[]) => ({
      tool: { driver: { name: tool } },
      results: uris.map((uri) => ({
        ruleId,
        locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } } }],
      })),
    });
    await writeFile(
      join(root, 'report.sarif'),
      JSON.stringify({
        version: '2.1.0',
        runs: [run('semgrep', 'eval-detected', ['app.js', 'dist/bundle.js']), run('gitleaks', 'github-pat', ['local.json'])],
      }),
    );

    const hidden = await collectFindings(root, [{ report: 'report.sarif' }]);
    expect(hidden.findings.map((finding) => finding.location?.path)).toEqual(['app.js']);
    expect(hidden.ignored).toBe(2);
    expect(hidden.protectedPaths).toEqual(['local.json']);

    const all = await collectFindings(root, [{ report: 'report.sarif' }], { includeIgnored: true });
    expect(all.findings).toHaveLength(3);
    expect(all.ignored).toBe(0);
  });

  it('skips a finished source, shows it first, and settles before the next one starts', async () => {
    await writeFile(join(root, 'other.js'), 'eval(x);\n');
    await writeFile(join(root, 'a.json'), report('app.js'));
    await writeFile(join(root, 'empty.json'), JSON.stringify({ results: [], errors: [], paths: { scanned: [] } }));
    await writeFile(join(root, 'b.json'), report('other.js'));
    const first = await collectFindings(root, [{ report: 'a.json' }]);
    expect(scanCovers(first, [{ report: 'a.json' }])).toBe(true);
    expect(scanCovers(first, [{ report: 'a.json' }, { report: 'b.json' }])).toBe(false);
    await rm(join(root, 'a.json'));

    const events: string[] = [];
    const result = await collectFindings(root, [{ report: 'a.json' }, { report: 'empty.json' }, { report: 'b.json' }], {
      resume: first,
      onSource: (outcome) => events.push(`done ${outcome.source}`),
      onStart: (name) => events.push(`start ${name}`),
      onFindings: (partial) => events.push(`found ${partial.findings.map((item) => item.location?.path).join(',')}`),
      onSettled: async (partial) => {
        const name = partial.sources.at(-1)?.source;
        events.push(`begin ${name}`);
        await Promise.resolve();
        events.push(`end ${name}`);
      },
    });

    expect(events).toEqual([
      'done a.json',
      'found app.js',
      'start empty.json',
      'done empty.json',
      'begin empty.json',
      'end empty.json',
      'start b.json',
      'done b.json',
      'found app.js,other.js',
      'begin b.json',
      'end b.json',
    ]);
    expect(result.findings.map((item) => item.location?.path)).toEqual(['app.js', 'other.js']);
    expect(result.sources.map((outcome) => outcome.status)).toEqual(['ok', 'ok', 'ok']);
  });

  it('keeps the ignored count from the scan it resumes', async () => {
    execFileSync('git', ['init', '-q'], { cwd: root });
    await writeFile(join(root, '.gitignore'), 'dist/\nlocal.json\n');
    const run = (tool: string, ruleId: string, uris: string[]) => ({
      tool: { driver: { name: tool } },
      results: uris.map((uri) => ({
        ruleId,
        locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } } }],
      })),
    });
    await writeFile(
      join(root, 'report.sarif'),
      JSON.stringify({
        version: '2.1.0',
        runs: [run('semgrep', 'eval-detected', ['app.js', 'dist/bundle.js']), run('gitleaks', 'github-pat', ['local.json'])],
      }),
    );
    const first = await collectFindings(root, [{ report: 'report.sarif' }]);
    await writeFile(join(root, 'other.js'), 'eval(x);\n');
    await writeFile(join(root, 'b.json'), report('other.js'));
    const second = await collectFindings(root, [{ report: 'report.sarif' }, { report: 'b.json' }], { resume: first });
    expect(second.ignored).toBe(2);
    expect(second.protectedPaths).toEqual(['local.json']);
    expect(second.findings.map((item) => item.location?.path).sort()).toEqual(['app.js', 'other.js']);
  });

  it('shows everything outside a git work tree', async () => {
    await writeFile(join(root, 'a.json'), report('app.js'));
    const result = await collectFindings(root, [{ report: 'a.json' }]);
    expect(result).toMatchObject({ ignored: 0, protectedPaths: [] });
    expect(result.findings).toHaveLength(1);
  });
});
