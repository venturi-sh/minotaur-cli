import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { MockLanguageModelV4 } from 'ai/test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveTarget } from './commit.js';
import type { SourceConfig } from './config.js';
import { Baseline, runFixes, suppressionsIn, verifyFix, type Rescan, type RunFixesOptions } from './fix.js';
import type { ResolvedModel } from './model.js';
import type { CollectResult, LocalFinding } from './sources.js';

type GenerateResult = Awaited<ReturnType<MockLanguageModelV4['doGenerate']>>;

let callId = 0;
function toolCall(toolName: string, input: unknown): GenerateResult {
  callId += 1;
  return {
    content: [{ type: 'tool-call', toolCallId: `call-${callId}`, toolName, input: JSON.stringify(input) }],
    finishReason: { unified: 'tool-calls', raw: undefined },
    usage: {
      inputTokens: { total: 1_000, noCache: 1_000, cacheRead: 0, cacheWrite: 0 },
      outputTokens: { total: 100, text: 100, reasoning: 0 },
    },
    warnings: [],
  } as GenerateResult;
}

const QUERY = 'db.query(`SELECT * FROM users WHERE id = ${id}`);';
const SAFE = "db.query('SELECT * FROM users WHERE id = ?', [id]);";
const OPENGREP: SourceConfig[] = [{ scanner: 'opengrep' }];

function finding(overrides: Partial<LocalFinding> = {}): LocalFinding {
  const fingerprint = (overrides.fingerprint ?? 'a1b2c3d4').padEnd(64, '0');
  return {
    id: fingerprint.slice(0, 8),
    fingerprint,
    kind: 'sast',
    severity: 'high',
    title: 'SQL injection',
    ruleId: 'sql-injection',
    vulnerabilityIds: [],
    references: [],
    location: { path: 'db.js', startLine: 1 },
    tool: { name: 'opengrep', version: '1' },
    tools: [{ name: 'opengrep', version: '1' }],
    ...overrides,
  };
}

function scanResult(findings: LocalFinding[], status: 'ok' | 'failed' = 'ok'): CollectResult {
  return { findings, sources: [{ source: 'opengrep', status, findings: findings.length, durationMs: 1 }], ignored: 0, protectedPaths: [] };
}

function model(results: GenerateResult[]): ResolvedModel {
  return {
    spec: { provider: 'openai-compatible', modelId: 'fake', id: 'openai-compatible:fake' },
    model: new MockLanguageModelV4({ doGenerate: results }),
    pricing: { inputPerMTok: 3, outputPerMTok: 15 },
    capabilities: { promptCaching: false, effort: false, forcedToolChoice: true },
    destination: 'a fake server',
  } as ResolvedModel;
}

const fixQuery = [
  toolCall('replace_in_file', { path: 'db.js', oldText: QUERY, newText: SAFE }),
  toolCall('submit_fix', { outcome: 'fixed', summary: 'Parameterized the query.', notes: ['Check callers pass a number.'] }),
];

let root: string;
let cache: string;
const git = (...args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' });

beforeEach(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), 'minotaur-fixrun-')));
  cache = await mkdtemp(join(tmpdir(), 'minotaur-fixcache-'));
  await writeFile(join(root, 'db.js'), `${QUERY}\n`);
  await writeFile(join(root, 'other.js'), 'run();\n');
  git('init', '-q');
  git('config', 'user.name', 't');
  git('config', 'user.email', 't@t');
  git('add', '.');
  git('commit', '-q', '-m', 'initial');
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
  await rm(cache, { recursive: true, force: true });
});

async function run(overrides: Partial<RunFixesOptions> & { rescans?: CollectResult[] }) {
  const rescans = [...(overrides.rescans ?? [scanResult([])])];
  const rescan: Rescan = async () => rescans.shift() ?? scanResult([]);
  const findings = overrides.findings ?? [finding()];
  return runFixes({
    target: await resolveTarget(root, undefined),
    findings,
    scanned: findings,
    protectedPaths: new Set(),
    model: model(fixQuery),
    limits: { maxSteps: 10, maxUsd: 1 },
    sources: OPENGREP,
    includeIgnored: false,
    branch: 'minotaur/fix-a1b2c3d4',
    cache,
    rescan,
    ...overrides,
  });
}

describe('runFixes', () => {
  it('commits a fix the rescan confirms, on its own branch', async () => {
    const run1 = await run({});
    expect(run1.branch).toBe('minotaur/fix-a1b2c3d4');
    expect(run1.results[0]).toMatchObject({ status: 'fixed', attempts: 1, changedFiles: ['db.js'], error: null });
    const message = git('log', '-1', '--format=%B', 'minotaur/fix-a1b2c3d4');
    expect(message).toContain('fix(security): SQL injection');
    expect(message).toContain('- Check callers pass a number.');
    expect(message).toContain(`Minotaur-Finding: ${finding().fingerprint}`);
    expect(git('show', 'minotaur/fix-a1b2c3d4:db.js')).toBe(`${SAFE}\n`);
    // The person's working tree and branch are left as they were.
    expect(await readFile(join(root, 'db.js'), 'utf8')).toBe(`${QUERY}\n`);
    expect(git('rev-parse', '--abbrev-ref', 'HEAD').trim()).not.toBe('minotaur/fix-a1b2c3d4');
    expect(git('worktree', 'list')).not.toContain(cache);
  });

  it('tries again with what the scanner said, then commits', async () => {
    const narrowed = QUERY.replace('${id}', '${Number(id)}');
    const result = await run({
      model: model([
        toolCall('replace_in_file', { path: 'db.js', oldText: QUERY, newText: narrowed }),
        toolCall('submit_fix', { outcome: 'fixed', summary: 'Cast the id.' }),
        toolCall('replace_in_file', { path: 'db.js', oldText: narrowed, newText: SAFE }),
        toolCall('submit_fix', { outcome: 'fixed', summary: 'Parameterized the query.' }),
      ]),
      rescans: [scanResult([finding()]), scanResult([])],
    });
    expect(result.results[0]).toMatchObject({ status: 'fixed', attempts: 2, summary: 'Parameterized the query.' });
    expect(git('show', 'minotaur/fix-a1b2c3d4:db.js')).toBe(`${SAFE}\n`);
  });

  it('rejects a fix that silences the scanner, and removes the empty branch', async () => {
    const silence = [
      toolCall('replace_in_file', { path: 'db.js', oldText: QUERY, newText: `${QUERY} // nosemgrep` }),
      toolCall('submit_fix', { outcome: 'fixed', summary: 'Done.' }),
    ];
    const result = await run({ model: model([...silence, ...silence]) });
    expect(result.branch).toBeNull();
    expect(result.results[0]).toMatchObject({ status: 'failed', attempts: 2, branch: null, commit: null });
    expect(result.results[0]!.error).toContain('silences the scanner');
    expect(git('branch', '--list', 'minotaur/*')).toBe('');
  });

  it('rejects a fix that adds a finding as severe in a changed file', async () => {
    const added = finding({ fingerprint: 'ffff0000', title: 'Command injection', ruleId: 'exec' });
    const result = await run({ rescans: [scanResult([added]), scanResult([added])], model: model([...fixQuery, toolCall('submit_fix', { outcome: 'fixed', summary: 'Same.' })]) });
    expect(result.results[0]!.status).toBe('failed');
    expect(result.results[0]!.error).toContain('adds a high finding: Command injection at db.js:1');
  });

  it('skips what a model may not fix, without calling it', async () => {
    const secret = finding({ fingerprint: '5ec5ec00', kind: 'secret', title: 'GitHub token' });
    const dependency = finding({ fingerprint: 'dep00000', kind: 'sca', location: { path: 'package-lock.json' } });
    const result = await run({ findings: [secret, dependency], branch: 'minotaur/fixes-abc' });
    expect(result.results.map((item) => item.status)).toEqual(['skipped', 'skipped']);
    expect(result.results[0]!.error).toContain('rotate');
    expect(result.results[1]!.error).toContain('not supported yet');
    expect(result.branch).toBeNull();
  });

  it('keeps the fixes that pass in a batch and undoes the rest', async () => {
    const second = finding({ fingerprint: 'b2b2b2b2', location: { path: 'other.js', startLine: 1 } });
    const result = await run({
      findings: [finding(), second],
      branch: 'minotaur/fixes-abc',
      model: model([
        ...fixQuery,
        toolCall('write_file', { path: 'other.js', content: 'half done\n' }),
        toolCall('submit_fix', { outcome: 'gave_up', summary: 'Needs a product decision.' }),
      ]),
    });
    expect(result.results.map((item) => item.status)).toEqual(['fixed', 'gave_up']);
    expect(git('rev-list', '--count', 'HEAD..minotaur/fixes-abc').trim()).toBe('1');
    expect(git('show', 'minotaur/fixes-abc:other.js')).toBe('run();\n');
  });

  it('refuses an existing branch unless forced', async () => {
    git('branch', 'minotaur/fix-a1b2c3d4');
    await expect(run({})).rejects.toThrow('already exists');
    expect((await run({ force: true })).results[0]!.status).toBe('fixed');
  });

  it('does not commit what no scanner can confirm, unless allowed', async () => {
    const reportOnly: SourceConfig[] = [{ report: 'semgrep.sarif' }];
    const refused = await run({ sources: reportOnly });
    expect(refused.results[0]).toMatchObject({ status: 'unverified', commit: null });
    const allowed = await run({ sources: reportOnly, allowUnverified: true });
    expect(allowed.results[0]!.status).toBe('committed_unverified');
    expect(git('log', '-1', '--format=%B', 'minotaur/fix-a1b2c3d4')).toContain('Not verified');
  });
});

describe('verifyFix', () => {
  const base = { tree: '/tmp', sources: OPENGREP, changedFiles: ['db.js'], diff: '' };

  it('fails while the rule fires as often in the file as before', async () => {
    const original = finding();
    const moved = finding({ fingerprint: 'c0ffee00' });
    const { verification } = await verifyFix({ ...base, finding: original, baseline: new Baseline([original]), rescan: async () => scanResult([moved]) });
    expect(verification.passed).toBe(false);
    expect(verification.problems[0]).toContain('as often as before');
  });

  it('passes when one of two matches in the file is fixed', async () => {
    const first = finding();
    const second = finding({ fingerprint: 'd00d0000' });
    const { verification } = await verifyFix({ ...base, finding: first, baseline: new Baseline([first, second]), rescan: async () => scanResult([second]) });
    expect(verification).toEqual({ scanners: ['opengrep'], passed: true, problems: [] });
  });

  it('does not count an old finding on a changed line as new', async () => {
    const target = finding();
    const neighbour = finding({ fingerprint: 'aaaa1111', ruleId: 'raw-query', severity: 'critical' });
    const moved = finding({ fingerprint: 'bbbb2222', ruleId: 'raw-query', severity: 'critical' });
    const { verification } = await verifyFix({ ...base, finding: target, baseline: new Baseline([target, neighbour]), rescan: async () => scanResult([moved]) });
    expect(verification).toEqual({ scanners: ['opengrep'], passed: true, problems: [] });
  });

  it('fails when the scanner cannot run again', async () => {
    const { verification } = await verifyFix({ ...base, finding: finding(), baseline: new Baseline([finding()]), rescan: async () => scanResult([], 'failed') });
    expect(verification.passed).toBe(false);
  });
});

describe('suppressionsIn', () => {
  it('finds only added lines that silence a scanner', () => {
    const diff = ['--- a/x.py', '+++ b/x.py', '-old()  # nosec', '+eval(x)  # NOSEC', '+safe()', ' context # nosemgrep'].join('\n');
    expect(suppressionsIn(diff)).toEqual(['eval(x)  # NOSEC']);
  });
});
