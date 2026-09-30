import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { MockLanguageModelV4 } from 'ai/test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveTarget } from './commit.js';
import type { SourceConfig } from './config.js';
import { Baseline, runFixes, suppressionsIn, upgradeVersion, verifyFix, type Checkpoint, type Rescan, type RunFixesOptions } from './fix.js';
import { ToolMissingError, UpgradeError, chooseVersion, type Runner } from './upgrade.js';
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

  it('skips a secret without calling the model', async () => {
    const secret = finding({ fingerprint: '5ec5ec00', kind: 'secret', title: 'GitHub token' });
    const result = await run({ findings: [secret], model: model([]) });
    expect(result.results[0]).toMatchObject({ status: 'skipped', steps: 0 });
    expect(result.results[0]!.error).toContain('rotate');
    expect(result.branch).toBeNull();
  });

  it('keeps the fixes that pass in a batch and undoes the rest', async () => {
    const second = finding({ fingerprint: 'b2b2b2b2', location: { path: 'other.js', startLine: 1 } });
    const result = await run({
      findings: [finding(), second],
      branch: 'minotaur/fixes-abc',
      rescans: [scanResult([second])],
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

describe('dependency fixes', () => {
  const TRIVY: SourceConfig[] = [{ scanner: 'trivy' }];
  const lodash = (overrides: Partial<LocalFinding> = {}) =>
    finding({
      fingerprint: '10da5h00',
      kind: 'sca',
      title: 'Prototype pollution in lodash',
      ruleId: 'CVE-2020-8203',
      location: { path: 'package-lock.json' },
      package: { name: 'lodash', version: '4.17.15', ecosystem: 'npm', fixedVersion: '4.17.19' },
      tool: { name: 'trivy', version: '1' },
      tools: [{ name: 'trivy', version: '1' }],
      ...overrides,
    });

  async function project(files: Record<string, string>) {
    for (const [path, content] of Object.entries(files)) {
      await mkdir(join(root, path, '..'), { recursive: true });
      await writeFile(join(root, path), content);
    }
    git('add', '.');
    git('commit', '-q', '-m', 'project');
  }

  /** Records each command, and writes the lockfile the way the tool would. */
  function recorder(behaviour: (tool: string, args: readonly string[], cwd: string) => Promise<void> = async () => {}) {
    const calls: string[] = [];
    const runTool: Runner = async (tool, args, cwd) => {
      calls.push(`${tool} ${args.join(' ')}`);
      await behaviour(tool, args, cwd);
      if (tool === 'npm') await writeFile(join(cwd, 'package-lock.json'), `{"lodash":"${calls.length}"}\n`);
    };
    return { calls, runTool };
  }

  it('upgrades a direct dependency with its package manager, without a model', async () => {
    await project({ 'package.json': '{\n  "dependencies": { "lodash": "^4.17.15" }\n}\n', 'package-lock.json': '{}\n' });
    const { calls, runTool } = recorder();
    const result = await run({ findings: [lodash()], sources: TRIVY, model: model([]), runTool, branch: 'minotaur/fix-10da5h00' });
    expect(calls).toEqual(['npm install lodash@4.17.19 --package-lock-only --ignore-scripts --no-audit --no-fund']);
    expect(result.results[0]).toMatchObject({ status: 'fixed', model: 'npm', steps: 0, changedFiles: ['package-lock.json'] });
    const message = git('log', '-1', '--format=%B', 'minotaur/fix-10da5h00');
    expect(message).toContain('fix(deps): Prototype pollution in lodash');
    expect(message).toContain('Minotaur-Fixed-By: npm');
  });

  it.each([
    ['4.17.15', ' --save-exact'],
    ['~4.17.15', ' --save-prefix=~'],
  ])('keeps the pin style of %s', async (range, flag) => {
    await project({ 'package.json': `{"devDependencies":{"lodash":"${range}"}}\n`, 'package-lock.json': '{}\n' });
    const { calls, runTool } = recorder();
    await run({ findings: [lodash()], sources: TRIVY, model: model([]), runTool, branch: 'minotaur/fix-10da5h00' });
    expect(calls).toEqual([`npm install lodash@4.17.19 --package-lock-only --ignore-scripts --no-audit --no-fund --save-dev${flag}`]);
  });

  it('forces a transitive dependency with an override and says so', async () => {
    await project({ 'package.json': '{\n\t"dependencies": { "express": "^4.0.0" }\n}\n', 'package-lock.json': '{}\n' });
    const { calls, runTool } = recorder();
    const result = await run({ findings: [lodash()], sources: TRIVY, model: model([]), runTool, branch: 'minotaur/fix-10da5h00' });
    expect(calls).toEqual(['npm install --package-lock-only --ignore-scripts --no-audit --no-fund']);
    expect(result.results[0]!.status).toBe('fixed');
    expect(result.results[0]!.notes[0]).toContain('override forces every copy of it to 4.17.19');
    const manifest = git('show', 'minotaur/fix-10da5h00:package.json');
    expect(JSON.parse(manifest).overrides).toEqual({ lodash: '4.17.19' });
    expect(manifest).toContain('\t"overrides"');
  });

  it('raises a pinned Python requirement in place', async () => {
    await project({ 'requirements.txt': 'Flask==1.0  # web\nrequests>=2\n' });
    const flask = lodash({ location: { path: 'requirements.txt' }, package: { name: 'flask', version: '1.0', ecosystem: 'pip', fixedVersion: '2.2.5, 2.3.2' } });
    const result = await run({ findings: [flask], sources: TRIVY, model: model([]), branch: 'minotaur/fix-10da5h00' });
    expect(result.results[0]!.status).toBe('fixed');
    expect(git('show', 'minotaur/fix-10da5h00:requirements.txt')).toBe('Flask==2.2.5  # web\nrequests>=2\n');
  });

  it('hands the manifest to the model when the package manager refuses, then relocks', async () => {
    await project({ 'Cargo.toml': '[dependencies]\nregex = "=1.5.4"\n', 'Cargo.lock': 'regex 1.5.4\n' });
    const regex = lodash({ location: { path: 'Cargo.lock' }, package: { name: 'regex', version: '1.5.4', ecosystem: 'cargo', fixedVersion: '1.5.5' } });
    const { calls, runTool } = recorder(async (_tool, args, cwd) => {
      if (args.includes('--precise')) throw new UpgradeError('cargo update failed: requirement "=1.5.4" does not match 1.5.5');
      await writeFile(join(cwd, 'Cargo.lock'), 'regex 1.5.5\n');
    });
    const fixer = model([
      toolCall('write_file', { path: 'Cargo.lock', content: 'forged\n' }),
      toolCall('replace_in_file', { path: 'Cargo.toml', oldText: '"=1.5.4"', newText: '"1.5.5"' }),
      toolCall('submit_fix', { outcome: 'fixed', summary: 'Raised regex to 1.5.5.' }),
    ]);
    const result = await run({ findings: [regex], sources: TRIVY, model: fixer, runTool, branch: 'minotaur/fix-10da5h00' });
    expect(calls).toEqual(['cargo update -p regex --precise 1.5.5', 'cargo update -p regex']);
    expect(result.results[0]).toMatchObject({ status: 'fixed', changedFiles: ['Cargo.lock', 'Cargo.toml'] });
    // The model's own write to the lockfile was refused; the tool wrote it.
    expect(git('show', 'minotaur/fix-10da5h00:Cargo.lock')).toBe('regex 1.5.5\n');
  });

  it('skips a project whose lockfile Minotaur cannot update, without calling the model', async () => {
    await project({ 'package.json': '{"dependencies":{"lodash":"^4.17.15"}}\n', 'yarn.lock': 'lodash@4.17.15\n' });
    const result = await run({ findings: [lodash({ location: { path: 'yarn.lock' } })], sources: TRIVY, model: model([]) });
    expect(result.results[0]).toMatchObject({ status: 'skipped', steps: 0 });
    expect(result.results[0]!.error).toContain('cannot update yarn.lock yet');
  });

  it('fails without a model when the package manager is not installed', async () => {
    await project({ 'package.json': '{"dependencies":{"lodash":"^4.17.15"}}\n', 'package-lock.json': '{}\n' });
    const runTool: Runner = async () => {
      throw new ToolMissingError('npm is not installed or not on PATH, so the lockfile cannot be updated');
    };
    const result = await run({ findings: [lodash()], sources: TRIVY, model: model([]), runTool });
    expect(result.results[0]).toMatchObject({ status: 'failed', steps: 0, error: 'npm is not installed or not on PATH, so the lockfile cannot be updated' });
  });

  it('upgrades once for every advisory of a package, to the highest version they need', async () => {
    await project({ 'package.json': '{"dependencies":{"lodash":"^4.17.15"}}\n', 'package-lock.json': '{}\n' });
    const other = lodash({ fingerprint: '10da5h11', ruleId: 'CVE-2021-23337', package: { name: 'lodash', version: '4.17.15', fixedVersion: '4.17.21' } });
    expect(upgradeVersion(lodash(), [lodash(), other])).toBe('4.17.21');
    const { calls, runTool } = recorder();
    const result = await run({ findings: [lodash(), other], scanned: [lodash(), other], sources: TRIVY, model: model([]), runTool, branch: 'minotaur/fixes-abc' });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain('lodash@4.17.21');
    expect(result.results.map((item) => item.status)).toEqual(['fixed', 'fixed']);
    expect(result.results[1]!.summary).toContain(`commit ${result.results[0]!.commit!.slice(0, 7)}`);
    expect(git('rev-list', '--count', 'HEAD..minotaur/fixes-abc').trim()).toBe('1');
    // The one commit names both findings, so a later run shows both as fixed on the branch.
    const message = git('log', '-1', '--format=%B', 'minotaur/fixes-abc');
    expect(message).toContain(`Minotaur-Finding: ${lodash().fingerprint}`);
    expect(message).toContain(`Minotaur-Finding: ${other.fingerprint}`);
  });
});

describe('chooseVersion', () => {
  it.each([
    ['4.17.15', '4.17.19', '4.17.19'],
    ['4.17.15', '4.17.21, 5.0.1', '4.17.21'],
    ['1.2.0', '>=1.2.3', '1.2.3'],
    ['2.0.0', '1.9.9, 2.0.1', '2.0.1'],
    ['v0.16.0', 'v0.17.0', 'v0.17.0'],
    [undefined, '3.0.0', '3.0.0'],
    ['1.0.0', 'unknown', null],
  ])('from %s with fixes "%s" picks %s', (current, fixed, expected) => {
    expect(chooseVersion(current, fixed)).toBe(expected);
  });
});

describe('batch cap', () => {
  const files = ['a.js', 'b.js', 'c.js'];
  const bad = (path: string) => finding({ fingerprint: `bad${path[0]}0000`, location: { path, startLine: 1 } });
  const script = () => files.flatMap((path) => [
    toolCall('replace_in_file', { path, oldText: 'bad();', newText: 'good();' }),
    toolCall('submit_fix', { outcome: 'fixed', summary: `Fixed ${path}.` }),
  ]);
  /** Reports each finding while its file still has the bad call. */
  const rescan: Rescan = async (tree) => {
    const still = [];
    for (const path of files) if ((await readFile(join(tree, path), 'utf8')).includes('bad();')) still.push(bad(path));
    return scanResult(still);
  };

  beforeEach(async () => {
    for (const path of files) await writeFile(join(root, path), 'bad();\n');
    git('add', '.');
    git('commit', '-q', '-m', 'bad calls');
  });

  async function batch(answers: boolean[], extra: Partial<RunFixesOptions> = {}) {
    const seen: Checkpoint[] = [];
    const run1 = await run({
      findings: files.map(bad),
      branch: 'minotaur/fixes-abc',
      model: model(script()),
      rescan,
      // A step costs little, but its worst case is priced near $0.15, so the second finding cannot start under $0.16.
      maxTotalUsd: 0.16,
      onCheckpoint: async (checkpoint) => {
        seen.push(checkpoint);
        return answers.shift() ?? false;
      },
      ...extra,
    });
    return { run: run1, seen };
  }

  it('asks at the cap, and goes on by one cap each time the answer is yes', async () => {
    const { run: result, seen } = await batch([true, true, true, true]);
    expect(result.results.map((item) => item.status)).toEqual(['fixed', 'fixed', 'fixed']);
    expect(seen.length).toBeGreaterThan(0);
    expect(seen[0]!.capUsd).toBeCloseTo(0.16);
    expect(seen[1]?.capUsd ?? 0.32).toBeCloseTo(0.32);
    expect(result.stoppedAtCap).toBe(false);
  });

  it('keeps what is committed and tries nothing more when the answer is stop', async () => {
    const { run: result, seen } = await batch([false]);
    expect(seen).toHaveLength(1);
    const statuses = result.results.map((item) => item.status);
    expect(statuses[0]).toBe('fixed');
    expect(statuses).toContain('stopped_at_cap');
    expect(statuses.at(-1)).toMatch(/stopped_at_cap|not_tried/);
    expect(result.stoppedAtCap).toBe(true);
    expect(result.branch).toBe('minotaur/fixes-abc');
    const spent = result.results.reduce((sum, item) => sum + item.costUsd, 0);
    expect(spent).toBeLessThanOrEqual(0.16);
  });

  it('stops at the cap when there is no one to ask', async () => {
    const { run: result } = await batch([], { onCheckpoint: undefined });
    expect(result.stoppedAtCap).toBe(true);
  });

  it('resumes the branch, skipping what it already fixed', async () => {
    const first = await batch([false]);
    const done = first.run.results.filter((item) => item.status === 'fixed').length;
    const again = await run({
      findings: files.map(bad),
      branch: 'minotaur/fixes-abc',
      resume: true,
      model: model(script().slice(done * 2)),
      rescan,
    });
    expect(again.alreadyOnBranch).toBe(done);
    expect(again.results.map((item) => item.status)).toEqual(files.slice(done).map(() => 'fixed'));
    expect(git('rev-list', '--count', 'HEAD..minotaur/fixes-abc').trim()).toBe(String(files.length));
  });

  it('refuses to resume a branch that is not there', async () => {
    await expect(run({ resume: true })).rejects.toThrow('no branch minotaur/fix-a1b2c3d4 to resume');
  });
});
