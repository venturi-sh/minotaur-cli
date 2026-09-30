import { mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { EXPLOIT_PROMPT_VERSION, Workspace } from './agent/index.js';
import type { AssessmentInput } from './core/index.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { loadChecks, saveCheck, type CheckIdentity } from './check-cache.js';
import { toLocal, type LocalFinding } from './sources.js';
import type { TriageResult } from './triage.js';

const IDENTITY = { model: 'openai-compatible:fake', effort: null };
const [A, B, C] = ['a', 'b', 'c'].map((letter) => letter.repeat(40)) as [string, string, string];

describe('check cache', () => {
  let root: string;
  let dir: string;
  let finding: LocalFinding;
  let inputs: AssessmentInput[];

  const check = (overrides: Partial<TriageResult> = {}): TriageResult => ({
    version: 1,
    finding: { id: finding.id, fingerprint: finding.fingerprint, kind: 'sast', severity: 'high', title: 't', tools: ['semgrep'], location: null },
    model: IDENTITY.model,
    promptVersion: EXPLOIT_PROMPT_VERSION,
    status: 'succeeded',
    exploitability: 'exploitable',
    confidence: 0.9,
    entryPoint: null,
    preconditions: [],
    rationale: 'r',
    evidence: [],
    openQuestions: [],
    rejectedEvidence: [],
    downgraded: false,
    filesRead: ['app.js'],
    continuedFrom: null,
    steps: 2,
    inputTokens: 10,
    outputTokens: 5,
    costUsd: 0,
    durationMs: 1,
    error: null,
    ...overrides,
  });

  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'minotaur-checks-repo-')));
    dir = join(await mkdtemp(join(tmpdir(), 'minotaur-checks-')), 'checks');
    await writeFile(join(root, 'app.js'), 'eval(req.query.code);\n');
    [finding] = toLocal([
      {
        fingerprint: 'c'.repeat(64),
        kind: 'sast',
        severity: 'high',
        title: 't',
        vulnerabilityIds: [],
        references: [],
        location: { path: 'app.js', startLine: 1 },
        tool: { name: 'semgrep', version: '1' },
        tools: [],
      },
    ]) as [LocalFinding];
    const workspace = await Workspace.open(root);
    await workspace.readFile('app.js');
    inputs = workspace.inputs();
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
    await rm(join(dir, '..'), { recursive: true, force: true });
  });

  const on = (commit: string) => ({ repo: root, commit });
  const load = (commit: string, identity: CheckIdentity = IDENTITY, protectedPaths = new Set<string>()) =>
    loadChecks(dir, on(commit), root, [finding], identity, protectedPaths);

  it('reuses a check on its own commit without looking at the files again, for this user only', async () => {
    expect(await saveCheck(dir, on(A), check(), inputs, IDENTITY, 1_000)).toBe(true);
    // The tree given for a commit is that commit, so nothing it read can differ.
    await writeFile(join(root, 'app.js'), 'eval(sanitize(req.query.code));\n');
    const found = await load(A);
    expect(found.get(finding.fingerprint)).toMatchObject({ createdAt: 1_000, result: { exploitability: 'exploitable' } });
    expect(found.get(finding.fingerprint)?.carriedFrom).toBeUndefined();

    const [folder] = await readdir(dir);
    const [file] = await readdir(join(dir, folder!, A));
    expect((await stat(join(dir, folder!, A, file!))).mode & 0o777).toBe(0o600);
  });

  it('carries a check to another commit while what it read is unchanged, and keeps it there', async () => {
    await saveCheck(dir, on(A), check(), inputs, IDENTITY, 1_000);
    const carried = (await load(B)).get(finding.fingerprint);
    expect(carried).toMatchObject({ createdAt: 1_000, carriedFrom: `commit ${A.slice(0, 7)}` });

    await writeFile(join(root, 'app.js'), 'eval(sanitize(req.query.code));\n');
    expect((await load(C)).size).toBe(0);
    // Kept for B when it was carried, so B no longer depends on the files.
    expect((await load(B)).get(finding.fingerprint)?.carriedFrom).toBeUndefined();
  });

  it('tries a check that did not carry over only once per commit and kind of tree', async () => {
    await saveCheck(dir, on(A), check(), inputs, IDENTITY);
    const original = await readFile(join(root, 'app.js'), 'utf8');
    await writeFile(join(root, 'app.js'), 'eval(sanitize(req.query.code));\n');
    expect((await load(B)).size).toBe(0);

    await writeFile(join(root, 'app.js'), original);
    expect((await load(B)).size).toBe(0);
    const copy = await loadChecks(dir, { repo: root, commit: B, copy: true }, root, [finding], IDENTITY, new Set());
    expect(copy.size).toBe(1);
  });

  it('carries checks from before they were kept per commit', async () => {
    await saveCheck(dir, on(A), check(), inputs, IDENTITY);
    const [folder] = await readdir(dir);
    await rm(join(dir, folder!, A), { recursive: true });
    const legacy = { format: 1, root, effort: null, inputs, createdAt: 5, result: check() };
    await writeFile(join(dir, folder!, `${finding.fingerprint}.json`), JSON.stringify(legacy));
    expect((await load(B)).get(finding.fingerprint)).toMatchObject({ createdAt: 5, carriedFrom: 'an earlier run' });
  });

  it('drops a check once a file it read holds a detected secret, even on its own commit', async () => {
    await saveCheck(dir, on(A), check(), inputs, IDENTITY);
    expect((await load(A, IDENTITY, new Set(['app.js']))).size).toBe(0);
    expect((await load(B, IDENTITY, new Set(['app.js']))).size).toBe(0);
  });

  it('needs the same model and effort', async () => {
    await saveCheck(dir, on(A), check(), inputs, IDENTITY);
    expect((await load(A, { ...IDENTITY, effort: 'high' })).size).toBe(0);
    expect((await load(A, { ...IDENTITY, model: 'openai-compatible:other' })).size).toBe(0);
  });

  it('carries checks kept without a commit only while what they read is unchanged', async () => {
    await saveCheck(dir, on(A), check(), inputs, IDENTITY);
    const [folder] = await readdir(dir);
    const file = `${finding.fingerprint}.json`;
    const entry = JSON.parse(await readFile(join(dir, folder!, A, file), 'utf8'));
    await rm(join(dir, folder!, A), { recursive: true });
    await mkdir(join(dir, folder!, 'no-commit'));
    await writeFile(join(dir, folder!, 'no-commit', file), JSON.stringify({ ...entry, commit: null }));
    expect((await load(B)).get(finding.fingerprint)?.carriedFrom).toBe('an earlier run');
    await writeFile(join(root, 'app.js'), 'eval(sanitize(req.query.code));\n');
    expect((await load(C)).size).toBe(0);
  });

  it('keeps an agent verdict that read nothing, and only on its own commit', async () => {
    const agent = check({ model: 'agent:cursor', promptVersion: 'agent-v1', filesRead: [] });
    expect(await saveCheck(dir, on(A), agent, [], { model: 'agent:cursor', effort: null })).toBe(true);
    const found = await loadChecks(dir, on(A), root, [finding], null, new Set());
    expect(found.get(finding.fingerprint)?.result.model).toBe('agent:cursor');
    expect((await load(B)).size).toBe(0);
  });

  it('keeps only succeeded checks that read something', async () => {
    expect(await saveCheck(dir, on(A), check({ status: 'failed' }), inputs, IDENTITY)).toBe(false);
    expect(await saveCheck(dir, on(A), check({ status: 'skipped_budget' }), inputs, IDENTITY)).toBe(false);
    expect(await saveCheck(dir, on(A), check(), [], IDENTITY)).toBe(false);
    expect((await load(A)).size).toBe(0);
  });
});
