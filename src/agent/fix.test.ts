import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { MockLanguageModelV4 } from 'ai/test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { SpendBudget } from './budget.js';
import { FixSession } from './fix.js';
import type { TriageSubject } from './prompt.js';
import { Workspace } from './workspace.js';

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

const subject: TriageSubject = {
  id: 'f1',
  fingerprint: 'fp1',
  kind: 'sast',
  severity: 'high',
  title: 'SQL injection',
  description: null,
  ruleId: 'sql-injection',
  vulnerabilityIds: [],
  location: { path: 'db.js', startLine: 1 },
  packageRef: null,
  toolName: 'opengrep',
  epss: null,
  kev: false,
};

const pricing = { inputPerMTok: 3, outputPerMTok: 15 };
const QUERY = 'db.query(`SELECT * FROM users WHERE id = ${id}`);';
const SAFE = "db.query('SELECT * FROM users WHERE id = ?', [id]);";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'minotaur-fix-'));
  await writeFile(join(root, 'db.js'), `${QUERY}\n`);
  await writeFile(join(root, '.env'), 'KEY=sk-live\n');
});
afterEach(() => rm(root, { recursive: true, force: true }));

async function session(results: GenerateResult[], budget = new SpendBudget(1)) {
  const workspace = await Workspace.open(root, { writable: { readOnly: ['.minotaur.yml'] } });
  const model = new MockLanguageModelV4({ doGenerate: results });
  return { model, fix: new FixSession(subject, workspace, { model, pricing, budget, maxSteps: 10 }) };
}

describe('FixSession', () => {
  it('edits the file and submits', async () => {
    const { fix } = await session([
      toolCall('read_file', { path: 'db.js' }),
      toolCall('replace_in_file', { path: 'db.js', oldText: QUERY, newText: SAFE }),
      toolCall('submit_fix', { outcome: 'fixed', summary: 'Parameterized the query.' }),
    ]);
    const attempt = await fix.start();
    expect(attempt).toMatchObject({ status: 'submitted', steps: 3, changedFiles: ['db.js'] });
    expect(attempt.submission).toEqual({ outcome: 'fixed', summary: 'Parameterized the query.', notes: [] });
    expect(await readFile(join(root, 'db.js'), 'utf8')).toBe(`${SAFE}\n`);
  });

  it('returns refused writes to the model and carries on', async () => {
    const { fix } = await session([
      toolCall('write_file', { path: '.env', content: 'x' }),
      toolCall('write_file', { path: '.minotaur.yml', content: 'sources: []' }),
      toolCall('submit_fix', { outcome: 'gave_up', summary: 'Needs a person.' }),
    ]);
    const attempt = await fix.start();
    expect(attempt.status).toBe('submitted');
    expect(attempt.submission?.outcome).toBe('gave_up');
    expect(attempt.changedFiles).toEqual([]);
    expect(await readFile(join(root, '.env'), 'utf8')).toBe('KEY=sk-live\n');
  });

  it('continues the same conversation on retry, sharing the counters', async () => {
    const { fix, model } = await session([
      toolCall('submit_fix', { outcome: 'fixed', summary: 'Nothing yet.' }),
      toolCall('replace_in_file', { path: 'db.js', oldText: QUERY, newText: SAFE }),
      toolCall('submit_fix', { outcome: 'fixed', summary: 'Parameterized the query.' }),
    ]);
    await fix.start();
    const second = await fix.retry('The finding is still reported at db.js:1.');
    expect(second).toMatchObject({ status: 'submitted', steps: 3, changedFiles: ['db.js'] });
    const prompt = JSON.stringify(model.doGenerateCalls.at(-2)?.prompt);
    expect(prompt).toContain('Nothing yet.');
    expect(prompt).toContain('still reported at db.js:1');
  });

  it('stops when the budget cannot pay for a step', async () => {
    const { fix } = await session([], new SpendBudget(0.0001));
    const attempt = await fix.start();
    expect(attempt.status).toBe('skipped_budget');
    expect(fix.canRetry()).toBe(false);
  });

  it('fails on a submission that does not match the schema', async () => {
    const { fix } = await session([toolCall('submit_fix', { outcome: 'maybe', summary: '' })]);
    const attempt = await fix.start();
    expect(attempt.status).toBe('failed');
  });
});
