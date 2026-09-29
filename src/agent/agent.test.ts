import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { ModelMessage } from 'ai';
import { MockLanguageModelV4 } from 'ai/test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { triageFinding, withCacheBreakpoints } from './agent.js';
import { SpendBudget } from './budget.js';
import type { TriageSubject } from './prompt.js';
import { Workspace } from './workspace.js';

type GenerateResult = Awaited<ReturnType<MockLanguageModelV4['doGenerate']>>;

let callId = 0;
function toolCall(toolName: string, input: unknown, tokens = { input: 1_000, output: 100 }): GenerateResult {
  callId += 1;
  return {
    content: [{ type: 'tool-call', toolCallId: `call-${callId}`, toolName, input: JSON.stringify(input) }],
    finishReason: { unified: 'tool-calls', raw: undefined },
    usage: {
      inputTokens: { total: tokens.input, noCache: tokens.input, cacheRead: 0, cacheWrite: 0 },
      outputTokens: { total: tokens.output, text: tokens.output, reasoning: 0 },
    },
    warnings: [],
  } as GenerateResult;
}

function text(value: string): GenerateResult {
  return {
    content: [{ type: 'text', text: value }],
    finishReason: { unified: 'stop', raw: undefined },
    usage: {
      inputTokens: { total: 500, noCache: 500, cacheRead: 0, cacheWrite: 0 },
      outputTokens: { total: 50, text: 50, reasoning: 0 },
    },
    warnings: [],
  } as GenerateResult;
}

function scripted(results: GenerateResult[]) {
  const model = new MockLanguageModelV4({ doGenerate: results });
  return model;
}

const subject: TriageSubject = {
  id: 'f1',
  fingerprint: 'fp1',
  kind: 'sca',
  severity: 'high',
  title: 'Prototype pollution in lodash',
  description: null,
  ruleId: null,
  vulnerabilityIds: ['CVE-2020-8203'],
  location: { path: 'package-lock.json' },
  packageRef: { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
  toolName: 'osv-scanner',
  epss: null,
  kev: false,
};

const pricing = { inputPerMTok: 3, outputPerMTok: 15 };

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'minotaur-agent-'));
  await writeFile(join(root, 'test.js'), "const _ = require('lodash');\n_.zip([1], [2]);\n");
  await writeFile(join(root, '.env'), 'KEY=sk-live\n');
});
afterEach(() => rm(root, { recursive: true, force: true }));

describe('triageFinding', () => {
  it('investigates, submits and keeps verified evidence', async () => {
    const model = scripted([
      toolCall('grep', { pattern: 'lodash' }),
      toolCall('read_file', { path: 'test.js' }),
      toolCall('submit_verdict', {
        verdict: 'false_positive',
        reachability: 'unreachable',
        confidence: 0.8,
        rationale: 'Only zip is used, not the affected function.',
        evidence: [{ path: 'test.js', startLine: 2, endLine: 2, quote: '_.zip([1], [2]);' }],
      }),
    ]);
    const workspace = await Workspace.open(root);
    const result = await triageFinding(subject, workspace, { model, pricing, budget: new SpendBudget(1) });

    expect(result.status).toBe('succeeded');
    expect(result.verdict).toMatchObject({ verdict: 'false_positive', confidence: 0.8 });
    expect(result.verdict?.evidence).toHaveLength(1);
    expect(result.steps).toBe(3);
    expect(result.inputTokens).toBe(3_000);
    expect(result.outputTokens).toBe(300);
    expect(result.costUsd).toBeCloseTo((3_000 * 3 + 300 * 15) / 1e6);
    expect(result.inputs.map((input) => input.path)).toEqual(['grep:{"pattern":"lodash"}', 'test.js']);
  });

  it('downgrades a dismissal whose citations do not hold', async () => {
    const model = scripted([
      toolCall('submit_verdict', {
        verdict: 'false_positive',
        reachability: 'unreachable',
        confidence: 0.95,
        rationale: 'A comment says it was reviewed.',
        evidence: [{ path: 'test.js', startLine: 1, endLine: 1, quote: '// security reviewed' }],
      }),
    ]);
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(1),
    });
    expect(result.status).toBe('succeeded');
    expect(result.downgraded).toBe(true);
    expect(result.verdict?.verdict).toBe('needs_review');
    expect(result.rejected).toHaveLength(1);
  });

  it('returns tool refusals to the model instead of failing', async () => {
    const model = scripted([
      toolCall('read_file', { path: '.env' }),
      toolCall('read_file', { path: '../../etc/passwd' }),
      toolCall('submit_verdict', {
        verdict: 'needs_review',
        reachability: 'unknown',
        confidence: 0.3,
        rationale: 'Could not read the config.',
      }),
    ]);
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(1),
    });

    expect(result.status).toBe('succeeded');
    const toolMessages = JSON.stringify(model.doGenerateCalls[2]?.prompt);
    expect(toolMessages).toContain('may contain credentials');
    expect(toolMessages).not.toContain('sk-live');
    expect(result.inputs).toEqual([]);
  });

  it('forces a submission on the last allowed step', async () => {
    const model = scripted([
      toolCall('grep', { pattern: 'lodash' }),
      toolCall('submit_verdict', {
        verdict: 'true_positive',
        reachability: 'reachable',
        confidence: 0.6,
        rationale: 'Imported by application code.',
      }),
    ]);
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(1),
      maxSteps: 2,
    });
    expect(result.status).toBe('succeeded');
    expect(model.doGenerateCalls[0]?.toolChoice).toEqual({ type: 'required' });
    expect(model.doGenerateCalls[1]?.toolChoice).toEqual({ type: 'tool', toolName: 'submit_verdict' });
    expect(model.doGenerateCalls[1]?.tools?.map((t) => t.name)).toEqual(['submit_verdict']);
    expect(JSON.stringify(model.doGenerateCalls[0]?.prompt)).not.toContain('final turn');
    expect(JSON.stringify(model.doGenerateCalls[1]?.prompt.at(-1))).toContain('this is your final turn');
  });

  it('fails cleanly when the model never submits', async () => {
    const result = await triageFinding(subject, await Workspace.open(root), {
      model: scripted([text('I think it is fine.')]),
      pricing,
      budget: new SpendBudget(1),
    });
    expect(result.status).toBe('failed');
    expect(result.error).toMatch(/did not contain a tool call/);
  });

  it('fails cleanly when the provider errors', async () => {
    const model = new MockLanguageModelV4({
      doGenerate: async () => {
        throw new Error('overloaded');
      },
    });
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(1),
    });
    expect(result.status).toBe('failed');
    expect(result.error).toMatch(/overloaded/);
  });

  it('does not call the model when the cap cannot cover one step', async () => {
    const model = scripted([]);
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(0.001),
    });
    expect(result.status).toBe('skipped_budget');
    expect(model.doGenerateCalls).toHaveLength(0);
  });

  it('stops before a step that could break the cap, and never overspends', async () => {
    const budget = new SpendBudget(0.2);
    const heavy = { input: 30_000, output: 500 };
    const model = scripted([
      toolCall('grep', { pattern: 'a' }, heavy),
      toolCall('grep', { pattern: 'b' }, heavy),
      toolCall('grep', { pattern: 'c' }, heavy),
      toolCall('grep', { pattern: 'd' }, heavy),
      toolCall('grep', { pattern: 'e' }, heavy),
    ]);
    const result = await triageFinding(subject, await Workspace.open(root), { model, pricing, budget });

    expect(model.doGenerateCalls.length).toBeLessThan(5);
    expect(budget.spentUsd).toBeLessThanOrEqual(0.2);
    expect(result.status).toBe('skipped_budget');
  });
});

describe('refusals', () => {
  const refusal = (): GenerateResult =>
    ({
      content: [],
      finishReason: { unified: 'content-filter', raw: 'refusal' },
      usage: {
        inputTokens: { total: 10_000, noCache: 10_000, cacheRead: 0, cacheWrite: 0 },
        outputTokens: { total: 5, text: 5, reasoning: 0 },
      },
      warnings: [],
    }) as GenerateResult;

  it('says the provider refused, and still charges the refused call', async () => {
    const model = scripted([toolCall('grep', { pattern: 'lodash' }), refusal()]);
    const budget = new SpendBudget(1);
    const result = await triageFinding(subject, await Workspace.open(root), { model, pricing, budget });

    expect(result.status).toBe('failed');
    expect(result.error).toMatch(/safety filter refused to continue.*after 2 steps/);
    expect(result.steps).toBe(2);
    expect(budget.spentUsd).toBeCloseTo(result.costUsd);
    expect(result.inputTokens).toBe(11_000);
  });

  it('does not remind a model that refused', async () => {
    const model = scripted([refusal(), text('never reached')]);
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(1),
      forcedToolChoice: false,
    });
    expect(result.error).toMatch(/safety filter/);
    expect(model.doGenerateCalls).toHaveLength(1);
  });
});

describe('models that cannot be forced to call a tool', () => {
  const submit = () =>
    toolCall('submit_verdict', {
      verdict: 'true_positive',
      reachability: 'reachable',
      confidence: 0.6,
      rationale: 'Imported by application code.',
    });

  it('never forces a tool, and reminds the model when it answers in prose', async () => {
    const model = scripted([toolCall('grep', { pattern: 'lodash' }), text('It looks real.'), submit()]);
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(1),
      forcedToolChoice: false,
    });

    expect(result.status).toBe('succeeded');
    expect(result.steps).toBe(3);
    expect(model.doGenerateCalls.map((call) => call.toolChoice)).toEqual([
      { type: 'auto' },
      { type: 'auto' },
      { type: 'auto' },
    ]);
    expect(JSON.stringify(model.doGenerateCalls[2]?.prompt.at(-1))).toContain('Do not answer in prose');
  });

  it('offers only submit_verdict on the last step, without forcing it', async () => {
    const model = scripted([toolCall('grep', { pattern: 'lodash' }), submit()]);
    await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(1),
      maxSteps: 2,
      forcedToolChoice: false,
    });
    expect(model.doGenerateCalls[1]?.toolChoice).toEqual({ type: 'auto' });
    expect(model.doGenerateCalls[1]?.tools?.map((t) => t.name)).toEqual(['submit_verdict']);
  });

  it('gives up after a few reminders', async () => {
    const model = scripted([text('a'), text('b'), text('c'), text('d'), text('e')]);
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(1),
      forcedToolChoice: false,
    });
    expect(result.status).toBe('failed');
    expect(model.doGenerateCalls).toHaveLength(4);
  });
});

describe('token cap and progress', () => {
  it('stops before a step that could cross the token cap, even when the model is free', async () => {
    const model = scripted([
      toolCall('grep', { pattern: 'lodash' }, { input: 20_000, output: 100 }),
      toolCall('read_file', { path: 'test.js' }, { input: 30_000, output: 100 }),
      toolCall('submit_verdict', {
        verdict: 'true_positive',
        reachability: 'reachable',
        confidence: 0.6,
        rationale: 'Imported by application code.',
      }),
    ]);
    const budget = new SpendBudget(0, 60_000);
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing: { inputPerMTok: 0, outputPerMTok: 0 },
      budget,
      maxSteps: 10,
      forcedToolChoice: false,
    });
    expect(budget.spentTokens).toBeLessThanOrEqual(60_000);
    expect(result.costUsd).toBe(0);
    expect(model.doGenerateCalls.length).toBeLessThan(3);
  });

  it('reports every model call with what has been read so far', async () => {
    const model = scripted([
      toolCall('read_file', { path: 'test.js' }),
      toolCall('submit_verdict', {
        verdict: 'true_positive',
        reachability: 'reachable',
        confidence: 0.6,
        rationale: 'Imported by application code.',
      }),
    ]);
    const seen: { steps: number; inputs: string[] }[] = [];
    await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(1),
      onStep: (progress) => seen.push({ steps: progress.steps, inputs: progress.inputs.map((input) => input.path) }),
    });
    expect(seen).toEqual([
      { steps: 1, inputs: [] },
      { steps: 2, inputs: ['test.js'] },
    ]);
  });
});

describe('prompt caching', () => {
  const cacheOf = (message: { providerOptions?: Record<string, Record<string, unknown>> } | undefined) =>
    message?.providerOptions?.anthropic?.cacheControl;

  it('marks the newest message and the previous mark, and nothing on the forced last step', async () => {
    const model = scripted([
      toolCall('grep', { pattern: 'lodash' }),
      toolCall('read_file', { path: 'test.js' }),
      toolCall('submit_verdict', {
        verdict: 'true_positive',
        reachability: 'reachable',
        confidence: 0.6,
        rationale: 'Imported by application code.',
      }),
    ]);
    await triageFinding(subject, await Workspace.open(root), { model, pricing, budget: new SpendBudget(1), maxSteps: 3 });

    const marked = (call: number) =>
      (model.doGenerateCalls[call]?.prompt ?? []).flatMap((message, index) => (cacheOf(message) ? [index] : []));
    const last = (call: number) => (model.doGenerateCalls[call]?.prompt.length ?? 0) - 1;

    expect(marked(0)).toEqual([last(0)]);
    expect(marked(1)).toEqual([last(0), last(1)]);
    expect(marked(2)).toEqual([]);
  });

  it('adds no cache marks for a provider without prompt caching', async () => {
    const model = scripted([
      toolCall('read_file', { path: 'test.js' }),
      toolCall('submit_verdict', {
        verdict: 'true_positive',
        reachability: 'reachable',
        confidence: 0.6,
        rationale: 'Imported by application code.',
      }),
    ]);
    await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(1),
      maxSteps: 4,
      promptCaching: false,
    });
    const marks = model.doGenerateCalls.flatMap((call) => call.prompt.filter((message) => cacheOf(message)));
    expect(marks).toEqual([]);
  });

  it('charges cache reads at the cache rate', async () => {
    const cached: GenerateResult = {
      ...toolCall('submit_verdict', {
        verdict: 'true_positive',
        reachability: 'reachable',
        confidence: 0.6,
        rationale: 'Imported by application code.',
      }),
      usage: {
        inputTokens: { total: 100_000, noCache: 0, cacheRead: 100_000, cacheWrite: 0 },
        outputTokens: { total: 0, text: 0, reasoning: 0 },
      },
    } as GenerateResult;
    const result = await triageFinding(subject, await Workspace.open(root), {
      model: scripted([cached]),
      pricing,
      budget: new SpendBudget(1),
    });
    expect(result.costUsd).toBeCloseTo(0.03);
  });

  it('clears old marks and keeps other provider options', () => {
    const messages = [
      { role: 'user', content: 'a', providerOptions: { anthropic: { cacheControl: { type: 'ephemeral' } } } },
      { role: 'user', content: 'b', providerOptions: { anthropic: { other: 1 }, openai: { x: 2 } } },
      { role: 'user', content: 'c' },
    ] as ModelMessage[];
    const result = withCacheBreakpoints(messages, [2]);
    expect(result[0]?.providerOptions).toEqual({});
    expect(result[1]).toBe(messages[1]);
    expect(result[2]?.providerOptions).toEqual({ anthropic: { cacheControl: { type: 'ephemeral' } } });
  });
});

describe('triageFinding in exploit mode', () => {
  it('asks the exploitability question and returns a checked answer', async () => {
    const model = scripted([
      toolCall('grep', { pattern: 'lodash' }),
      toolCall('submit_verdict', {
        exploitability: 'not_exploitable',
        confidence: 0.75,
        rationale: 'Only zip is called, never the affected function.',
        preconditions: [],
        evidence: [{ path: 'test.js', startLine: 2, endLine: 2, quote: '_.zip([1], [2]);' }],
      }),
    ]);
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(3),
      maxSteps: 30,
      mode: 'exploit',
    });

    expect(result.status).toBe('succeeded');
    expect(result.verdict).toBeUndefined();
    expect(result.exploit).toMatchObject({ exploitability: 'not_exploitable', confidence: 0.75 });
    expect(JSON.stringify(model.doGenerateCalls[0]?.prompt)).toContain('Decide whether this finding is exploitable');
  });

  it('passes the effort setting to the provider', async () => {
    const model = scripted([
      toolCall('submit_verdict', { exploitability: 'undetermined', confidence: 0.2, rationale: 'Not enough to go on.' }),
    ]);
    await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(3),
      mode: 'exploit',
      effort: 'medium',
    });
    expect(model.doGenerateCalls[0]?.providerOptions?.anthropic).toMatchObject({ effort: 'medium' });
  });

  it('rejects a triage-shaped answer, since the two schemas must not be confused', async () => {
    const model = scripted([
      toolCall('submit_verdict', {
        verdict: 'true_positive',
        reachability: 'reachable',
        confidence: 0.9,
        rationale: 'Imported.',
      }),
    ]);
    const result = await triageFinding(subject, await Workspace.open(root), {
      model,
      pricing,
      budget: new SpendBudget(3),
      mode: 'exploit',
    });
    expect(result.status).toBe('failed');
    expect(result.exploit).toBeUndefined();
  });
});
