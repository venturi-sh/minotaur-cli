import { describe, expect, it } from 'vitest';

import type { ExploitVerdict, TriageVerdict } from '../core/index.js';

import { costOf, SpendBudget, worstCaseStepTokens, worstCaseStepUsd } from './budget.js';
import { checkEvidence, checkExploitEvidence, type LineSource } from './evidence.js';
import {
  capabilitiesOf,
  createModel,
  describeDestination,
  FREE,
  parseEffort,
  parseModelSpec,
  resolvePricing,
} from './model.js';
import { renderFinding, type TriageSubject } from './prompt.js';

const source: LineSource = {
  async lines(path, start, end) {
    const files: Record<string, string[]> = {
      'src/app.js': ["const _ = require('lodash');", '  _.template(input);', "console.log('ok');"],
    };
    const lines = files[path];
    if (!lines || start < 1 || end > lines.length) return undefined;
    return lines.slice(start - 1, end);
  },
};

const verdict = (overrides: Partial<TriageVerdict>): TriageVerdict => ({
  verdict: 'false_positive',
  reachability: 'unreachable',
  confidence: 0.9,
  rationale: 'Only used in a test.',
  evidence: [],
  ...overrides,
});

describe('checkEvidence', () => {
  it('keeps quotes that match, ignoring indentation and line-number prefixes', async () => {
    const result = await checkEvidence(
      verdict({
        evidence: [
          { path: 'src/app.js', startLine: 2, endLine: 2, quote: '_.template(input);' },
          { path: 'src/app.js', startLine: 1, endLine: 2, quote: "1: const _ = require('lodash');\n2: _.template(input);" },
        ],
      }),
      source,
    );
    expect(result.verdict.evidence).toHaveLength(2);
    expect(result.rejected).toEqual([]);
    expect(result.downgraded).toBe(false);
  });

  it('drops quotes that are not in the cited lines', async () => {
    const result = await checkEvidence(
      verdict({
        verdict: 'true_positive',
        evidence: [
          { path: 'src/app.js', startLine: 1, endLine: 1, quote: '_.template(input);' },
          { path: 'src/missing.js', startLine: 1, endLine: 1, quote: 'x' },
          { path: 'src/app.js', startLine: 3, endLine: 9, quote: 'console' },
          { path: 'src/app.js', startLine: 1, endLine: 1, quote: '   ' },
        ],
      }),
      source,
    );
    expect(result.verdict.evidence).toEqual([]);
    expect(result.rejected).toHaveLength(4);
    expect(result.verdict.verdict).toBe('true_positive');
  });

  it('downgrades a false positive with no verifiable evidence', async () => {
    const result = await checkEvidence(
      verdict({ evidence: [{ path: 'src/app.js', startLine: 1, endLine: 1, quote: '// reviewed, safe' }] }),
      source,
    );
    expect(result.downgraded).toBe(true);
    expect(result.verdict.verdict).toBe('needs_review');
    expect(result.verdict.confidence).toBeLessThanOrEqual(0.5);
    expect(result.verdict.rationale).toMatch(/Downgraded from false_positive/);
  });
});

describe('checkExploitEvidence', () => {
  const answer = (overrides: Partial<ExploitVerdict>): ExploitVerdict => ({
    exploitability: 'exploitable',
    confidence: 0.8,
    rationale: 'Input reaches the template.',
    preconditions: [],
    evidence: [],
    openQuestions: [],
    ...overrides,
  });
  const path = { path: 'src/app.js', startLine: 2, endLine: 2, quote: '_.template(input);' };
  const invented = { path: 'src/app.js', startLine: 2, endLine: 2, quote: 'eval(req.body)' };

  it('keeps a yes that stands on a real path', async () => {
    const result = await checkExploitEvidence(answer({ evidence: [path] }), source);
    expect(result.verdict.exploitability).toBe('exploitable');
    expect(result.downgraded).toBe(false);
  });

  it('turns a yes with no path that checks out into undetermined', async () => {
    const result = await checkExploitEvidence(answer({ evidence: [invented] }), source);
    expect(result.verdict.exploitability).toBe('undetermined');
    expect(result.verdict.rationale).toMatch(/Downgraded from exploitable/);
    expect(result.rejected).toEqual([invented]);
  });

  it('turns a no with no blocking code into undetermined, the same as a yes', async () => {
    const result = await checkExploitEvidence(answer({ exploitability: 'not_exploitable' }), source);
    expect(result.verdict.exploitability).toBe('undetermined');
    expect(result.verdict.confidence).toBeLessThanOrEqual(0.5);
  });

  it('leaves undetermined alone even without citations', async () => {
    const result = await checkExploitEvidence(answer({ exploitability: 'undetermined' }), source);
    expect(result.downgraded).toBe(false);
  });
});

describe('budget', () => {
  const pricing = { inputPerMTok: 3, outputPerMTok: 15 };

  it('prices usage per million tokens', () => {
    expect(costOf(pricing, { inputTokens: 1_000_000, outputTokens: 100_000 })).toBeCloseTo(4.5);
  });

  it('prices cache reads at a tenth of input and cache writes at a quarter more', () => {
    const usage = { inputTokens: 1_000_000, outputTokens: 0, cacheReadTokens: 800_000, cacheWriteTokens: 100_000 };
    // 100k plain at 3, 100k written at 3.75, 800k read at 0.3.
    expect(costOf(pricing, usage)).toBeCloseTo(0.3 + 0.375 + 0.24);
  });

  it('uses a model’s own cache-read rate when it has one', () => {
    const opus55 = resolvePricing(parseModelSpec('anthropic:claude-opus-5-5'));
    const usage = { inputTokens: 1_000_000, outputTokens: 0, cacheReadTokens: 1_000_000 };
    expect(costOf(opus55, usage)).toBeCloseTo(0.2);
  });

  it('accepts only known effort levels', () => {
    expect(parseEffort(undefined, 'medium', 'EXPLOIT_EFFORT')).toBe('medium');
    expect(parseEffort(' high ', 'medium', 'EXPLOIT_EFFORT')).toBe('high');
    expect(() => parseEffort('extreme', 'medium', 'EXPLOIT_EFFORT')).toThrow(/EXPLOIT_EFFORT must be one of/);
  });

  it('prices the next step at its worst case, with everything uncached written to the cache', () => {
    const allowance = { maxToolOutputTokens: 5_000, maxOutputTokens: 1_000 };
    expect(worstCaseStepUsd(pricing, 10_000, allowance)).toBeCloseTo(0.05625 + 0.015);
  });

  it('prices the prefix the previous step cached as a read', () => {
    const allowance = { maxToolOutputTokens: 5_000, maxOutputTokens: 1_000 };
    const cold = worstCaseStepUsd(pricing, 100_000, allowance);
    const warm = worstCaseStepUsd(pricing, 100_000, allowance, 90_000);
    expect(warm).toBeCloseTo((90_000 * 0.3 + 15_000 * 3.75) / 1_000_000 + 0.015);
    expect(warm).toBeLessThan(cold / 3);
    expect(worstCaseStepUsd(pricing, 10_000, allowance, 50_000)).toBeCloseTo(
      (10_000 * 0.3 + 5_000 * 3.75) / 1_000_000 + 0.015,
    );
  });

  it('refuses spend that would cross the cap', () => {
    const budget = new SpendBudget(0.1);
    expect(budget.canAfford(0.1)).toBe(true);
    budget.record(0.07);
    expect(budget.canAfford(0.04)).toBe(false);
    expect(budget.remainingUsd).toBeCloseTo(0.03);
    budget.record(-5);
    expect(budget.spentUsd).toBeCloseTo(0.07);
  });

  it('rejects a nonsensical cap', () => {
    expect(() => new SpendBudget(Number.NaN)).toThrow(/invalid/);
    expect(() => new SpendBudget(-1)).toThrow(/invalid/);
    expect(() => new SpendBudget(1, 0)).toThrow(/invalid token limit/);
  });

  it('enforces a token cap alongside the dollar cap', () => {
    const budget = new SpendBudget(0, 10_000);
    expect(budget.canAfford(0, 10_000)).toBe(true);
    budget.record(0, 6_000);
    expect(budget.canAfford(0, 5_000)).toBe(false);
    expect(budget.canAfford(0, 4_000)).toBe(true);
    expect(budget.spentTokens).toBe(6_000);
    expect(new SpendBudget(1).canAfford(0.5, 1e12)).toBe(true);
  });

  it('bounds a step by context, largest tool output and the output allowance', () => {
    expect(worstCaseStepTokens(10_000, { maxToolOutputTokens: 8_000, maxOutputTokens: 2_000 })).toBe(20_000);
  });
});

describe('model configuration', () => {
  it('defaults to anthropic and parses provider:model', () => {
    expect(parseModelSpec(undefined).provider).toBe('anthropic');
    expect(parseModelSpec('anthropic:claude-haiku-4-5')).toEqual({
      provider: 'anthropic',
      modelId: 'claude-haiku-4-5',
      id: 'anthropic:claude-haiku-4-5',
    });
  });

  it('rejects malformed or unsupported specs', () => {
    expect(() => parseModelSpec('claude')).toThrow(/provider:model/);
    expect(() => parseModelSpec('openai:gpt-5')).toThrow(/unsupported/);
  });

  it('accepts any model on an openai-compatible server, colons in the name included', () => {
    expect(parseModelSpec('openai-compatible:qwen3-coder:30b')).toEqual({
      provider: 'openai-compatible',
      modelId: 'qwen3-coder:30b',
      id: 'openai-compatible:qwen3-coder:30b',
    });
  });

  it('only uses Anthropic-specific features on Anthropic models', () => {
    expect(capabilitiesOf(parseModelSpec('anthropic:claude-sonnet-5'))).toEqual({
      promptCaching: true,
      effort: true,
      forcedToolChoice: true,
    });
    expect(capabilitiesOf(parseModelSpec('anthropic:claude-opus-5-5')).forcedToolChoice).toBe(false);
    expect(capabilitiesOf(parseModelSpec('openai-compatible:llama'))).toEqual({
      promptCaching: false,
      effort: false,
      forcedToolChoice: false,
    });
  });

  it('treats a self-hosted model as free unless a price is set', () => {
    const local = parseModelSpec('openai-compatible:llama');
    expect(resolvePricing(local)).toEqual(FREE);
    expect(resolvePricing(local, { TRIAGE_PRICE_INPUT_PER_MTOK: '1', TRIAGE_PRICE_OUTPUT_PER_MTOK: '2' })).toEqual({
      inputPerMTok: 1,
      outputPerMTok: 2,
    });
  });

  it('needs a server address for an openai-compatible model, and says where code goes', () => {
    const local = parseModelSpec('openai-compatible:llama');
    expect(() => createModel(local, {})).toThrow(/localhost:11434/);
    expect(createModel(local, { baseURL: 'http://gpu.internal:8000/v1' })).toBeTruthy();
    expect(describeDestination(local, { baseURL: 'http://gpu.internal:8000/v1' })).toBe('http://gpu.internal:8000/v1');
    expect(describeDestination(parseModelSpec('anthropic:claude-sonnet-5'), {})).toBe('Anthropic API');
  });

  it('requires a price so the cap can be enforced', () => {
    expect(resolvePricing(parseModelSpec('anthropic:claude-haiku-4-5'))).toEqual({ inputPerMTok: 1, outputPerMTok: 5 });
    expect(() => resolvePricing(parseModelSpec('anthropic:claude-new'))).toThrow(/no price known/);
    expect(
      resolvePricing(parseModelSpec('anthropic:claude-new'), {
        TRIAGE_PRICE_INPUT_PER_MTOK: '2',
        TRIAGE_PRICE_OUTPUT_PER_MTOK: '8',
      }),
    ).toEqual({ inputPerMTok: 2, outputPerMTok: 8 });
  });
});

describe('renderFinding', () => {
  const subject: TriageSubject = {
    id: 'f1',
    fingerprint: 'fp',
    kind: 'sca',
    severity: 'high',
    title: 'Prototype pollution in lodash',
    description: 'x'.repeat(4_000),
    ruleId: null,
    vulnerabilityIds: ['CVE-2020-8203'],
    location: { path: 'package-lock.json', startLine: 10, endLine: 12, snippet: 'lodash' },
    packageRef: { name: 'lodash', version: '4.17.15', ecosystem: 'npm', fixedVersion: '4.17.19' },
    toolName: 'osv-scanner',
    epss: 0.12345,
    kev: true,
  };

  it('shows the finding without state or notes, and bounds long text', () => {
    const text = renderFinding(subject);
    expect(text).toContain('Package: lodash@4.17.15 (npm)');
    expect(text).toContain('Fixed in: 4.17.19');
    expect(text).toContain('Location: package-lock.json:10-12');
    expect(text).toContain('Known exploited: yes');
    expect(text).toContain('EPSS: 0.123');
    expect(text).toContain('[truncated]');
    expect(text).not.toMatch(/state/i);
  });

  it('labels code findings', () => {
    expect(renderFinding({ ...subject, kind: 'sast', ruleId: 'js.xss', packageRef: null })).toContain('Rule: js.xss');
  });

  const earlier = {
    exploitability: 'undetermined',
    confidence: 0.4,
    rationale: 'Could not tell whether merge() receives request bodies.',
    entryPoint: 'POST /api/profile',
    preconditions: ['authenticated user'],
    evidence: [{ path: 'src/profile.js', startLine: 8, endLine: 8, quote: '_.merge(profile, req.body)' }],
    openQuestions: ['Does src/middleware/body.js strip __proto__?'],
    filesRead: ['src/profile.js', 'src/app.js'],
  };

  it('hands a follow-up the earlier notes, marked as unverified', () => {
    const text = renderFinding(subject, 'exploit', earlier);
    expect(text).toContain('Earlier answer: undetermined (confidence 0.4)');
    expect(text).toContain('Entry point it found: POST /api/profile');
    expect(text).toContain('- src/profile.js:8: _.merge(profile, req.body)');
    expect(text).toContain('- Does src/middleware/body.js strip __proto__?');
    expect(text).toContain('Files it read: src/profile.js, src/app.js');
    expect(text).toMatch(/can be wrong.*cite it again yourself/s);
  });

  it('never shows earlier notes to routine triage', () => {
    expect(renderFinding(subject, 'triage', earlier)).not.toContain('Earlier answer');
  });
});
