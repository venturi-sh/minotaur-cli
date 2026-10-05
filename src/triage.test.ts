import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { LocalFinding } from './sources.js';
import { resolveModel } from './model.js';
import { loadEarlierCheck, modelLabel, refusalFor, type TriageResult } from './triage.js';

function finding(overrides: Partial<LocalFinding>): LocalFinding {
  return {
    id: 'abcd1234',
    fingerprint: 'abcd1234'.padEnd(64, '0'),
    kind: 'sast',
    severity: 'high',
    title: 'SQL injection',
    vulnerabilityIds: [],
    references: [],
    tool: { name: 'semgrep', version: '1' },
    tools: [],
    location: { path: 'routes/login.js', startLine: 2 },
    ...overrides,
  };
}

describe('modelLabel', () => {
  it('names the model, its effort and how it is reached', async () => {
    expect(modelLabel(await resolveModel({}, {}, { ANTHROPIC_API_KEY: 'sk-test' }))).toBe(
      'anthropic:claude-sonnet-5 (medium) via ANTHROPIC_API_KEY',
    );
    expect(modelLabel(await resolveModel({ model: 'claude-code' }, {}, {}))).toBe('claude-code:claude-sonnet-5 (medium) via ACP, Claude subscription');
    expect(modelLabel(await resolveModel({ model: 'openai-compatible:qwen', baseUrl: 'http://localhost:11434/v1' }, {}, {}))).toBe(
      'openai-compatible:qwen via http://localhost:11434/v1',
    );
  });
});

describe('refusalFor', () => {
  const none = new Set<string>();

  it('lets a code finding through', () => {
    expect(refusalFor(finding({}), none)).toBeNull();
  });

  it('never sends a secret, a credential file, or a file with a detected secret', () => {
    expect(refusalFor(finding({ kind: 'secret' }), none)).toMatch(/secret findings are never triaged/);
    expect(refusalFor(finding({ location: { path: '.env' } }), none)).toMatch(/credential file/);
    expect(refusalFor(finding({}), new Set(['routes/login.js']))).toMatch(/contains a detected secret/);
  });

  it('allows infrastructure and licence findings', () => {
    expect(refusalFor(finding({ kind: 'iac' }), none)).toBeNull();
    expect(refusalFor(finding({ kind: 'license' }), none)).toBeNull();
  });
});

describe('loadEarlierCheck', () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'minotaur-earlier-'));
  });
  afterAll(() => rm(dir, { recursive: true, force: true }));

  const earlier = (overrides: Partial<TriageResult> = {}): TriageResult => ({
    version: 1,
    finding: {
      id: 'abcd1234',
      fingerprint: 'abcd1234'.padEnd(64, '0'),
      kind: 'sast',
      severity: 'high',
      title: 'SQL injection',
      tools: ['semgrep'],
      location: { path: 'routes/login.js', startLine: 2 },
    },
    model: 'openai-compatible:m',
    promptVersion: 'x',
    status: 'succeeded',
    exploitability: 'undetermined',
    confidence: 0.4,
    entryPoint: null,
    preconditions: [],
    rationale: 'Could not find the route registration.',
    evidence: [],
    openQuestions: ['Is routes/login.js mounted?'],
    rejectedEvidence: [],
    downgraded: false,
    filesRead: ['routes/login.js'],
    continuedFrom: null,
    steps: 3,
    inputTokens: 100,
    outputTokens: 10,
    costUsd: 0,
    durationMs: 5,
    error: null,
    ...overrides,
  });

  async function write(name: string, content: unknown): Promise<string> {
    const path = join(dir, name);
    await writeFile(path, typeof content === 'string' ? content : JSON.stringify(content));
    return path;
  }

  it('reads the notes of a finished check of the same finding', async () => {
    const check = await loadEarlierCheck(await write('ok.json', earlier()), finding({}));
    expect(check).toMatchObject({ exploitability: 'undetermined', openQuestions: ['Is routes/login.js mounted?'] });
  });

  it('refuses a check of another finding, an unfinished one, or something else entirely', async () => {
    const other = finding({ id: 'eeee0000', fingerprint: 'e'.repeat(64) });
    await expect(loadEarlierCheck(await write('ok.json', earlier()), other)).rejects.toThrow(/not eeee0000/);
    await expect(
      loadEarlierCheck(await write('failed.json', earlier({ status: 'failed', exploitability: null })), finding({})),
    ).rejects.toThrow(/no finished answer/);
    await expect(loadEarlierCheck(await write('scan.json', { version: 1, findings: [] }), finding({}))).rejects.toThrow(
      /not the JSON output/,
    );
    await expect(loadEarlierCheck(join(dir, 'missing.json'), finding({}))).rejects.toThrow(/could not read/);
  });
});
