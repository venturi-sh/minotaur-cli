import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadConfig, parseConfig, sourceFromFlag } from './config.js';

describe('parseConfig', () => {
  it('reads sources, model and triage limits', () => {
    const config = parseConfig(`
sources:
  - scanner: semgrep
    args: ["--config", "p/default"]
  - report: reports/trivy.json
    format: trivy
model: openai-compatible:qwen3-coder
baseUrl: http://localhost:11434/v1
triage:
  maxSteps: 20
  maxTokens: 400000
`);
    expect(config).toEqual({
      sources: [{ scanner: 'semgrep', args: ['--config', 'p/default'] }, { report: 'reports/trivy.json', format: 'trivy' }],
      model: 'openai-compatible:qwen3-coder',
      baseUrl: 'http://localhost:11434/v1',
      triage: { maxSteps: 20, maxTokens: 400_000 },
    });
  });

  it('accepts an empty file', () => {
    expect(parseConfig('')).toEqual({});
  });

  it('refuses an API key, since the file is meant to be committed', () => {
    expect(() => parseConfig('apiKey: sk-ant-123')).toThrow(/must not contain an API key/);
  });

  it('says where a mistake is', () => {
    expect(() => parseConfig('sources:\n  - scanner: semgrep\n    arg: x')).toThrow(/sources\.0/);
    expect(() => parseConfig('triage:\n  maxSteps: 1')).toThrow(/triage\.maxSteps/);
    expect(() => parseConfig('model: [')).toThrow(/not valid YAML/);
  });
});

describe('loadConfig', () => {
  it('is optional', async () => {
    const root = await mkdtemp(join(tmpdir(), 'minotaur-config-'));
    try {
      expect(await loadConfig(root)).toEqual({ config: {}, path: null });
      await writeFile(join(root, '.minotaur.yml'), 'model: anthropic:claude-opus-5-5\n');
      expect((await loadConfig(root)).config.model).toBe('anthropic:claude-opus-5-5');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('sourceFromFlag', () => {
  const scanners = ['semgrep', 'trivy'];

  it('treats a known name as a scanner and anything file-like as a report', () => {
    expect(sourceFromFlag('semgrep', scanners)).toEqual({ scanner: 'semgrep' });
    expect(sourceFromFlag('semgrep.json', scanners)).toEqual({ report: 'semgrep.json' });
    expect(sourceFromFlag('out/results.sarif', scanners)).toEqual({ report: 'out/results.sarif' });
  });

  it('rejects an unknown scanner name', () => {
    expect(() => sourceFromFlag('snyk', scanners)).toThrow(/unknown source "snyk"/);
  });
});
