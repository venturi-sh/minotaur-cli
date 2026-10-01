import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadConfig, parseConfig, type Config } from './config.js';
import {
  anthropicModels,
  anthropicReady,
  applyChoices,
  initialScanners,
  installMissing,
  installWithBrew,
  missingScanners,
  renderConfig,
  saveConfig,
  scannerChoices,
  type ConfigChoices,
} from './configure.js';

const existing: Config = {
  sources: [
    { scanner: 'semgrep', args: ['--config', 'p/default'] },
    { report: 'reports/trivy.json', format: 'trivy' },
  ],
  model: 'openai-compatible:qwen3-coder',
  baseUrl: 'http://localhost:11434/v1',
  triage: { maxSteps: 20, maxTokens: 400_000 },
  focus: { noise: { paths: ['**/test/**'] } },
};

describe('applyChoices', () => {
  it('keeps scanner arguments, report files, triage and focus, and drops the server address for Anthropic', () => {
    const next = applyChoices(existing, { scanners: ['opengrep', 'semgrep'], provider: 'anthropic', modelId: 'claude-opus-5-5' });
    expect(next).toEqual({
      sources: [
        { scanner: 'semgrep', args: ['--config', 'p/default'] },
        { scanner: 'opengrep' },
        { report: 'reports/trivy.json', format: 'trivy' },
      ],
      model: 'anthropic:claude-opus-5-5',
      triage: { maxSteps: 20, maxTokens: 400_000 },
      focus: { noise: { paths: ['**/test/**'] } },
    });
    expect(next).not.toHaveProperty('baseUrl');
    expect(next).not.toHaveProperty('apiKey');
  });

  it('records a local server, and clears a model when asked not to record one', () => {
    const local = applyChoices(existing, {
      scanners: ['trivy'],
      provider: 'openai-compatible',
      modelId: 'openai-compatible:qwen3-coder',
      baseUrl: 'http://localhost:11434/v1',
    });
    expect(local.model).toBe('openai-compatible:qwen3-coder');
    expect(local.baseUrl).toBe('http://localhost:11434/v1');
    expect(local.triage).toEqual(existing.triage);

    const cleared = applyChoices(existing, { scanners: ['trivy'], provider: 'unset' });
    expect(cleared.model).toBeUndefined();
    expect(cleared.baseUrl).toBeUndefined();
    expect(cleared.triage).toEqual(existing.triage);
  });

  it('rejects an empty scanner list, an unknown scanner and a bad server address', () => {
    expect(() => applyChoices({}, { scanners: [], provider: 'unset' })).toThrow(/at least one scanner/);
    expect(() => applyChoices({}, { scanners: ['snyk'], provider: 'unset' })).toThrow(/unknown scanner "snyk"/);
    const bad: ConfigChoices = { scanners: ['trivy'], provider: 'openai-compatible', modelId: 'qwen', baseUrl: 'localhost:11434' };
    expect(() => applyChoices({}, bad)).toThrow(/http or https/);
    expect(() => applyChoices({}, { scanners: ['trivy'], provider: 'anthropic', modelId: 'not-a-model' })).toThrow(/unknown Anthropic model/);
  });
});

describe('renderConfig', () => {
  it('round-trips through the config parser and does not record a key', () => {
    const text = renderConfig(applyChoices(existing, { scanners: ['semgrep'], provider: 'anthropic' }));
    expect(text).toMatch(/^# Minotaur settings/);
    expect(text).not.toMatch(/^apiKey:/m);
    expect(text).not.toMatch(/^api_key:/m);
    expect(parseConfig(text)).toEqual(applyChoices(existing, { scanners: ['semgrep'], provider: 'anthropic' }));
  });
});

describe('saveConfig', () => {
  it('writes a file loadConfig accepts', async () => {
    const root = await mkdtemp(join(tmpdir(), 'minotaur-config-'));
    try {
      const path = await saveConfig(root, applyChoices(existing, { scanners: ['trivy', 'opengrep'], provider: 'anthropic' }));
      expect(path).toBe(join(root, '.minotaur.yml'));
      expect((await loadConfig(root)).config.model).toBe('anthropic:claude-sonnet-5');
      expect((await loadConfig(root)).config.sources).toEqual([
        { scanner: 'trivy' },
        { scanner: 'opengrep' },
        { report: 'reports/trivy.json', format: 'trivy' },
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('scanner choices', () => {
  it('starts from the file, and otherwise from the fallback', () => {
    expect(initialScanners(existing, ['trivy'])).toEqual(['semgrep']);
    expect(initialScanners({}, ['trivy', 'opengrep', 'made-up'])).toEqual(['trivy', 'opengrep']);
  });

  it('says whether a scanner is installed or downloaded', () => {
    const choices = scannerChoices(new Set(['trivy']));
    expect(choices.find((choice) => choice.name === 'trivy')?.label).toContain('installed');
    expect(choices.find((choice) => choice.name === 'opengrep')?.label).toContain('downloaded if missing');
    expect(choices.find((choice) => choice.name === 'semgrep')?.label).toContain('not installed');
    expect(scannerChoices(new Set(), true).find((choice) => choice.name === 'osv-scanner')?.label).toContain('Homebrew if missing');
  });

  it('lists the default Anthropic model first', () => {
    expect(anthropicModels()[0]).toBe('claude-sonnet-5');
    expect(anthropicModels()).toContain('claude-sonnet-5');
  });

  it('splits missing scanners into ones Minotaur can download and the rest', () => {
    expect(missingScanners(['opengrep', 'semgrep', 'trivy'], new Set(['trivy']))).toEqual({
      download: ['opengrep'],
      brew: [],
      separate: ['semgrep'],
    });
    expect(missingScanners(['osv-scanner', 'semgrep', 'trivy'], new Set(['trivy']), true)).toEqual({
      download: [],
      brew: ['osv-scanner', 'semgrep'],
      separate: [],
    });
  });
});

describe('installMissing', () => {
  it('downloads a managed scanner, and the Opengrep rules with Opengrep', async () => {
    const tools: string[] = [];
    let rules = 0;
    await installMissing(['trivy', 'opengrep'], {
      tool: async (name) => {
        tools.push(name);
      },
      rules: async () => {
        rules += 1;
      },
    });
    expect(tools).toEqual(['trivy', 'opengrep']);
    expect(rules).toBe(1);
  });

  it('refuses a scanner it cannot download', async () => {
    await expect(installMissing(['semgrep'], { tool: async () => undefined, rules: async () => undefined })).rejects.toThrow(/not a scanner Minotaur can download/);
  });
});

describe('installWithBrew', () => {
  it('installs the Homebrew formulas for the scanners', async () => {
    const formulas: string[][] = [];
    await installWithBrew(['osv-scanner', 'semgrep'], async (requested) => {
      formulas.push([...requested]);
      return 0;
    });
    expect(formulas).toEqual([['osv-scanner', 'semgrep']]);
  });

  it('says when Homebrew does not install them', async () => {
    await expect(installWithBrew(['grype'], async () => 1)).rejects.toThrow(/did not install grype/);
    await expect(installWithBrew(['trivy'], async () => 0)).rejects.toThrow(/no Homebrew formula/);
  });
});

describe('anthropicReady', () => {
  it('is true when a key is set, and false when there is no login', async () => {
    expect(await anthropicReady({ ANTHROPIC_API_KEY: 'sk-test' })).toBe(true);
    const dir = await mkdtemp(join(tmpdir(), 'minotaur-auth-'));
    try {
      expect(await anthropicReady({ ANTHROPIC_CONFIG_DIR: dir })).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
