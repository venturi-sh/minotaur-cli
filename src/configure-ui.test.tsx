import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';

import { describe, expect, it, vi } from 'vitest';

import { loadConfig } from './config.js';
import { configureRepository, askConfig } from './configure-ui.js';

const ANSI = /\u001b\[[0-9;?]*[A-Za-z]|\u001b\][^\u0007]*\u0007/g;
const tick = (ms = 80) => new Promise((resolve) => setTimeout(resolve, ms));

function terminal() {
  const input = Object.assign(new PassThrough(), {
    isTTY: true,
    setRawMode() {
      return input;
    },
    ref() {},
    unref() {},
  });
  const output = Object.assign(new PassThrough(), { isTTY: true, columns: 100, rows: 40 });
  let raw = '';
  output.on('data', (chunk: Buffer) => (raw += chunk.toString('utf8')));
  return { input, output, screen: () => raw.replace(ANSI, '') };
}

describe('configureRepository', () => {
  it('writes the answers without a terminal', async () => {
    const root = await mkdtemp(join(tmpdir(), 'minotaur-config-'));
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      expect(
        await configureRepository({
          root,
          env: {},
          anthropicReady: true,
          answers: { scanners: ['trivy', 'opengrep'], provider: 'openai-compatible', modelId: 'qwen3-coder', baseUrl: 'http://localhost:11434/v1' },
        }),
      ).toBe(0);
      expect((await loadConfig(root)).config).toMatchObject({
        sources: [{ scanner: 'trivy' }, { scanner: 'opengrep' }],
        model: 'openai-compatible:qwen3-coder',
        baseUrl: 'http://localhost:11434/v1',
      });
      expect(String(stdout.mock.calls[0]?.[0])).toContain('.minotaur.yml');
      expect(String(stderr.mock.calls[0]?.[0])).toContain('MINOTAUR_API_KEY');
    } finally {
      stdout.mockRestore();
      stderr.mockRestore();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('starts the Console login only when asked, after the file is written', async () => {
    const root = await mkdtemp(join(tmpdir(), 'minotaur-config-'));
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const login = vi.fn(async () => 0);
    try {
      expect(
        await configureRepository({
          root,
          env: {},
          anthropicReady: false,
          signIn: true,
          login,
          answers: { scanners: ['trivy'], provider: 'anthropic' },
        }),
      ).toBe(0);
      expect((await loadConfig(root)).config.model).toBe('anthropic:claude-sonnet-5');
      expect(login).toHaveBeenCalledOnce();
    } finally {
      vi.restoreAllMocks();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('downloads the scanners it was asked to, after the file is written', async () => {
    const root = await mkdtemp(join(tmpdir(), 'minotaur-config-'));
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const installScanners = vi.fn(async () => undefined);
    try {
      expect(
        await configureRepository({
          root,
          env: { MINOTAUR_API_KEY: 'sk-test' },
          anthropicReady: true,
          install: ['opengrep'],
          installScanners,
          answers: { scanners: ['opengrep'], provider: 'unset' },
        }),
      ).toBe(0);
      expect(installScanners).toHaveBeenCalledWith(['opengrep']);
      expect(stderr.mock.calls.map((call) => String(call[0])).join('')).toContain('Installed opengrep.');
    } finally {
      vi.restoreAllMocks();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('keeps the file when a download fails', async () => {
    const root = await mkdtemp(join(tmpdir(), 'minotaur-config-'));
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      expect(
        await configureRepository({
          root,
          env: {},
          anthropicReady: true,
          install: ['trivy'],
          installScanners: async () => {
            throw new Error('could not download trivy');
          },
          answers: { scanners: ['trivy'], provider: 'unset' },
        }),
      ).toBe(1);
      expect((await loadConfig(root)).config.sources).toEqual([{ scanner: 'trivy' }]);
    } finally {
      vi.restoreAllMocks();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('installs missing scanners with Homebrew after the file is written', async () => {
    const root = await mkdtemp(join(tmpdir(), 'minotaur-config-'));
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const brewInstall = vi.fn(async () => 0);
    try {
      expect(
        await configureRepository({
          root,
          env: { MINOTAUR_API_KEY: 'sk-test' },
          anthropicReady: true,
          canBrew: true,
          brew: ['osv-scanner', 'semgrep'],
          brewInstall,
          answers: { scanners: ['osv-scanner', 'semgrep'], provider: 'unset' },
        }),
      ).toBe(0);
      expect(brewInstall).toHaveBeenCalledWith(['osv-scanner', 'semgrep']);
      expect(stderr.mock.calls.map((call) => String(call[0])).join('')).toContain('Installed osv-scanner and semgrep with Homebrew.');
    } finally {
      vi.restoreAllMocks();
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('configureRepository with Claude Code', () => {
  it('installs the ACP adapter when asked, after the file is written', async () => {
    const root = await mkdtemp(join(tmpdir(), 'minotaur-config-'));
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const acpInstall = vi.fn(async () => 0);
    try {
      expect(
        await configureRepository({
          root,
          env: {},
          anthropicReady: false,
          acpReady: false,
          installAcp: true,
          acpInstall,
          answers: { scanners: ['trivy'], provider: 'claude-code', modelId: 'claude-opus-5-5' },
        }),
      ).toBe(0);
      expect((await loadConfig(root)).config.model).toBe('claude-code:claude-opus-5-5');
      expect(acpInstall).toHaveBeenCalledOnce();
      const said = stderr.mock.calls.map((call) => String(call[0])).join('');
      expect(said).toContain('Installed the Claude Code ACP adapter.');
      expect(said).toContain('/login');
      expect(said).not.toContain('ANTHROPIC_API_KEY');
    } finally {
      vi.restoreAllMocks();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('says how to install the adapter when it is missing and was not installed', async () => {
    const root = await mkdtemp(join(tmpdir(), 'minotaur-config-'));
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const acpInstall = vi.fn(async () => 0);
    try {
      expect(
        await configureRepository({ root, env: {}, anthropicReady: true, acpReady: false, acpInstall, answers: { scanners: ['trivy'], provider: 'claude-code' } }),
      ).toBe(0);
      expect(acpInstall).not.toHaveBeenCalled();
      expect(stderr.mock.calls.map((call) => String(call[0])).join('')).toContain('npm install -g @agentclientprotocol/claude-agent-acp');
    } finally {
      vi.restoreAllMocks();
      await rm(root, { recursive: true, force: true });
    }
  });

  it('fails when npm does not install the adapter, and keeps the file', async () => {
    const root = await mkdtemp(join(tmpdir(), 'minotaur-config-'));
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      expect(
        await configureRepository({
          root,
          env: {},
          anthropicReady: true,
          acpReady: false,
          installAcp: true,
          acpInstall: async () => 1,
          answers: { scanners: ['trivy'], provider: 'claude-code' },
        }),
      ).toBe(1);
      expect((await loadConfig(root)).config.model).toBe('claude-code:claude-sonnet-5');
    } finally {
      vi.restoreAllMocks();
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('askConfig', () => {
  it('chooses Claude Code and offers to install its adapter', async () => {
    const { input, output, screen } = terminal();
    const pending = askConfig({
      config: {},
      installed: new Set(['trivy']),
      fallbackScanners: ['trivy'],
      anthropicReady: false,
      acpReady: false,
      input,
      output,
    });
    await tick();
    input.write('\r');
    await tick();
    expect(screen()).toContain('Your Claude subscription, through Claude Code (ACP)');
    input.write('\u001b[B');
    await tick();
    input.write('\r');
    await tick();
    expect(screen()).toContain('Which Claude model should Claude Code use?');
    input.write('\r');
    await tick();
    expect(screen()).toContain('model: claude-code:claude-sonnet-5');
    input.write('\r');
    await tick();
    expect(screen()).toContain('claude-agent-acp) is not installed');
    input.write('\r');
    const outcome = await pending;
    expect(outcome?.choices).toMatchObject({ provider: 'claude-code', modelId: 'claude-sonnet-5' });
    expect(outcome?.installAcp).toBe(true);
    expect(outcome?.signIn).toBe(false);
  });

  it('walks the questions and returns the highlighted choices', async () => {
    const { input, output, screen } = terminal();
    const pending = askConfig({
      config: { sources: [{ report: 'reports/trivy.json', format: 'trivy' }], triage: { maxSteps: 12 } },
      installed: new Set(['trivy', 'opengrep']),
      fallbackScanners: ['trivy', 'opengrep'],
      anthropicReady: true,
      input,
      output,
    });
    await tick();
    expect(screen()).toContain('Which scanners');
    expect(screen()).toContain('reports/trivy.json');

    input.write('\r');
    await tick();
    input.write('\r');
    await tick();
    input.write('\r');
    await tick();
    expect(screen()).toContain('Write this to .minotaur.yml?');
    input.write('\r');
    const outcome = await pending;

    expect(outcome?.signIn).toBe(false);
    expect(outcome?.install).toEqual([]);
    expect(outcome?.brew).toEqual([]);
    expect(outcome?.separate).toEqual([]);
    expect(outcome?.choices).toMatchObject({
      scanners: ['trivy', 'opengrep'],
      provider: 'anthropic',
      modelId: 'claude-sonnet-5',
    });
  });

  it('offers to download a managed scanner that is not installed', async () => {
    const { input, output, screen } = terminal();
    const pending = askConfig({
      config: {},
      installed: new Set(['trivy']),
      fallbackScanners: ['trivy', 'opengrep', 'semgrep'],
      anthropicReady: true,
      input,
      output,
    });
    await tick();
    input.write('\r');
    await tick();
    expect(screen()).toContain('Download opengrep');
    expect(screen()).toContain('semgrep must be installed separately');
    input.write('\r');
    await tick();
    input.write('\r');
    await tick();
    input.write('\r');
    await tick();
    input.write('\r');
    const outcome = await pending;
    expect(outcome?.install).toEqual(['opengrep']);
    expect(outcome?.separate).toEqual(['semgrep']);
  });

  it('offers to install a missing scanner with Homebrew', async () => {
    const { input, output, screen } = terminal();
    const pending = askConfig({
      config: {},
      installed: new Set(['trivy']),
      fallbackScanners: ['trivy', 'osv-scanner'],
      anthropicReady: true,
      canBrew: true,
      input,
      output,
    });
    await tick();
    input.write('\r');
    await tick();
    expect(screen()).toContain('Install osv-scanner with Homebrew');
    input.write('\r');
    await tick();
    input.write('\r');
    await tick();
    input.write('\r');
    await tick();
    input.write('\r');
    const outcome = await pending;
    expect(outcome?.brew).toEqual(['osv-scanner']);
    expect(outcome?.install).toEqual([]);
  });
});
