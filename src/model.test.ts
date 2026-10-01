import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { resolveModel } from './model.js';

describe('resolveModel', () => {
  it('explains both ways to set up a model when none is configured', async () => {
    await expect(resolveModel({}, {}, {})).rejects.toThrow(/No model is configured[\s\S]*Ollama[\s\S]*ANTHROPIC_API_KEY[\s\S]*auth login/);
  });

  it('defaults to the exploit model when only an Anthropic key is present', async () => {
    const resolved = await resolveModel({}, {}, { ANTHROPIC_API_KEY: 'sk-test' });
    expect(resolved.spec.id).toBe('anthropic:claude-opus-5-5');
    expect(resolved.effort).toBe('medium');
    expect(resolved.destination).toBe('Anthropic API');
    expect(resolved.capabilities.promptCaching).toBe(true);
  });

  it('lets flags win over the config file, and the config file over the environment', async () => {
    const env = { MINOTAUR_MODEL: 'openai-compatible:from-env', MINOTAUR_BASE_URL: 'http://env:1/v1' };
    const config = { model: 'openai-compatible:from-config', baseUrl: 'http://config:1/v1' };
    expect((await resolveModel({}, {}, env)).spec.id).toBe('openai-compatible:from-env');
    expect((await resolveModel({}, config, env)).destination).toBe('http://config:1/v1');
    const flagged = await resolveModel({ model: 'openai-compatible:from-flag', baseUrl: 'http://flag:1/v1' }, config, env);
    expect(flagged.spec.id).toBe('openai-compatible:from-flag');
    expect(flagged.destination).toBe('http://flag:1/v1');
  });

  it('treats a self-hosted model as free and uses none of the Anthropic features', async () => {
    const resolved = await resolveModel({ model: 'openai-compatible:qwen3-coder', baseUrl: 'http://localhost:11434/v1' }, {}, {});
    expect(resolved.pricing).toEqual({ inputPerMTok: 0, outputPerMTok: 0 });
    expect(resolved.capabilities).toEqual({ promptCaching: false, effort: false, forcedToolChoice: false });
    expect(resolved.effort).toBeUndefined();
  });

  it('reports what is missing', async () => {
    await expect(resolveModel({ model: 'anthropic:claude-sonnet-5' }, {}, {})).rejects.toThrow(/needs ANTHROPIC_API_KEY/);
    await expect(resolveModel({ model: 'openai-compatible:x' }, {}, {})).rejects.toThrow(/needs the server address/);
    await expect(resolveModel({ model: 'openai-compatible:x', baseUrl: 'http://a/v1', effort: 'high' }, {}, {})).rejects.toThrow(
      /only applies to Anthropic/,
    );
    await expect(resolveModel({ effort: 'extreme' }, {}, { ANTHROPIC_API_KEY: 'k' })).rejects.toThrow(/--effort must be one of/);
  });

  it('leaves out the config effort when --model picks a model without effort', async () => {
    const config = { model: 'anthropic:claude-opus-5-5', triage: { effort: 'high' } };
    const resolved = await resolveModel({ model: 'openai-compatible:x', baseUrl: 'http://a/v1' }, config, {});
    expect(resolved.effort).toBeUndefined();
  });

  it('uses a Console login when no API key is set, and an API key instead when one is', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'minotaur-login-'));
    const token = 'sk-ant-oat01-from-the-console';
    try {
      await writeLogin(dir, { type: 'oauth_token', access_token: token, account_email: 'ada@example.com' });
      const env = { ANTHROPIC_CONFIG_DIR: dir };
      const signedIn = await resolveModel({}, {}, env);
      expect(signedIn.destination).toBe('Anthropic API, signed in');
      expect(signedIn.spec.id).toBe('anthropic:claude-opus-5-5');
      expect(signedIn.destination).not.toContain(token);

      const keyed = await resolveModel({}, {}, { ...env, ANTHROPIC_API_KEY: 'sk-ant-api-from-the-env' });
      expect(keyed.destination).toBe('Anthropic API');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

async function writeLogin(dir: string, credentials: Record<string, unknown>): Promise<void> {
  const path = join(dir, 'credentials');
  await mkdir(path, { recursive: true });
  const file = join(path, 'default.json');
  await writeFile(file, JSON.stringify(credentials));
  await chmod(file, 0o600);
}
