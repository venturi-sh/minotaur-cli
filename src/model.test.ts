import { describe, expect, it } from 'vitest';

import { resolveModel } from './model.js';

describe('resolveModel', () => {
  it('explains both ways to set up a model when none is configured', () => {
    expect(() => resolveModel({}, {}, {})).toThrow(/No model is configured[\s\S]*Ollama[\s\S]*ANTHROPIC_API_KEY/);
  });

  it('defaults to the exploit model when only an Anthropic key is present', () => {
    const resolved = resolveModel({}, {}, { ANTHROPIC_API_KEY: 'sk-test' });
    expect(resolved.spec.id).toBe('anthropic:claude-opus-5-5');
    expect(resolved.effort).toBe('medium');
    expect(resolved.destination).toBe('Anthropic API');
    expect(resolved.capabilities.promptCaching).toBe(true);
  });

  it('lets flags win over the config file, and the config file over the environment', () => {
    const env = { MINOTAUR_MODEL: 'openai-compatible:from-env', MINOTAUR_BASE_URL: 'http://env:1/v1' };
    const config = { model: 'openai-compatible:from-config', baseUrl: 'http://config:1/v1' };
    expect(resolveModel({}, {}, env).spec.id).toBe('openai-compatible:from-env');
    expect(resolveModel({}, config, env).destination).toBe('http://config:1/v1');
    const flagged = resolveModel({ model: 'openai-compatible:from-flag', baseUrl: 'http://flag:1/v1' }, config, env);
    expect(flagged.spec.id).toBe('openai-compatible:from-flag');
    expect(flagged.destination).toBe('http://flag:1/v1');
  });

  it('treats a self-hosted model as free and uses none of the Anthropic features', () => {
    const resolved = resolveModel({ model: 'openai-compatible:qwen3-coder', baseUrl: 'http://localhost:11434/v1' }, {}, {});
    expect(resolved.pricing).toEqual({ inputPerMTok: 0, outputPerMTok: 0 });
    expect(resolved.capabilities).toEqual({ promptCaching: false, effort: false, forcedToolChoice: false });
    expect(resolved.effort).toBeUndefined();
  });

  it('reports what is missing', () => {
    expect(() => resolveModel({ model: 'anthropic:claude-sonnet-5' }, {}, {})).toThrow(/needs ANTHROPIC_API_KEY/);
    expect(() => resolveModel({ model: 'openai-compatible:x' }, {}, {})).toThrow(/needs the server address/);
    expect(() => resolveModel({ model: 'openai-compatible:x', baseUrl: 'http://a/v1', effort: 'high' }, {}, {})).toThrow(
      /only applies to Anthropic/,
    );
    expect(() => resolveModel({ effort: 'extreme' }, {}, { ANTHROPIC_API_KEY: 'k' })).toThrow(/--effort must be one of/);
  });

  it('leaves out the config effort when --model picks a model without effort', () => {
    const config = { model: 'anthropic:claude-opus-5-5', triage: { effort: 'high' } };
    const resolved = resolveModel({ model: 'openai-compatible:x', baseUrl: 'http://a/v1' }, config, {});
    expect(resolved.effort).toBeUndefined();
  });
});
