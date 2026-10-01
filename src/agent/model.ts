/**
 * Which model triages, and what it costs.
 *
 * `TRIAGE_MODEL` is `provider:model`, so switching provider is configuration
 * rather than code. Three providers exist: Anthropic, OpenAI's API, and
 * `openai-compatible`, which is any server that speaks the OpenAI chat
 * completions format. That covers Ollama, vLLM, LM Studio, llama.cpp and most
 * internal gateways, so the code can stay on hardware the customer controls.
 */

import { createAnthropic } from '@ai-sdk/anthropic';
import { createOpenAICompatible } from '@ai-sdk/openai-compatible';
import type { LanguageModel } from 'ai';

import { MODEL_PRICING, type ModelPricing } from './budget.js';

export const DEFAULT_TRIAGE_MODEL = 'anthropic:claude-sonnet-5';
/** Used when an Anthropic key or Console login is set and no model is named. */
export const DEFAULT_EXPLOIT_MODEL = 'anthropic:claude-sonnet-5';
/** Used when the only credential is an OpenAI API key. */
export const DEFAULT_OPENAI_MODEL = 'openai:gpt-5.4';
const OPENAI_API = 'https://api.openai.com/v1';

/** How much the model thinks and writes per call; Anthropic's `effort` setting. */
export const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'] as const;
export type Effort = (typeof EFFORTS)[number];
export const DEFAULT_EXPLOIT_EFFORT: Effort = 'medium';

export function parseEffort(value: string | undefined, fallback: Effort, setting: string): Effort {
  const raw = (value ?? '').trim() || fallback;
  if (!(EFFORTS as readonly string[]).includes(raw)) {
    throw new Error(`${setting} must be one of ${EFFORTS.join(', ')}, got "${raw}"`);
  }
  return raw as Effort;
}

export const PROVIDERS = ['anthropic', 'openai', 'openai-compatible'] as const;
export type Provider = (typeof PROVIDERS)[number];

export interface ModelSpec {
  provider: Provider;
  modelId: string;
  /** `provider:model`, the form recorded on every assessment. */
  id: string;
}

/** Models that reject a `tool_choice` of `any` or a named tool, so they cannot be made to call one. */
const NO_FORCED_TOOL_CHOICE = new Set(['anthropic:claude-opus-5-5']);

/** Provider features the agent uses when they exist and does without when they do not. */
export interface ModelCapabilities {
  /** Anthropic prompt-cache breakpoints on the conversation. */
  promptCaching: boolean;
  /** Anthropic's `effort` setting. */
  effort: boolean;
  /** Whether a tool call can be required; without it the agent reminds the model instead. */
  forcedToolChoice: boolean;
}

export function capabilitiesOf(spec: ModelSpec): ModelCapabilities {
  if (spec.provider === 'anthropic') {
    return { promptCaching: true, effort: true, forcedToolChoice: !NO_FORCED_TOOL_CHOICE.has(spec.id) };
  }
  if (spec.provider === 'openai') return { promptCaching: false, effort: false, forcedToolChoice: true };
  // Local servers differ in whether they honour tool_choice, and one that
  // ignores it looks exactly like a model answering in prose. Reminding works
  // everywhere.
  return { promptCaching: false, effort: false, forcedToolChoice: false };
}

export function supportsForcedToolChoice(spec: ModelSpec): boolean {
  return capabilitiesOf(spec).forcedToolChoice;
}

export function parseModelSpec(
  value: string | undefined,
  fallback = DEFAULT_TRIAGE_MODEL,
  setting = 'TRIAGE_MODEL',
): ModelSpec {
  const raw = (value ?? '').trim() || fallback;
  const [provider, ...rest] = raw.split(':');
  const modelId = rest.join(':');
  if (!provider || !modelId) throw new Error(`${setting} must look like provider:model, got "${raw}"`);
  if (!(PROVIDERS as readonly string[]).includes(provider)) {
    throw new Error(`unsupported provider "${provider}" in ${setting}, expected one of ${PROVIDERS.join(', ')}`);
  }
  return { provider: provider as Provider, modelId, id: `${provider}:${modelId}` };
}

/** A self-hosted model costs nothing per token, so its spend is bounded by steps and tokens instead. */
export const FREE: ModelPricing = { inputPerMTok: 0, outputPerMTok: 0 };

export function resolvePricing(
  spec: ModelSpec,
  env: { TRIAGE_PRICE_INPUT_PER_MTOK?: string | undefined; TRIAGE_PRICE_OUTPUT_PER_MTOK?: string | undefined } = {},
  prefix = 'TRIAGE',
): ModelPricing {
  const input = Number(env.TRIAGE_PRICE_INPUT_PER_MTOK);
  const output = Number(env.TRIAGE_PRICE_OUTPUT_PER_MTOK);
  if (env.TRIAGE_PRICE_INPUT_PER_MTOK && env.TRIAGE_PRICE_OUTPUT_PER_MTOK && input >= 0 && output >= 0) {
    return { inputPerMTok: input, outputPerMTok: output };
  }
  const known = MODEL_PRICING[spec.id];
  if (known) return known;
  if (spec.provider === 'openai-compatible') return FREE;
  throw new Error(
    `no price known for ${spec.id}; set ${prefix}_PRICE_INPUT_PER_MTOK and ${prefix}_PRICE_OUTPUT_PER_MTOK so the spend cap can be enforced`,
  );
}

/** Sent with a Console OAuth token, on the API call and when refreshing it. */
export const OAUTH_BETA = 'oauth-2025-04-20';

export interface ModelConnection {
  apiKey?: string | undefined;
  /** Claude Console access token. Sent as `Authorization: Bearer`, never as `x-api-key`. */
  authToken?: string | undefined;
  /** Where an `openai-compatible` server listens, such as `http://localhost:11434/v1`. */
  baseURL?: string | undefined;
  /** True when the credential came from a stored login rather than an API key in the environment. */
  signedIn?: boolean | undefined;
}

export function createModel(spec: ModelSpec, connection: ModelConnection | string): LanguageModel {
  const parsed = typeof connection === 'string' ? { apiKey: connection } : connection;
  const { apiKey, authToken, baseURL } = parsed;
  if (spec.provider === 'anthropic') {
    // A bearer token must not also send x-api-key. The provider rejects both at once.
    const auth = authToken
      ? { authToken, headers: { 'anthropic-beta': OAUTH_BETA } }
      : apiKey
        ? { apiKey }
        : {};
    return createAnthropic({ ...auth, ...(baseURL ? { baseURL } : {}) })(spec.modelId);
  }
  if (spec.provider === 'openai') {
    if (!apiKey) throw new Error(`${spec.id} needs an OpenAI API key`);
    return createOpenAICompatible({ name: 'openai', baseURL: baseURL ?? OPENAI_API, apiKey })(spec.modelId);
  }
  if (!baseURL) {
    throw new Error(
      `${spec.id} needs the address of the server, for example http://localhost:11434/v1 for Ollama`,
    );
  }
  return createOpenAICompatible({ name: 'openai-compatible', baseURL, ...(apiKey ? { apiKey } : {}) })(spec.modelId);
}

/** Where the code goes when this model is called, said plainly for the person running it. */
export function describeDestination(spec: ModelSpec, connection: ModelConnection): string {
  if (spec.provider === 'anthropic') {
    const where = connection.baseURL ? `Anthropic API via ${connection.baseURL}` : 'Anthropic API';
    return connection.signedIn ? `${where}, signed in` : where;
  }
  if (spec.provider === 'openai') {
    const where = connection.baseURL ? `OpenAI API via ${connection.baseURL}` : 'OpenAI API';
    return connection.signedIn ? `${where}, signed in` : where;
  }
  return connection.baseURL ?? 'an unconfigured server';
}
