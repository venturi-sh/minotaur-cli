/**
 * Which model triage talks to. Flags win, then `.minotaur.yml`, then the
 * environment. An API key only ever comes from the environment or from
 * `minotaur auth login`. An environment key wins over a stored login.
 */

import {
  DEFAULT_EXPLOIT_EFFORT,
  DEFAULT_EXPLOIT_MODEL,
  DEFAULT_OPENAI_MODEL,
  capabilitiesOf,
  createModel,
  describeDestination,
  parseEffort,
  parseModelSpec,
  resolvePricing,
  type Effort,
  type ModelCapabilities,
  type ModelConnection,
  type ModelPricing,
  type ModelSpec,
} from './agent/index.js';

import { loadConsoleToken, loadOpenAIKey, type Env as AuthEnv } from './auth.js';
import type { Config } from './config.js';

type LanguageModel = ReturnType<typeof createModel>;

export interface ModelFlags {
  model?: string | undefined;
  baseUrl?: string | undefined;
  effort?: string | undefined;
}

export interface ResolvedModel {
  spec: ModelSpec;
  model: LanguageModel;
  pricing: ModelPricing;
  capabilities: ModelCapabilities;
  effort?: Effort;
  destination: string;
}

type Env = AuthEnv;

const SETUP_HELP = [
  'No model is configured. Either:',
  '  - use a model server you run yourself, such as Ollama:',
  '      --model openai-compatible:qwen3-coder --base-url http://localhost:11434/v1',
  '  - or use Anthropic: export ANTHROPIC_API_KEY=..., or minotaur auth login anthropic',
  '  - or use OpenAI: export OPENAI_API_KEY=..., or minotaur auth login openai',
  'The same settings can go in .minotaur.yml (model, baseUrl) or MINOTAUR_MODEL and MINOTAUR_BASE_URL.',
].join('\n');

export async function resolveModel(flags: ModelFlags, config: Config, env: Env): Promise<ResolvedModel> {
  const configured = flags.model ?? config.model ?? env['MINOTAUR_MODEL'];
  const baseURL = flags.baseUrl ?? config.baseUrl ?? env['MINOTAUR_BASE_URL'];

  // With nothing named, a Claude Console login or an OpenAI key picks the provider.
  if (!configured && !env['ANTHROPIC_API_KEY'] && !env['MINOTAUR_API_KEY']) {
    const login = await loadConsoleToken(env);
    if (login) return finish(parseModelSpec(undefined, DEFAULT_EXPLOIT_MODEL, '--model'), { authToken: login.accessToken, signedIn: true, baseURL }, flags, config, env);
    const openAI = env['OPENAI_API_KEY'] ?? (await loadOpenAIKey(env));
    if (openAI) return finish(parseModelSpec(DEFAULT_OPENAI_MODEL), { apiKey: openAI, signedIn: !env['OPENAI_API_KEY'], baseURL }, flags, config, env);
    throw new Error(SETUP_HELP);
  }

  const spec = parseModelSpec(configured, DEFAULT_EXPLOIT_MODEL, '--model');
  if (spec.provider === 'anthropic') {
    const apiKey = env['ANTHROPIC_API_KEY'] ?? env['MINOTAUR_API_KEY'];
    if (apiKey) return finish(spec, { apiKey, baseURL }, flags, config, env);
    const login = await loadConsoleToken(env);
    if (!login) throw new Error(`${spec.id} needs ANTHROPIC_API_KEY in the environment, or minotaur auth login anthropic`);
    return finish(spec, { authToken: login.accessToken, signedIn: true, baseURL }, flags, config, env);
  }
  if (spec.provider === 'openai') {
    const fromEnv = env['OPENAI_API_KEY'] ?? env['MINOTAUR_API_KEY'];
    const apiKey = fromEnv ?? (await loadOpenAIKey(env));
    if (!apiKey) throw new Error(`${spec.id} needs OPENAI_API_KEY in the environment, or minotaur auth login openai`);
    return finish(spec, { apiKey, signedIn: !fromEnv, baseURL }, flags, config, env);
  }
  if (!baseURL) {
    throw new Error(
      `${spec.id} needs the server address: --base-url, baseUrl in .minotaur.yml, or MINOTAUR_BASE_URL (Ollama is http://localhost:11434/v1)`,
    );
  }

  return finish(spec, { apiKey: env['MINOTAUR_API_KEY'], baseURL }, flags, config, env);
}

function finish(spec: ModelSpec, connection: ModelConnection, flags: ModelFlags, config: Config, env: Env): ResolvedModel {
  const capabilities = capabilitiesOf(spec);
  if (flags.effort && !capabilities.effort) {
    throw new Error(`--effort only applies to Anthropic models, not ${spec.id}`);
  }
  // The config's effort is for its own model, so a --model without effort support leaves it out.
  const requestedEffort = flags.effort ?? (capabilities.effort ? config.triage?.effort : undefined);
  const effort = capabilities.effort ? parseEffort(requestedEffort, DEFAULT_EXPLOIT_EFFORT, '--effort') : undefined;

  return {
    spec,
    model: createModel(spec, connection),
    pricing: resolvePricing(
      spec,
      {
        TRIAGE_PRICE_INPUT_PER_MTOK: env['MINOTAUR_PRICE_INPUT_PER_MTOK'],
        TRIAGE_PRICE_OUTPUT_PER_MTOK: env['MINOTAUR_PRICE_OUTPUT_PER_MTOK'],
      },
      'MINOTAUR',
    ),
    capabilities,
    ...(effort ? { effort } : {}),
    destination: describeDestination(spec, connection),
  };
}
