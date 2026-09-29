/**
 * Spend control.
 *
 * The cap is enforced before a model call, never after it: a limit checked
 * once the money is spent is a report, not a limit. Each call is priced at its
 * worst case — the context so far plus the largest tool output, and the full
 * output allowance — so the cap holds even when a step turns out expensive.
 * Cached input is priced at the cache rates, which is what makes long
 * investigations affordable: each step resends the whole conversation.
 */

export interface ModelPricing {
  /** US dollars per million input tokens. */
  inputPerMTok: number;
  /** US dollars per million output tokens. */
  outputPerMTok: number;
  /** A cache read as a fraction of input, when the model differs from `CACHE_READ_MULTIPLIER`. */
  cacheReadMultiplier?: number;
}

/**
 * List prices, which have to be kept in step with the provider. A model not
 * listed here needs `TRIAGE_PRICE_INPUT_PER_MTOK` and
 * `TRIAGE_PRICE_OUTPUT_PER_MTOK`, because without a price there is no way to
 * enforce the cap, and running uncapped is not an acceptable default.
 */
export const MODEL_PRICING: Record<string, ModelPricing> = {
  'anthropic:claude-sonnet-5': { inputPerMTok: 3, outputPerMTok: 15 },
  'anthropic:claude-sonnet-4-6': { inputPerMTok: 3, outputPerMTok: 15 },
  'anthropic:claude-sonnet-4-5': { inputPerMTok: 3, outputPerMTok: 15 },
  'anthropic:claude-haiku-4-5': { inputPerMTok: 1, outputPerMTok: 5 },
  'anthropic:claude-opus-5': { inputPerMTok: 5, outputPerMTok: 25 },
  'anthropic:claude-opus-5-5': { inputPerMTok: 4, outputPerMTok: 20, cacheReadMultiplier: 0.05 },
};

/** Anthropic prices prompt-cache writes (5-minute lifetime) and reads relative to plain input. */
export const CACHE_WRITE_MULTIPLIER = 1.25;
export const CACHE_READ_MULTIPLIER = 0.1;

export interface Usage {
  /** All input tokens, cached or not. */
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
}

export function costOf(pricing: ModelPricing, usage: Usage): number {
  const read = usage.cacheReadTokens ?? 0;
  const write = usage.cacheWriteTokens ?? 0;
  const plain = Math.max(0, usage.inputTokens - read - write);
  const input = plain + write * CACHE_WRITE_MULTIPLIER + read * (pricing.cacheReadMultiplier ?? CACHE_READ_MULTIPLIER);
  return (input * pricing.inputPerMTok + usage.outputTokens * pricing.outputPerMTok) / 1_000_000;
}

/**
 * A dollar cap, and optionally a token cap. A self-hosted model is free per
 * token but not per minute, so the token cap is how a local run is bounded
 * when steps alone are too coarse.
 */
export class SpendBudget {
  private spent = 0;
  private tokens = 0;

  constructor(
    readonly limitUsd: number,
    readonly limitTokens = Number.POSITIVE_INFINITY,
  ) {
    if (!(limitUsd >= 0)) throw new Error(`invalid spend limit: ${limitUsd}`);
    if (!(limitTokens > 0)) throw new Error(`invalid token limit: ${limitTokens}`);
  }

  get spentUsd(): number {
    return this.spent;
  }

  get spentTokens(): number {
    return this.tokens;
  }

  get remainingUsd(): number {
    return Math.max(0, this.limitUsd - this.spent);
  }

  canAfford(costUsd: number, tokens = 0): boolean {
    return this.spent + costUsd <= this.limitUsd && this.tokens + tokens <= this.limitTokens;
  }

  record(costUsd: number, tokens = 0): void {
    this.spent += Math.max(0, costUsd);
    this.tokens += Math.max(0, tokens);
  }
}

/** Tokens the next call could use at most: the context, the largest tool output and the full output allowance. */
export function worstCaseStepTokens(contextTokens: number, allowance: StepAllowance): number {
  return contextTokens + allowance.maxToolOutputTokens + allowance.maxOutputTokens;
}

export interface StepAllowance {
  /** Tokens a single tool result may add to the context. */
  maxToolOutputTokens: number;
  /** The output allowance given to each call. */
  maxOutputTokens: number;
}

/**
 * What the next call could cost if everything about it goes the expensive way.
 * `cachedTokens` is the prefix the previous call cached; it is priced as a
 * read, which assumes the cache outlives the seconds between two steps.
 * Everything after it is priced as a cache write.
 */
export function worstCaseStepUsd(
  pricing: ModelPricing,
  contextTokens: number,
  allowance: StepAllowance,
  cachedTokens = 0,
): number {
  const cached = Math.min(cachedTokens, contextTokens);
  const fresh = contextTokens - cached + allowance.maxToolOutputTokens;
  return costOf(pricing, {
    inputTokens: cached + fresh,
    outputTokens: allowance.maxOutputTokens,
    cacheReadTokens: cached,
    cacheWriteTokens: fresh,
  });
}
