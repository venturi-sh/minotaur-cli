/**
 * The tool loop the triage and fix agents share.
 *
 * The model works with tools and ends by calling one final tool, whose input
 * schema is the answer. The loop also ends at a step limit or when the next
 * call could break the spend cap; on the last affordable step the model is
 * made to call the final tool rather than keep working.
 *
 * One loop can run more than once. The counters and the prompt-cache marks
 * carry over, so a follow-up turn, such as "your fix did not pass, try
 * again", shares the step limit and the budget with the first one.
 *
 * A second budget, `pauseAt`, is shared by several loops, such as every fix
 * in a batch. When it runs out the loop pauses instead of finishing: the
 * conversation is kept, and `run` with the same messages picks it up once a
 * person has raised the cap.
 */

import {
  generateText,
  hasToolCall,
  isStepCount,
  type LanguageModel,
  type ModelMessage,
  type StopCondition,
  type ToolSet,
  wrapLanguageModel,
} from 'ai';

import {
  costOf,
  worstCaseStepTokens,
  worstCaseStepUsd,
  type ModelPricing,
  type SpendBudget,
  type StepAllowance,
} from './budget.js';
import type { Effort } from './model.js';

export interface LoopOptions {
  model: LanguageModel;
  pricing: ModelPricing;
  budget: SpendBudget;
  /** A shared cap that pauses the loop instead of ending it. */
  pauseAt?: SpendBudget | undefined;
  maxSteps: number;
  allowance: StepAllowance;
  abortSignal?: AbortSignal | undefined;
  /** Anthropic's effort setting; absent leaves the model's default. */
  effort?: Effort | undefined;
  /** False for models that reject a forced tool choice; they are reminded instead. Defaults to true. */
  forcedToolChoice?: boolean | undefined;
  /** Anthropic prompt-cache breakpoints. Defaults to true; other providers ignore or reject them. */
  promptCaching?: boolean | undefined;
  /** Called after every model call. */
  onStep?: ((usage: LoopUsage) => void) | undefined;
}

export interface LoopUsage {
  steps: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
}

export interface LoopRequest {
  system: string;
  /** The whole conversation so far. A follow-up passes the previous `messages` with a new user turn. */
  messages: ModelMessage[];
  tools: ToolSet;
  /** The tool whose call ends the loop. Its input is the answer. */
  finalTool: string;
  /** What the final tool submits, for errors: "a verdict". */
  answer: string;
  /** Sent when the model answers in prose instead of calling a tool. */
  reminder: string;
  /** Sent with the forced call on the last step the limits allow. */
  finalTurn: string;
}

export interface LoopOutcome extends LoopUsage {
  /** `paused`: the shared cap stopped it; run it again with `messages` to continue. */
  status: 'submitted' | 'failed' | 'skipped_budget' | 'paused';
  /** The final tool's input, not yet validated. Set when `status` is `submitted`. */
  submitted?: unknown;
  /** The conversation including the model's replies, to continue from. */
  messages: ModelMessage[];
  error?: string;
}

/** How many times a model that answered in prose is reminded to use the tools. */
const MAX_REMINDERS = 3;

const CACHE_CONTROL = { type: 'ephemeral' } as const;

/**
 * Every step resends the whole conversation, so the newest message is marked as
 * a prompt-cache breakpoint. The previous mark stays so the next call is sure to
 * find it; older marks are cleared, since Anthropic allows four at most.
 */
export function withCacheBreakpoints(messages: ModelMessage[], indexes: number[]): ModelMessage[] {
  return messages.map((message, index) => {
    const { anthropic, ...otherProviders } = message.providerOptions ?? {};
    const { cacheControl: _cleared, ...anthropicRest } = anthropic ?? {};
    const marked = indexes.includes(index);
    if (!marked && !anthropic?.cacheControl) return message;
    const nextAnthropic = marked ? { ...anthropicRest, cacheControl: CACHE_CONTROL } : anthropicRest;
    const providerOptions = Object.keys(nextAnthropic).length
      ? { ...otherProviders, anthropic: nextAnthropic }
      : otherProviders;
    return { ...message, providerOptions } as ModelMessage;
  });
}

/** Rough and deliberately high: this only has to bound the first call. */
function estimateTokens(text: string): number {
  return Math.ceil(text.length / 2.5);
}

function messageText(messages: readonly ModelMessage[]): string {
  return messages.map((message) => (typeof message.content === 'string' ? message.content : JSON.stringify(message.content))).join('');
}

const TOOL_DEFINITION_TOKENS = 1_500;

export class ToolLoop {
  private steps = 0;
  private inputTokens = 0;
  private outputTokens = 0;
  private costUsd = 0;
  private contextTokens = 0;
  private cachedTokens = 0;
  private previousBreakpoint: number | undefined;
  private lastFinish: string | undefined;
  private readonly model: LanguageModel;

  constructor(private readonly options: LoopOptions) {
    // Accounting happens per model call rather than per step, because a call the
    // SDK rejects afterwards, such as a refusal under a required tool choice,
    // never reaches onStepEnd but is still billed.
    this.model =
      typeof options.model === 'string'
        ? options.model
        : wrapLanguageModel({
            model: options.model,
            middleware: {
              specificationVersion: 'v4',
              wrapGenerate: async ({ doGenerate }) => {
                const response = await doGenerate();
                this.steps += 1;
                this.lastFinish = response.finishReason.unified;
                const usage = response.usage;
                const stepIn = usage.inputTokens.total ?? 0;
                const stepOut = usage.outputTokens.total ?? 0;
                const cacheReadTokens = usage.inputTokens.cacheRead ?? 0;
                const cacheWriteTokens = usage.inputTokens.cacheWrite ?? 0;
                const stepCost = costOf(options.pricing, { inputTokens: stepIn, outputTokens: stepOut, cacheReadTokens, cacheWriteTokens });
                this.inputTokens += stepIn;
                this.outputTokens += stepOut;
                this.costUsd += stepCost;
                options.budget.record(stepCost, stepIn + stepOut);
                options.pauseAt?.record(stepCost, stepIn + stepOut);
                this.contextTokens = stepIn + stepOut;
                this.cachedTokens = cacheReadTokens + cacheWriteTokens;
                options.onStep?.(this.usage());
                return response;
              },
            },
          });
  }

  usage(): LoopUsage {
    return { steps: this.steps, inputTokens: this.inputTokens, outputTokens: this.outputTokens, costUsd: this.costUsd };
  }

  /** False once the step limit is used up or the next call could break the spend cap. */
  canContinue(): boolean {
    return this.steps < this.options.maxSteps && this.canAffordForced();
  }

  private nextStepUsd(): number {
    return worstCaseStepUsd(this.options.pricing, this.contextTokens, this.options.allowance, this.cachedTokens);
  }

  /** Forcing a tool changes tool_choice, which invalidates the cached conversation. */
  private forcedStepUsd(): number {
    return worstCaseStepUsd(this.options.pricing, this.contextTokens, this.options.allowance);
  }

  private stepTokens(): number {
    return worstCaseStepTokens(this.contextTokens, this.options.allowance);
  }

  private canAffordNext(): boolean {
    return this.options.budget.canAfford(this.nextStepUsd(), this.stepTokens());
  }

  private canAffordForced(): boolean {
    return this.options.budget.canAfford(this.forcedStepUsd(), this.stepTokens());
  }

  /** True when the shared cap, not this loop's own, cannot pay for the next call. */
  private mustPause(): boolean {
    const pauseAt = this.options.pauseAt;
    return pauseAt !== undefined && !pauseAt.canAfford(this.forcedStepUsd(), 0);
  }

  private refused(): boolean {
    return this.lastFinish === 'content-filter';
  }

  private refusal(): string {
    const steps = this.steps;
    return `the model provider's safety filter refused to continue (stop reason "refusal") after ${steps} step${steps === 1 ? '' : 's'}`;
  }

  async run(request: LoopRequest): Promise<LoopOutcome> {
    const { options } = this;
    const { budget, allowance, maxSteps } = options;
    this.contextTokens = Math.max(this.contextTokens, estimateTokens(request.system + messageText(request.messages)) + TOOL_DEFINITION_TOKENS);
    let messages = request.messages;
    const done = (outcome: Omit<LoopOutcome, keyof LoopUsage | 'messages'>): LoopOutcome => ({ ...this.usage(), messages, ...outcome });

    if (!this.canAffordNext()) {
      return done({ status: 'skipped_budget', error: 'spend cap reached before this finding' });
    }
    if (this.mustPause()) return done({ status: 'paused' });

    const caching = options.promptCaching ?? true;
    const marked = (current: ModelMessage[], indexes: number[]) => (caching ? withCacheBreakpoints(current, indexes) : current);
    const outOfBudget: StopCondition<ToolSet> = () => !this.canAffordForced() || this.mustPause();
    const forced = options.forcedToolChoice ?? true;
    const { finalTool } = request;

    try {
      let submitted: { input: unknown } | undefined;
      let finish = 'unknown';

      for (let reminders = 0; ; reminders += 1) {
        const result = await generateText({
          model: this.model,
          system: request.system,
          messages,
          tools: request.tools,
          maxOutputTokens: allowance.maxOutputTokens,
          // Without this the model may answer in prose, which ends the loop with
          // no answer and the tokens already spent.
          toolChoice: forced ? 'required' : 'auto',
          maxRetries: 2,
          ...(options.abortSignal ? { abortSignal: options.abortSignal } : {}),
          ...(options.effort ? { providerOptions: { anthropic: { effort: options.effort } } } : {}),
          stopWhen: [hasToolCall(finalTool), isStepCount(maxSteps - this.steps), outOfBudget],
          prepareStep: ({ messages: current }) => {
            const lastStep = this.steps >= maxSteps - 1;
            const lastAffordable = !budget.canAfford(this.nextStepUsd() + this.forcedStepUsd(), 2 * this.stepTokens());
            if (lastStep || lastAffordable) {
              return {
                toolChoice: forced ? { type: 'tool', toolName: finalTool } : 'auto',
                activeTools: [finalTool],
                // A bare forced call reads as a stub to the model, which then submits "placeholder".
                messages: [...marked(current, []), { role: 'user', content: request.finalTurn }],
              };
            }
            const latest = current.length - 1;
            const breakpoints = this.previousBreakpoint === undefined ? [latest] : [this.previousBreakpoint, latest];
            this.previousBreakpoint = latest;
            return { messages: marked(current, breakpoints) };
          },
        });

        messages = [...messages, ...result.response.messages];
        submitted = result.steps.flatMap((step) => step.toolCalls).find((call) => call.toolName === finalTool);
        finish = result.steps.at(-1)?.finishReason ?? 'unknown';
        const answeredInProse = result.steps.at(-1)?.toolCalls.length === 0;
        if (submitted || !answeredInProse || this.refused() || reminders >= MAX_REMINDERS) break;
        if (this.mustPause()) break;
        if (this.steps >= maxSteps || !this.canAffordForced()) break;
        messages = [...messages, { role: 'user', content: request.reminder }];
      }

      if (!submitted && this.canAffordForced() && this.steps < maxSteps && this.mustPause() && !this.refused()) {
        return done({ status: 'paused' });
      }
      if (!submitted) {
        const stoppedForBudget = !this.canAffordNext();
        const steps = this.steps;
        return done({
          status: stoppedForBudget && !this.refused() ? 'skipped_budget' : 'failed',
          error: this.refused()
            ? this.refusal()
            : stoppedForBudget
              ? 'spend cap reached mid-investigation'
              : `the model did not submit ${request.answer} (stopped with "${finish}" after ${steps} step${steps === 1 ? '' : 's'})`,
        });
      }
      return done({ status: 'submitted', submitted: submitted.input });
    } catch (error) {
      return done({ status: 'failed', error: this.refused() ? this.refusal() : (error as Error).message });
    }
  }
}
