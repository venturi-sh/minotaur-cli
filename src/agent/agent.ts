/**
 * The triage loop for one finding.
 *
 * The model investigates with read-only tools and ends by calling
 * `submit_verdict`, whose input is the verdict schema, so a verdict is
 * validated before it exists. The loop also ends at a step limit or when the
 * next call could break the spend cap; on the last affordable step the model
 * is made to submit rather than keep reading.
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
  exploitVerdictSchema,
  triageVerdictSchema,
  type AssessmentInput,
  type AssessmentMode,
  type Evidence,
  type ExploitVerdict,
  type TriageVerdict,
} from '../core/index.js';

import {
  costOf,
  worstCaseStepTokens,
  worstCaseStepUsd,
  type ModelPricing,
  type SpendBudget,
  type StepAllowance,
} from './budget.js';
import { checkEvidence, checkExploitEvidence } from './evidence.js';
import {
  EXPLOIT_SYSTEM_PROMPT,
  renderFinding,
  SYSTEM_PROMPT,
  type EarlierCheck,
  type TriageSubject,
} from './prompt.js';
import type { Effort } from './model.js';
import { triageTools } from './tools.js';
import type { Workspace } from './workspace.js';

export interface AgentOptions {
  model: LanguageModel;
  pricing: ModelPricing;
  budget: SpendBudget;
  maxSteps?: number;
  allowance?: StepAllowance;
  abortSignal?: AbortSignal;
  /** `exploit` asks the deeper yes-or-no question with its own prompt and answer schema. */
  mode?: AssessmentMode;
  /** In exploit mode, a previous check to continue from. */
  earlier?: EarlierCheck;
  /** Anthropic's effort setting; absent leaves the model's default. */
  effort?: Effort;
  /** False for models that reject a forced tool choice; they are reminded instead. Defaults to true. */
  forcedToolChoice?: boolean;
  /** Anthropic prompt-cache breakpoints. Defaults to true; other providers ignore or reject them. */
  promptCaching?: boolean;
  /** Called after every model call, for showing progress. */
  onStep?: (progress: StepProgress) => void;
}

export interface StepProgress {
  steps: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  /** Everything read or searched so far. */
  inputs: AssessmentInput[];
}

/** How many times a model that answered in prose is reminded to use the tools. */
const MAX_REMINDERS = 3;

export const REMINDER =
  'Do not answer in prose. Keep investigating with the tools, and finish by calling submit_verdict with your answer.';

export const DEFAULT_MAX_STEPS = 8;

export const DEFAULT_ALLOWANCE: StepAllowance = {
  // A full read is about 20k characters; code runs near three characters a token.
  maxToolOutputTokens: 8_000,
  maxOutputTokens: 2_000,
};

export interface AgentResult {
  status: 'succeeded' | 'failed' | 'skipped_budget';
  verdict?: TriageVerdict;
  /** Set instead of `verdict` in exploit mode. */
  exploit?: ExploitVerdict;
  /** Citations dropped because the code did not match them. */
  rejected: Evidence[];
  downgraded: boolean;
  inputs: AssessmentInput[];
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  steps: number;
  error?: string;
}

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

const TOOL_DEFINITION_TOKENS = 1_500;

export const FINAL_TURN =
  'The investigation budget is used up and this is your final turn. Submit your real, final answer now, ' +
  'based only on what you have already read. The rationale must state your actual conclusion and reasoning, ' +
  'and cite the lines you relied on. If what you found is not enough to decide, say so and answer with the ' +
  'least committed option.';

export async function triageFinding(
  subject: TriageSubject,
  workspace: Workspace,
  options: AgentOptions,
): Promise<AgentResult> {
  const mode = options.mode ?? 'triage';
  const maxSteps = options.maxSteps ?? DEFAULT_MAX_STEPS;
  const allowance = options.allowance ?? DEFAULT_ALLOWANCE;
  const { budget, pricing } = options;
  const system = mode === 'exploit' ? EXPLOIT_SYSTEM_PROMPT : SYSTEM_PROMPT;
  const prompt = renderFinding(subject, mode, options.earlier);

  let inputTokens = 0;
  let outputTokens = 0;
  let costUsd = 0;
  let contextTokens = estimateTokens(system + prompt) + TOOL_DEFINITION_TOKENS;
  let cachedTokens = 0;
  let previousBreakpoint: number | undefined;

  const nextStepUsd = () => worstCaseStepUsd(pricing, contextTokens, allowance, cachedTokens);
  // Forcing a tool changes tool_choice, which invalidates the cached conversation.
  const forcedStepUsd = () => worstCaseStepUsd(pricing, contextTokens, allowance);
  const stepTokens = () => worstCaseStepTokens(contextTokens, allowance);
  const canAffordNext = () => budget.canAfford(nextStepUsd(), stepTokens());
  const canAffordForced = () => budget.canAfford(forcedStepUsd(), stepTokens());
  const caching = options.promptCaching ?? true;
  const marked = (messages: ModelMessage[], indexes: number[]) =>
    caching ? withCacheBreakpoints(messages, indexes) : messages;

  const base = () => ({
    rejected: [],
    downgraded: false,
    inputs: workspace.inputs(),
    inputTokens,
    outputTokens,
    costUsd,
  });

  if (!canAffordNext()) {
    return { ...base(), status: 'skipped_budget', steps: 0, error: 'spend cap reached before this finding' };
  }

  const outOfBudget: StopCondition<ToolSet> = () => !canAffordForced();
  const forced = options.forcedToolChoice ?? true;
  const tools = triageTools(workspace, mode);

  let steps = 0;
  let lastFinish: string | undefined;
  const refused = () => lastFinish === 'content-filter';
  const refusal = () =>
    `the model provider's safety filter refused to continue (stop reason "refusal") after ${steps} step${steps === 1 ? '' : 's'}`;

  // Accounting happens per model call rather than per step, because a call the
  // SDK rejects afterwards, such as a refusal under a required tool choice,
  // never reaches onStepEnd but is still billed.
  const model =
    typeof options.model === 'string'
      ? options.model
      : wrapLanguageModel({
          model: options.model,
          middleware: {
            specificationVersion: 'v4',
            wrapGenerate: async ({ doGenerate }) => {
              const response = await doGenerate();
              steps += 1;
              lastFinish = response.finishReason.unified;
              const usage = response.usage;
              const stepIn = usage.inputTokens.total ?? 0;
              const stepOut = usage.outputTokens.total ?? 0;
              const cacheReadTokens = usage.inputTokens.cacheRead ?? 0;
              const cacheWriteTokens = usage.inputTokens.cacheWrite ?? 0;
              const stepCost = costOf(pricing, { inputTokens: stepIn, outputTokens: stepOut, cacheReadTokens, cacheWriteTokens });
              inputTokens += stepIn;
              outputTokens += stepOut;
              costUsd += stepCost;
              budget.record(stepCost, stepIn + stepOut);
              contextTokens = stepIn + stepOut;
              cachedTokens = cacheReadTokens + cacheWriteTokens;
              options.onStep?.({ steps, inputTokens, outputTokens, costUsd, inputs: workspace.inputs() });
              return response;
            },
          },
        });

  try {
    let messages: ModelMessage[] = [{ role: 'user', content: prompt }];
    let submitted: { input: unknown } | undefined;
    let finish = 'unknown';

    for (let reminders = 0; ; reminders += 1) {
      const result = await generateText({
        model,
        system,
        messages,
        tools,
        maxOutputTokens: allowance.maxOutputTokens,
        // Without this the model may answer in prose, which ends the loop with
        // no verdict and the tokens already spent.
        toolChoice: forced ? 'required' : 'auto',
        maxRetries: 2,
        ...(options.abortSignal ? { abortSignal: options.abortSignal } : {}),
        ...(options.effort ? { providerOptions: { anthropic: { effort: options.effort } } } : {}),
        stopWhen: [hasToolCall('submit_verdict'), isStepCount(maxSteps - steps), outOfBudget],
        prepareStep: ({ messages: current }) => {
          const lastStep = steps >= maxSteps - 1;
          const lastAffordable = !budget.canAfford(nextStepUsd() + forcedStepUsd(), 2 * stepTokens());
          if (lastStep || lastAffordable) {
            return {
              toolChoice: forced ? { type: 'tool', toolName: 'submit_verdict' } : 'auto',
              activeTools: ['submit_verdict'],
              // A bare forced call reads as a stub to the model, which then submits "placeholder".
              messages: [...marked(current, []), { role: 'user', content: FINAL_TURN }],
            };
          }
          const latest = current.length - 1;
          const breakpoints = previousBreakpoint === undefined ? [latest] : [previousBreakpoint, latest];
          previousBreakpoint = latest;
          return { messages: marked(current, breakpoints) };
        },
      });

      submitted = result.steps.flatMap((step) => step.toolCalls).find((call) => call.toolName === 'submit_verdict');
      finish = result.steps.at(-1)?.finishReason ?? 'unknown';
      const answeredInProse = result.steps.at(-1)?.toolCalls.length === 0;
      if (submitted || !answeredInProse || refused() || reminders >= MAX_REMINDERS) break;
      if (steps >= maxSteps || !canAffordForced()) break;
      messages = [...messages, ...result.response.messages, { role: 'user', content: REMINDER }];
    }

    if (!submitted) {
      const stoppedForBudget = !canAffordNext();
      return {
        ...base(),
        status: stoppedForBudget && !refused() ? 'skipped_budget' : 'failed',
        steps,
        error: refused()
          ? refusal()
          : stoppedForBudget
            ? 'spend cap reached mid-investigation'
            : `the model did not submit a verdict (stopped with "${finish}" after ${steps} step${steps === 1 ? '' : 's'})`,
      };
    }

    if (mode === 'exploit') {
      const parsed = exploitVerdictSchema.safeParse(submitted.input);
      if (!parsed.success) {
        return { ...base(), status: 'failed', steps, error: `invalid verdict: ${parsed.error.message}` };
      }
      const checked = await checkExploitEvidence(parsed.data, workspace);
      return {
        ...base(),
        status: 'succeeded',
        exploit: checked.verdict,
        rejected: checked.rejected,
        downgraded: checked.downgraded,
        steps,
      };
    }

    const parsed = triageVerdictSchema.safeParse(submitted.input);
    if (!parsed.success) {
      return { ...base(), status: 'failed', steps, error: `invalid verdict: ${parsed.error.message}` };
    }

    const checked = await checkEvidence(parsed.data, workspace);
    return {
      ...base(),
      status: 'succeeded',
      verdict: checked.verdict,
      rejected: checked.rejected,
      downgraded: checked.downgraded,
      steps,
    };
  } catch (error) {
    return { ...base(), status: 'failed', steps, error: refused() ? refusal() : (error as Error).message };
  }
}
