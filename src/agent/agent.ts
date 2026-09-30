/**
 * The triage agent for one finding.
 *
 * The model investigates with read-only tools and ends by calling
 * `submit_verdict`, whose input is the verdict schema, so a verdict is
 * validated before it exists. The loop itself, with its step and spend
 * limits, is in `loop.ts`.
 */

import type { LanguageModel } from 'ai';

import {
  exploitVerdictSchema,
  triageVerdictSchema,
  type AssessmentInput,
  type AssessmentMode,
  type Evidence,
  type ExploitVerdict,
  type TriageVerdict,
} from '../core/index.js';

import type { ModelPricing, SpendBudget, StepAllowance } from './budget.js';
import { checkEvidence, checkExploitEvidence } from './evidence.js';
import {
  EXPLOIT_SYSTEM_PROMPT,
  renderFinding,
  SYSTEM_PROMPT,
  type EarlierCheck,
  type TriageSubject,
} from './prompt.js';
import { ToolLoop } from './loop.js';
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
  const loop = new ToolLoop({
    model: options.model,
    pricing: options.pricing,
    budget: options.budget,
    maxSteps: options.maxSteps ?? DEFAULT_MAX_STEPS,
    allowance: options.allowance ?? DEFAULT_ALLOWANCE,
    abortSignal: options.abortSignal,
    effort: options.effort,
    forcedToolChoice: options.forcedToolChoice,
    promptCaching: options.promptCaching,
    onStep: options.onStep && ((usage) => options.onStep!({ ...usage, inputs: workspace.inputs() })),
  });
  const outcome = await loop.run({
    system: mode === 'exploit' ? EXPLOIT_SYSTEM_PROMPT : SYSTEM_PROMPT,
    messages: [{ role: 'user', content: renderFinding(subject, mode, options.earlier) }],
    tools: triageTools(workspace, mode),
    finalTool: 'submit_verdict',
    answer: 'a verdict',
    reminder: REMINDER,
    finalTurn: FINAL_TURN,
  });

  const base = {
    rejected: [],
    downgraded: false,
    inputs: workspace.inputs(),
    inputTokens: outcome.inputTokens,
    outputTokens: outcome.outputTokens,
    costUsd: outcome.costUsd,
    steps: outcome.steps,
  };
  if (outcome.status !== 'submitted') {
    return { ...base, status: outcome.status, ...(outcome.error ? { error: outcome.error } : {}) };
  }

  try {
    if (mode === 'exploit') {
      const parsed = exploitVerdictSchema.safeParse(outcome.submitted);
      if (!parsed.success) {
        return { ...base, status: 'failed', error: `invalid verdict: ${parsed.error.message}` };
      }
      const checked = await checkExploitEvidence(parsed.data, workspace);
      return { ...base, status: 'succeeded', exploit: checked.verdict, rejected: checked.rejected, downgraded: checked.downgraded };
    }

    const parsed = triageVerdictSchema.safeParse(outcome.submitted);
    if (!parsed.success) {
      return { ...base, status: 'failed', error: `invalid verdict: ${parsed.error.message}` };
    }
    const checked = await checkEvidence(parsed.data, workspace);
    return { ...base, status: 'succeeded', verdict: checked.verdict, rejected: checked.rejected, downgraded: checked.downgraded };
  } catch (error) {
    return { ...base, status: 'failed', error: (error as Error).message };
  }
}
