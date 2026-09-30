/**
 * The fix agent for one finding.
 *
 * The model reads and edits a writable workspace, which is a worktree of its
 * own, and ends by calling `submit_fix`. Whether the fix works is decided
 * outside, by running the scanner again. When it does not, `retry` sends the
 * scanner's answer back into the same conversation, within the same step and
 * spend limits.
 */

import type { LanguageModel, ModelMessage } from 'ai';

import type { ModelPricing, SpendBudget, StepAllowance } from './budget.js';
import { fixSubmissionSchema, type FixSubmission } from './fix-schema.js';
import { ToolLoop, type LoopUsage } from './loop.js';
import type { Effort } from './model.js';
import { FIX_SYSTEM_PROMPT, renderFixRequest, type EarlierCheck, type TriageSubject } from './prompt.js';
import { fixTools } from './tools.js';
import type { Workspace } from './workspace.js';

export { fixSubmissionSchema, type FixSubmission };

export interface FixAgentOptions {
  model: LanguageModel;
  pricing: ModelPricing;
  budget: SpendBudget;
  /** The batch's cap: when it runs out the fix pauses, and `resume` continues it. */
  pauseAt?: SpendBudget | undefined;
  maxSteps: number;
  abortSignal?: AbortSignal | undefined;
  effort?: Effort | undefined;
  forcedToolChoice?: boolean | undefined;
  promptCaching?: boolean | undefined;
  /** Extra instructions for this finding's kind, such as how a dependency is upgraded here. */
  guidance?: string | undefined;
  /** An earlier exploitability check, whose notes help find the cause. */
  earlier?: EarlierCheck | undefined;
  onStep?: ((progress: FixProgress) => void) | undefined;
}

export interface FixProgress extends LoopUsage {
  /** Files edited so far. */
  changedFiles: string[];
}

export interface FixAttempt extends LoopUsage {
  /** `paused`: the batch's cap was reached; call `resume` once it is raised. */
  status: 'submitted' | 'failed' | 'skipped_budget' | 'paused';
  submission?: FixSubmission;
  /** Every file edited so far, across attempts. */
  changedFiles: string[];
  error?: string;
}

/** A whole file rewritten is the largest reply the model needs to make. */
export const FIX_ALLOWANCE: StepAllowance = {
  maxToolOutputTokens: 8_000,
  maxOutputTokens: 8_000,
};

export const FIX_REMINDER =
  'Do not answer in prose. Keep working with the tools, and finish by calling submit_fix with your result.';

export const FIX_FINAL_TURN =
  'The budget for this fix is used up and this is your final turn. Call submit_fix now. If your edits are complete, ' +
  'submit fixed with a summary of what you changed. If they are not, submit gave_up and say what is left to do.';

export class FixSession {
  private readonly loop: ToolLoop;
  private messages: ModelMessage[] = [];

  constructor(
    private readonly subject: TriageSubject,
    private readonly workspace: Workspace,
    private readonly options: FixAgentOptions,
  ) {
    this.loop = new ToolLoop({
      model: options.model,
      pricing: options.pricing,
      budget: options.budget,
      pauseAt: options.pauseAt,
      maxSteps: options.maxSteps,
      allowance: FIX_ALLOWANCE,
      abortSignal: options.abortSignal,
      effort: options.effort,
      forcedToolChoice: options.forcedToolChoice,
      promptCaching: options.promptCaching,
      onStep: options.onStep && ((usage) => options.onStep!({ ...usage, changedFiles: workspace.changedFiles() })),
    });
  }

  /** The first attempt. */
  start(): Promise<FixAttempt> {
    return this.attempt([{ role: 'user', content: renderFixRequest(this.subject, this.options.earlier, this.options.guidance) }]);
  }

  /** Another attempt in the same conversation, after the fix did not pass. `feedback` says why. */
  retry(feedback: string): Promise<FixAttempt> {
    return this.attempt([...this.messages, { role: 'user', content: feedback }]);
  }

  /** Continues a paused attempt from where it stopped. */
  resume(): Promise<FixAttempt> {
    return this.attempt(this.messages);
  }

  /** False once the steps or the budget would not allow another attempt. */
  canRetry(): boolean {
    return this.loop.canContinue();
  }

  private async attempt(messages: ModelMessage[]): Promise<FixAttempt> {
    const outcome = await this.loop.run({
      system: FIX_SYSTEM_PROMPT,
      messages,
      tools: fixTools(this.workspace),
      finalTool: 'submit_fix',
      answer: 'a fix',
      reminder: FIX_REMINDER,
      finalTurn: FIX_FINAL_TURN,
    });
    this.messages = outcome.messages;
    const base = { ...this.loop.usage(), changedFiles: this.workspace.changedFiles() };
    if (outcome.status !== 'submitted') {
      return { ...base, status: outcome.status, ...(outcome.error ? { error: outcome.error } : {}) };
    }
    const parsed = fixSubmissionSchema.safeParse(outcome.submitted);
    if (!parsed.success) return { ...base, status: 'failed', error: `invalid submission: ${parsed.error.message}` };
    return { ...base, status: 'submitted', submission: parsed.data };
  }
}
