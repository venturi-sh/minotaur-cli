/**
 * When an earlier verdict can stand in for a new one.
 *
 * The key is the finding plus the prompt version and model that produced the
 * verdict, and the condition is that everything the agent looked at would look
 * the same today. That is narrower than "the commit changed", which would
 * re-triage everything on every push, and wider than "the flagged line
 * changed", which misses the caller that now sanitizes the input.
 */

import type { AssessmentInput } from '../core/index.js';

import type { Workspace } from './workspace.js';

export interface CachedAssessment {
  status: string;
  promptVersion: string;
  model: string;
  inputs: AssessmentInput[];
}

export async function isReusable(
  previous: CachedAssessment | undefined,
  current: { promptVersion: string; modelId: string },
  workspace: Workspace,
): Promise<boolean> {
  if (!previous || previous.status !== 'succeeded') return false;
  if (previous.promptVersion !== current.promptVersion || previous.model !== current.modelId) return false;
  return workspace.unchanged(previous.inputs);
}
