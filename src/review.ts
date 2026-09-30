/**
 * Exploitability checks done by an agent in the editor, instead of a model.
 *
 * `brief` tells the agent which commit to read and how to answer. `verdict`
 * checks that answer against the files and keeps it with the other checks.
 */

import { AGENT_PROMPT_VERSION, Workspace, agentInstructions, renderFinding } from './agent/index.js';
import { checkExploitEvidence } from './agent/evidence.js';
import { exploitVerdictSchema, protectedReason, type ExploitVerdict } from './core/index.js';
import { z } from 'zod';

import type { CheckIdentity } from './check-cache.js';
import type { LocalFinding } from './sources.js';
import { earlierFrom, refusalFor, toSubject, type TriageResult } from './triage.js';

/** `agent`, or `agent:cursor` when a name is given. */
export function agentIdentity(name: string | undefined): CheckIdentity {
  const who = name?.trim();
  return { model: who ? `agent:${who}` : 'agent', effort: null };
}

export interface Brief {
  commit: { sha: string; short: string; subject: string } | null;
  /** Read files in this directory only. It is the commit, which may be a clean copy. */
  tree: string;
  finding: string;
  instructions: string;
  /** JSON Schema for the verdict. */
  verdict: unknown;
  /** Write the verdict JSON to this command's stdin, or pass it with --file. */
  submit: string;
  earlier: ReturnType<typeof earlierFrom> | null;
}

export function buildBrief(options: {
  finding: LocalFinding;
  tree: string;
  commit: Brief['commit'];
  submit: string;
  earlier?: TriageResult | undefined;
}): Brief {
  return {
    commit: options.commit,
    tree: options.tree,
    finding: renderFinding(toSubject(options.finding), 'exploit', options.earlier ? earlierFrom(options.earlier, options.finding, 'the earlier check') : undefined),
    instructions: agentInstructions(),
    verdict: z.toJSONSchema(exploitVerdictSchema),
    submit: options.submit,
    earlier: options.earlier ? earlierFrom(options.earlier, options.finding, 'the earlier check') : null,
  };
}

export interface VerdictRefusal {
  problems: string[];
}

/** Checks a verdict and builds the result to store. Does not write it. */
export async function reviewVerdict(options: {
  finding: LocalFinding;
  tree: string;
  protectedPaths: ReadonlySet<string>;
  raw: unknown;
  by: CheckIdentity;
}): Promise<{ result: TriageResult } | VerdictRefusal> {
  const refusal = refusalFor(options.finding, options.protectedPaths);
  if (refusal) return { problems: [refusal] };

  const parsed = exploitVerdictSchema.safeParse(options.raw);
  if (!parsed.success) {
    return { problems: parsed.error.issues.map((issue) => `${issue.path.join('.') || 'verdict'}: ${issue.message}`) };
  }

  const blocked = parsed.data.evidence.filter((item) => protectedReason(item.path, options.protectedPaths));
  if (blocked.length > 0) {
    return {
      problems: blocked.map((item) => `${item.path} holds a secret or is a credential file, so it cannot be cited`),
    };
  }

  const workspace = await Workspace.open(options.tree, { denied: [...options.protectedPaths] });
  const checked = await checkExploitEvidence(parsed.data, workspace);
  return { result: toResult(options.finding, checked.verdict, checked.rejected, checked.downgraded, options.by.model) };
}

function toResult(
  finding: LocalFinding,
  verdict: ExploitVerdict,
  rejected: ExploitVerdict['evidence'],
  downgraded: boolean,
  model: string,
): TriageResult {
  return {
    version: 1,
    finding: {
      id: finding.id,
      fingerprint: finding.fingerprint,
      kind: finding.kind,
      severity: finding.severity,
      title: finding.title,
      tools: (finding.tools.length > 0 ? finding.tools : [finding.tool]).map((tool) => tool.name),
      location: finding.location
        ? {
            path: finding.location.path,
            ...(finding.location.startLine ? { startLine: finding.location.startLine } : {}),
            ...(finding.location.endLine ? { endLine: finding.location.endLine } : {}),
          }
        : null,
    },
    model,
    promptVersion: AGENT_PROMPT_VERSION,
    status: 'succeeded',
    exploitability: verdict.exploitability,
    confidence: verdict.confidence,
    entryPoint: verdict.entryPoint ?? null,
    preconditions: verdict.preconditions,
    rationale: verdict.rationale,
    evidence: verdict.evidence,
    openQuestions: verdict.openQuestions,
    rejectedEvidence: rejected,
    downgraded,
    filesRead: [],
    continuedFrom: null,
    steps: 0,
    inputTokens: 0,
    outputTokens: 0,
    costUsd: 0,
    durationMs: 0,
    error: null,
  };
}
