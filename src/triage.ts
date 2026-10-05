/**
 * One exploitability check of one finding, with nothing stored.
 *
 * The result is self-contained: written out with `--json`, it is also what
 * `--continue-from` reads back, which is how a follow-up digs deeper without
 * a database.
 */

import { readFile } from 'node:fs/promises';

import {
  DEFAULT_ALLOWANCE,
  EXPLOIT_PROMPT_VERSION,
  SpendBudget,
  Workspace,
  triageFinding,
  triageWithClaudeCode,
  type EarlierCheck,
  type StepProgress,
  type TriageSubject,
} from './agent/index.js';
import { evidenceSchema, exploitabilitySchema, isTriageable, protectedReason, type AssessmentInput } from './core/index.js';
import { z } from 'zod';

import type { CheckIdentity } from './check-cache.js';
import type { ResolvedModel } from './model.js';
import type { LocalFinding } from './sources.js';

export const DEFAULT_MAX_STEPS = 30;
export const DEFAULT_MAX_USD = 3;

export interface TriageLimits {
  maxSteps: number;
  maxUsd: number;
  maxTokens?: number | undefined;
}

export const triageResultSchema = z.object({
  version: z.literal(1),
  finding: z.object({
    id: z.string(),
    fingerprint: z.string(),
    kind: z.string(),
    severity: z.string(),
    title: z.string(),
    tools: z.array(z.string()),
    location: z.object({ path: z.string(), startLine: z.number().optional(), endLine: z.number().optional() }).nullable(),
  }),
  model: z.string(),
  promptVersion: z.string(),
  status: z.enum(['succeeded', 'failed', 'skipped_budget']),
  exploitability: exploitabilitySchema.nullable(),
  confidence: z.number().nullable(),
  entryPoint: z.string().nullable(),
  preconditions: z.array(z.string()),
  rationale: z.string().nullable(),
  evidence: z.array(evidenceSchema),
  openQuestions: z.array(z.string()),
  rejectedEvidence: z.array(evidenceSchema),
  downgraded: z.boolean(),
  filesRead: z.array(z.string()),
  continuedFrom: z.string().nullable(),
  steps: z.number(),
  inputTokens: z.number(),
  outputTokens: z.number(),
  costUsd: z.number(),
  durationMs: z.number(),
  error: z.string().nullable(),
});
export type TriageResult = z.infer<typeof triageResultSchema>;

/** Why a finding cannot go to a model, or null when it can. `protectedPaths` are the files with a detected secret. */
export function refusalFor(finding: LocalFinding, protectedPaths: ReadonlySet<string>): string | null {
  if (!isTriageable(finding.kind)) {
    return 'secret findings are never triaged, because judging one would send the credential to the model provider';
  }
  const path = finding.location?.path;
  const reason = path ? protectedReason(path, protectedPaths) : null;
  if (reason === 'credential_file') return `${path} is a credential file, so it is never sent to a model`;
  if (reason === 'secret_finding') return `${path} contains a detected secret, so it is never sent to a model`;
  return null;
}

export function toSubject(finding: LocalFinding): TriageSubject {
  return {
    id: finding.fingerprint,
    fingerprint: finding.fingerprint,
    kind: finding.kind,
    severity: finding.severity,
    title: finding.title,
    description: finding.description ?? null,
    ruleId: finding.ruleId ?? null,
    vulnerabilityIds: finding.vulnerabilityIds,
    location: finding.location ?? null,
    packageRef: finding.package ?? null,
    toolName: toolNames(finding).join(', '),
    epss: finding.epss ?? null,
    kev: finding.kev ?? false,
  };
}

function toolNames(finding: LocalFinding): string[] {
  return (finding.tools.length > 0 ? finding.tools : [finding.tool]).map((tool) => tool.name);
}

/** The notes a follow-up starts from, which must be a finished check of this same finding. */
export async function loadEarlierCheck(path: string, finding: LocalFinding): Promise<EarlierCheck> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(`could not read ${path}: ${(error as Error).message}`);
  }
  const parsed = triageResultSchema.safeParse(raw);
  if (!parsed.success) throw new Error(`${path} is not the JSON output of "minotaur triage --json"`);
  return earlierFrom(parsed.data, finding, path);
}

/** The notes of a finished check, for a follow-up on the same finding. `source` names it in errors. */
export function earlierFrom(earlier: TriageResult, finding: LocalFinding, source: string): EarlierCheck {
  if (earlier.finding.fingerprint !== finding.fingerprint) {
    throw new Error(`${source} is a check of finding ${earlier.finding.id}, not ${finding.id}`);
  }
  if (earlier.status !== 'succeeded' || !earlier.exploitability || !earlier.rationale) {
    throw new Error(`${source} has no finished answer to continue from; run a fresh check instead`);
  }
  return {
    exploitability: earlier.exploitability,
    confidence: earlier.confidence,
    rationale: earlier.rationale,
    entryPoint: earlier.entryPoint,
    preconditions: earlier.preconditions,
    evidence: earlier.evidence,
    openQuestions: earlier.openQuestions,
    filesRead: earlier.filesRead,
  };
}

export function describeModel(model: ResolvedModel): string {
  return `${model.destination} (${model.spec.id}${model.effort ? `, ${model.effort} effort` : ''})`;
}

/** The model and how it is reached, for the header of the browser: "anthropic:claude-sonnet-5 (medium) via ANTHROPIC_API_KEY". */
export function modelLabel(model: ResolvedModel): string {
  return `${model.spec.id}${model.effort ? ` (${model.effort})` : ''} via ${model.access}`;
}

export function describeLimits(model: ResolvedModel, limits: TriageLimits): string {
  const free = model.pricing.inputPerMTok === 0 && model.pricing.outputPerMTok === 0;
  const subscription = model.spec.provider === 'claude-code';
  const caps = [
    `${limits.maxSteps} steps`,
    ...(free ? [] : [`$${limits.maxUsd}`]),
    ...(limits.maxTokens && !subscription ? [`${limits.maxTokens.toLocaleString('en-US')} tokens`] : []),
  ];
  const note = subscription ? ' (uses your Claude subscription, not per-token billing)' : free ? ' (no per-token price for this model)' : '';
  return `${caps.join(', ')}${note}`;
}

export interface RunTriageOptions {
  root: string;
  finding: LocalFinding;
  /** Files with a detected secret, which the agent must not read. */
  protectedPaths: ReadonlySet<string>;
  model: ResolvedModel;
  limits: TriageLimits;
  earlier?: { check: EarlierCheck; from: string } | undefined;
  onStep?: (progress: StepProgress) => void;
  abortSignal?: AbortSignal;
  /** Keeps a finished check for reuse, with what it read. Nothing is kept without it. */
  keep?: ((result: TriageResult, inputs: readonly AssessmentInput[]) => Promise<unknown>) | undefined;
}

export function identityOf(model: ResolvedModel): CheckIdentity {
  return { model: model.spec.id, effort: model.effort ?? null };
}

export async function runTriage(options: RunTriageOptions): Promise<TriageResult> {
  const { finding, model, limits } = options;
  const refusal = refusalFor(finding, options.protectedPaths);
  if (refusal) throw new Error(refusal);

  const workspace = await Workspace.open(options.root, { denied: [...options.protectedPaths] });
  const started = Date.now();
  const subject = toSubject(finding);
  const result = model.model
    ? await triageFinding(subject, workspace, {
        model: model.model,
        pricing: model.pricing,
        budget: new SpendBudget(limits.maxUsd, limits.maxTokens),
        maxSteps: limits.maxSteps,
        // A full answer with an ordered attack path runs longer than a triage verdict.
        allowance: { ...DEFAULT_ALLOWANCE, maxOutputTokens: 4_000 },
        mode: 'exploit',
        forcedToolChoice: model.capabilities.forcedToolChoice,
        promptCaching: model.capabilities.promptCaching,
        ...(model.effort ? { effort: model.effort } : {}),
        ...(options.earlier ? { earlier: options.earlier.check } : {}),
        ...(options.onStep ? { onStep: options.onStep } : {}),
        ...(options.abortSignal ? { abortSignal: options.abortSignal } : {}),
      })
    : // No API client: Claude Code runs the check on the Claude subscription.
      await triageWithClaudeCode(subject, workspace, {
        modelId: model.spec.modelId,
        maxSteps: limits.maxSteps,
        mode: 'exploit',
        effort: model.effort,
        earlier: options.earlier?.check,
        onStep: options.onStep,
        abortSignal: options.abortSignal,
      });
  const exploit = result.exploit;

  const check: TriageResult = {
    version: 1,
    finding: {
      id: finding.id,
      fingerprint: finding.fingerprint,
      kind: finding.kind,
      severity: finding.severity,
      title: finding.title,
      tools: toolNames(finding),
      location: finding.location
        ? {
            path: finding.location.path,
            ...(finding.location.startLine ? { startLine: finding.location.startLine } : {}),
            ...(finding.location.endLine ? { endLine: finding.location.endLine } : {}),
          }
        : null,
    },
    model: model.spec.id,
    promptVersion: EXPLOIT_PROMPT_VERSION,
    status: result.status,
    exploitability: exploit?.exploitability ?? null,
    confidence: exploit?.confidence ?? null,
    entryPoint: exploit?.entryPoint ?? null,
    preconditions: exploit?.preconditions ?? [],
    rationale: exploit?.rationale ?? null,
    evidence: exploit?.evidence ?? [],
    openQuestions: exploit?.openQuestions ?? [],
    rejectedEvidence: result.rejected,
    downgraded: result.downgraded,
    filesRead: result.inputs.map((input) => input.path),
    continuedFrom: options.earlier?.from ?? null,
    steps: result.steps,
    inputTokens: result.inputTokens,
    outputTokens: result.outputTokens,
    costUsd: result.costUsd,
    durationMs: Date.now() - started,
    error: result.error ?? null,
  };
  // Losing the copy only costs a re-run later, so it never fails the check.
  await options.keep?.(check, result.inputs).catch(() => false);
  return check;
}
