/**
 * The triage contract.
 *
 * An agent reads the repository around a finding and says whether it is real.
 * What it says is attached beside the finding and never replaces the human
 * triage state: an agent that could close findings would, sooner or later,
 * close a real one where nobody would see it.
 *
 * Isomorphic, like the rest of core: the dashboard renders these types.
 */

import { z } from 'zod';

import type { FindingKind } from './finding.js';
import type { FindingState } from './scan.js';

export const TRIAGE_VERDICTS = ['true_positive', 'false_positive', 'needs_review'] as const;
export const triageVerdictValueSchema = z.enum(TRIAGE_VERDICTS);
export type TriageVerdictValue = z.infer<typeof triageVerdictValueSchema>;

export const REACHABILITY = ['reachable', 'unreachable', 'unknown'] as const;
export const reachabilitySchema = z.enum(REACHABILITY);
export type Reachability = z.infer<typeof reachabilitySchema>;

/**
 * `skipped_budget` is recorded rather than silently dropped, for the same
 * reason scanners report `skipped`: "not assessed" and "assessed as fine" must
 * never look alike.
 */
export const ASSESSMENT_STATUSES = ['succeeded', 'failed', 'skipped_budget'] as const;
export const assessmentStatusSchema = z.enum(ASSESSMENT_STATUSES);
export type AssessmentStatus = z.infer<typeof assessmentStatusSchema>;

/**
 * Kinds the agent is allowed to look at. Secrets are excluded because judging
 * one means sending the credential to a model provider.
 */
export const TRIAGE_KINDS = ['sca', 'sast', 'iac', 'license'] as const satisfies readonly FindingKind[];

export function isTriageable(kind: FindingKind): boolean {
  return (TRIAGE_KINDS as readonly FindingKind[]).includes(kind);
}

const SAFE_ENV_SUFFIXES = new Set(['.example', '.sample', '.template', '.dist']);

/** Files that routinely hold credentials. Reading one would send it to the model provider. */
export function isSensitiveFile(path: string): boolean {
  const name = (path.split(/[\\/]/).pop() ?? '').toLowerCase();

  if (name === '.env' || name.startsWith('.env.')) {
    const suffix = name.slice('.env'.length);
    return !SAFE_ENV_SUFFIXES.has(suffix);
  }
  if (/\.(pem|key|p12|pfx|jks|keystore|kdbx|ppk)$/.test(name)) return true;
  if (/^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/.test(name)) return true;
  return ['.npmrc', '.pypirc', '.netrc', '.git-credentials', 'credentials', 'credentials.json'].includes(
    name,
  );
}

/**
 * Whether a secret finding still keeps its file away from the agent. Only a
 * person marking it a false positive lifts that: "fixed" or "accepted risk"
 * say the secret was real, and an old copy may still be in the file.
 */
export function secretProtectsFile(state: FindingState): boolean {
  return state !== 'false_positive';
}

export type ProtectedReason = 'credential_file' | 'secret_finding';

/** Why the agent may not read `path`, or null when it may. */
export function protectedReason(path: string, secretPaths: ReadonlySet<string>): ProtectedReason | null {
  if (isSensitiveFile(path)) return 'credential_file';
  if (secretPaths.has(path)) return 'secret_finding';
  return null;
}

export const evidenceSchema = z.object({
  path: z.string().min(1),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  /** The cited text, checked against the file before the verdict is stored. */
  quote: z.string().min(1),
});
export type Evidence = z.infer<typeof evidenceSchema>;

export const triageVerdictSchema = z
  .object({
    verdict: triageVerdictValueSchema,
    reachability: reachabilitySchema,
    confidence: z.number().min(0).max(1),
    rationale: z.string().min(1),
    evidence: z.array(evidenceSchema).default([]),
  })
  .refine((value) => value.evidence.every((item) => item.endLine >= item.startLine), {
    message: 'evidence endLine must not precede startLine',
    path: ['evidence'],
  });
export type TriageVerdict = z.infer<typeof triageVerdictSchema>;

/**
 * The on-demand, deeper question: can an attacker actually trigger this here?
 * Both answers have to be shown in code. `undetermined` is what the agent says
 * when it could show neither, because a forced "no" is how real issues get
 * buried.
 */
export const EXPLOITABILITY = ['exploitable', 'not_exploitable', 'undetermined'] as const;
export const exploitabilitySchema = z.enum(EXPLOITABILITY);
export type Exploitability = z.infer<typeof exploitabilitySchema>;

export const exploitVerdictSchema = z.object({
  exploitability: exploitabilitySchema,
  confidence: z.number().min(0).max(1),
  rationale: z.string().min(1),
  /** Where attacker-controlled input enters, such as "POST /api/upload body". Absent when there is none. */
  entryPoint: z.string().min(1).optional(),
  /** What else must hold for the attack to work, such as "requires an authenticated user". */
  preconditions: z.array(z.string().min(1)).default([]),
  /**
   * For `exploitable`, the path in order from entry point to vulnerable call.
   * For `not_exploitable`, the code that blocks it.
   */
  evidence: z.array(evidenceSchema).default([]),
  /** What is still unresolved and where to look next, so a follow-up check can pick it up. */
  openQuestions: z.array(z.string().min(1)).default([]),
});
export type ExploitVerdict = z.infer<typeof exploitVerdictSchema>;

export const ASSESSMENT_MODES = ['triage', 'exploit'] as const;
export const assessmentModeSchema = z.enum(ASSESSMENT_MODES);
export type AssessmentMode = z.infer<typeof assessmentModeSchema>;

/** A file the agent read, hashed so a cached verdict can be reused only while the code is unchanged. */
export const assessmentInputSchema = z.object({
  path: z.string(),
  sha256: z.string().length(64),
});
export type AssessmentInput = z.infer<typeof assessmentInputSchema>;

export const TRIAGE_QUEUE = 'minotaur.triage';

/** Versioned for the same reason as the scan contract: bump rather than reinterpret. */
export const TRIAGE_JOB_CONTRACT_VERSION = 1;

export const triageJobSchema = z.object({
  contractVersion: z.literal(TRIAGE_JOB_CONTRACT_VERSION),
  scanId: z.uuid(),
  projectId: z.uuid(),
  /** Restricts the job to these findings, for a manual re-run. Absent means select automatically. */
  findingIds: z.array(z.uuid()).min(1).optional(),
  /** Ignore cached assessments. */
  force: z.boolean().default(false),
  /** `exploit` is the deeper on-demand check, and only runs on named findings. */
  mode: assessmentModeSchema.default('triage'),
  /** An earlier exploitability check of the one finding in `findingIds` to build on. */
  continueFrom: z.uuid().optional(),
})
  .refine((job) => job.mode === 'triage' || job.findingIds !== undefined, {
    message: 'an exploitability check needs explicit findingIds',
    path: ['findingIds'],
  })
  .refine((job) => job.continueFrom === undefined || (job.mode === 'exploit' && job.findingIds?.length === 1), {
    message: 'only an exploitability check of one finding can continue an earlier one',
    path: ['continueFrom'],
  });
export type TriageJob = z.infer<typeof triageJobSchema>;

/**
 * What the worker can do, published to Redis so the dashboard can say why no
 * verdicts are appearing. The key expires, so a missing key means no worker.
 */
export const TRIAGE_STATUS_KEY = 'minotaur:triage:status';
export const TRIAGE_STATUS_TTL_SECONDS = 90;

export const triageWorkerStatusSchema = z.object({
  enabled: z.boolean(),
  reason: z.string().optional(),
  model: z.string().optional(),
  maxUsdPerScan: z.number().optional(),
  maxFindingsPerScan: z.number().optional(),
  exploitModel: z.string().optional(),
  exploitMaxUsd: z.number().optional(),
  exploitEffort: z.string().optional(),
});
export type TriageWorkerStatus = z.infer<typeof triageWorkerStatusSchema>;

/** Reported through the job while it runs: `done` findings out of `total` selected. */
export const triageProgressSchema = z.object({
  done: z.number().int().nonnegative(),
  total: z.number().int().nonnegative(),
});
export type TriageProgress = z.infer<typeof triageProgressSchema>;

/** What a finished triage job returns, and what the dashboard shows for it. */
export interface TriageRunSummary {
  considered: number;
  triaged: number;
  reused: number;
  failed: number;
  skippedBudget: number;
  /** Left out because the per-scan finding cap was reached. */
  skippedCap: number;
  /** Left out because the finding sits in a file the agent may not read. */
  skippedProtected: number;
  costUsd: number;
}
