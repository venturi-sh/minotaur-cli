/**
 * Fixing findings on a branch of their own.
 *
 * Each finding is fixed in a worktree at the scanned commit, and the fix only
 * counts once the scanner that reported the finding runs again and no longer
 * reports it. A fix that passes becomes one commit; one that does not is
 * undone, so the next finding starts from the last good commit.
 */

import {
  FixSession,
  FIX_PROMPT_VERSION,
  SpendBudget,
  SUPPRESSION_MARKERS,
  Workspace,
  type EarlierCheck,
  type FixAttempt,
  type FixProgress,
  type FixSubmission,
} from './agent/index.js';
import { protectedReason, severityRank } from './core/index.js';

import { CONFIG_FILE, type SourceConfig } from './config.js';
import type { Target } from './commit.js';
import { DECISIONS_FILE } from './decisions.js';
import type { EnsureOptions } from './managed.js';
import type { ResolvedModel } from './model.js';
import { collectFindings, type CollectResult, type LocalFinding } from './sources.js';
import { toSubject, type TriageLimits } from './triage.js';
import {
  closeFixBranch,
  commitFix,
  discardChanges,
  openFixBranch,
  uncommittedDiff,
  type FixBranch,
} from './worktree.js';

/** A fix gets one more try after the scanner says it did not work. */
export const MAX_ATTEMPTS = 2;

/** Kinds the model can fix today. Dependencies and licenses come with package upgrades. */
const MODEL_FIXABLE = new Set(['sast', 'iac']);

export type FixStatus =
  /** Committed after the scanner no longer reported the finding. */
  | 'fixed'
  /** Committed without a rescan, because `--allow-unverified` was given. */
  | 'committed_unverified'
  /** Not committed: no scanner can run again to confirm it. */
  | 'unverified'
  | 'failed'
  | 'gave_up'
  /** The per-finding step or spend limit ran out. */
  | 'stopped_at_limit'
  /** Never tried, such as a secret, or a finding in a protected file. */
  | 'skipped';

export interface Verification {
  /** The scanners run again. Empty when none could be. */
  scanners: string[];
  passed: boolean;
  /** Why it did not pass, one line each. */
  problems: string[];
}

export interface FixResult {
  version: 1;
  finding: {
    id: string;
    fingerprint: string;
    kind: string;
    severity: string;
    title: string;
    location: { path: string; startLine?: number; endLine?: number } | null;
  };
  status: FixStatus;
  branch: string | null;
  commit: string | null;
  summary: string | null;
  notes: string[];
  changedFiles: string[];
  verification: Verification | null;
  attempts: number;
  model: string;
  promptVersion: string;
  steps: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  durationMs: number;
  error: string | null;
}

/** Why the model may not fix a finding, or null when it may. */
export function fixRefusal(finding: LocalFinding, protectedPaths: ReadonlySet<string>): string | null {
  if (finding.kind === 'secret') {
    return 'a model never fixes a secret, because it would have to read the credential; move it out of the code and rotate it';
  }
  if (!MODEL_FIXABLE.has(finding.kind)) return `fixing ${finding.kind === 'sca' ? 'dependency' : finding.kind} findings is not supported yet`;
  const path = finding.location?.path;
  if (!path) return 'the scanner gave no file for this finding';
  const reason = protectedReason(path, protectedPaths);
  if (reason === 'credential_file') return `${path} is a credential file, so it is never sent to a model`;
  if (reason === 'secret_finding') return `${path} contains a detected secret, so it is never sent to a model`;
  return null;
}

/** Scanner sources that can run again for this finding: the ones that reported it. Report files cannot. */
export function rescanSources(finding: LocalFinding, sources: readonly SourceConfig[]): SourceConfig[] {
  const reporters = new Set((finding.tools.length > 0 ? finding.tools : [finding.tool]).map((tool) => tool.name));
  return sources.filter((source) => 'scanner' in source && reporters.has(source.scanner));
}

/**
 * What the scanners reported before any fix, updated as fixes are committed,
 * so a finding a scanner reported all along never counts as new.
 */
export class Baseline {
  private findings: LocalFinding[];
  private readonly known: Set<string>;

  constructor(findings: readonly LocalFinding[]) {
    this.findings = [...findings];
    this.known = new Set(findings.map((finding) => finding.fingerprint));
  }

  isKnown(finding: LocalFinding): boolean {
    return this.known.has(finding.fingerprint);
  }

  /** How many findings of this rule the scanners reported in this file. */
  countOf(finding: LocalFinding): number {
    const key = issueKey(finding);
    return key ? this.findings.filter((other) => issueKey(other) === key).length : 0;
  }

  /** After a commit: what these scanners report now is the new normal. */
  accept(findings: readonly LocalFinding[], scanners: readonly string[]): void {
    const rescanned = new Set(scanners);
    this.findings = [...this.findings.filter((finding) => !reportedBy(finding).some((tool) => rescanned.has(tool))), ...findings];
    for (const finding of findings) this.known.add(finding.fingerprint);
  }
}

function reportedBy(finding: LocalFinding): string[] {
  return (finding.tools.length > 0 ? finding.tools : [finding.tool]).map((tool) => tool.name);
}

/** The same rule in the same file. Findings the rescan still reports under this key may be the same issue with new code. */
function issueKey(finding: LocalFinding): string | null {
  if (!finding.ruleId || !finding.location) return null;
  return `${finding.ruleId}\u0000${finding.location.path}`;
}

/** Lines the diff adds that silence a scanner. */
export function suppressionsIn(diff: string): string[] {
  const markers = SUPPRESSION_MARKERS.map((marker) => marker.toLowerCase());
  return diff
    .split('\n')
    .filter((line) => line.startsWith('+') && !line.startsWith('+++'))
    .map((line) => line.slice(1))
    .filter((line) => markers.some((marker) => line.toLowerCase().includes(marker)))
    .map((line) => line.trim());
}

export type Rescan = (tree: string, sources: readonly SourceConfig[]) => Promise<CollectResult>;

/**
 * Checks a fix: the scanners that reported the finding no longer do, nothing
 * as severe is new in the changed files, and no line silences a scanner.
 */
export async function verifyFix(options: {
  finding: LocalFinding;
  tree: string;
  sources: readonly SourceConfig[];
  changedFiles: readonly string[];
  diff: string;
  baseline: Baseline;
  rescan: Rescan;
}): Promise<{ verification: Verification; after: LocalFinding[] }> {
  const { finding, baseline } = options;
  const problems = suppressionsIn(options.diff).map((line) => `the change silences the scanner instead of fixing the code: ${line}`);
  const scanners = options.sources.map((source) => ('scanner' in source ? source.scanner : source.report));
  if (options.sources.length === 0) return { verification: { scanners, passed: false, problems }, after: [] };

  const collected = await options.rescan(options.tree, options.sources);
  const broken = collected.sources.filter((outcome) => outcome.status === 'failed');
  for (const outcome of broken) problems.push(`${outcome.source} could not run again: ${outcome.error ?? 'failed'}`);
  const after = collected.findings;

  if (after.some((other) => other.fingerprint === finding.fingerprint)) {
    problems.push(`the scanner still reports the finding at ${where(finding)}`);
  } else if (issueKey(finding)) {
    const before = baseline.countOf(finding);
    const now = after.filter((other) => issueKey(other) === issueKey(finding)).length;
    if (now >= before) problems.push(`the scanner still reports ${finding.ruleId} in ${finding.location!.path} as often as before (${now})`);
  }

  // A finding in a changed file with a new fingerprint may be old code that moved. It is new only when its rule fires there more often than before.
  const changed = new Set(options.changedFiles);
  const added = new Map<string, LocalFinding>();
  for (const other of after) {
    if (baseline.isKnown(other) || !other.location || !changed.has(other.location.path)) continue;
    if (other.kind !== 'secret' && severityRank(other.severity) < severityRank(finding.severity)) continue;
    const key = issueKey(other) ?? other.fingerprint;
    const now = after.filter((each) => (issueKey(each) ?? each.fingerprint) === key).length;
    if (issueKey(other) && now <= baseline.countOf(other)) continue;
    added.set(key, other);
  }
  for (const other of added.values()) problems.push(`the change adds a ${other.severity} finding: ${other.title} at ${where(other)}`);
  return { verification: { scanners, passed: problems.length === 0, problems }, after };
}

function where(finding: Pick<LocalFinding, 'location'>): string {
  const location = finding.location;
  if (!location) return 'no location';
  return `${location.path}${location.startLine ? `:${location.startLine}` : ''}`;
}

export type FixEvent =
  | { type: 'start'; finding: LocalFinding; index: number; total: number }
  | { type: 'step'; finding: LocalFinding; progress: FixProgress; maxSteps: number }
  | { type: 'verify'; finding: LocalFinding; scanners: string[] }
  | { type: 'retry'; finding: LocalFinding; problems: string[] }
  | { type: 'done'; result: FixResult };

export interface RunFixesOptions {
  target: Target;
  /** The findings to fix, in order. */
  findings: readonly LocalFinding[];
  /** Everything the scan reported, which the rescans are compared with. */
  scanned: readonly LocalFinding[];
  protectedPaths: ReadonlySet<string>;
  model: ResolvedModel;
  limits: TriageLimits;
  /** The configured sources. Only the scanners among them run again. */
  sources: readonly SourceConfig[];
  includeIgnored: boolean;
  branch: string;
  cache: string;
  force?: boolean;
  allowUnverified?: boolean;
  /** Earlier exploitability checks, by fingerprint. */
  earlier?: ReadonlyMap<string, EarlierCheck>;
  managed?: EnsureOptions;
  abortSignal?: AbortSignal;
  onEvent?: (event: FixEvent) => void;
  /** For tests: how the tree is scanned again. */
  rescan?: Rescan;
}

export interface FixRun {
  /** The branch with the commits, or null when nothing was committed and it was removed. */
  branch: string | null;
  results: FixResult[];
  /** True when Ctrl-C stopped the run before every finding was tried. */
  interrupted: boolean;
}

export async function runFixes(options: RunFixesOptions): Promise<FixRun> {
  const branch = await openFixBranch(options.target, options.branch, options.cache, { force: options.force ?? false });
  const baseline = new Baseline(options.scanned);
  const rescan: Rescan =
    options.rescan ??
    ((tree, sources) => collectFindings(tree, sources, { includeIgnored: options.includeIgnored, managed: options.managed ?? {} }));
  const results: FixResult[] = [];
  let kept = false;
  try {
    for (const [index, finding] of options.findings.entries()) {
      if (options.abortSignal?.aborted) break;
      options.onEvent?.({ type: 'start', finding, index, total: options.findings.length });
      const result = await fixOne(finding, branch, baseline, rescan, options);
      results.push(result);
      options.onEvent?.({ type: 'done', result });
    }
  } finally {
    ({ kept } = await closeFixBranch(branch));
  }
  if (!kept) for (const result of results) result.branch = null;
  return { branch: kept ? branch.name : null, results, interrupted: options.abortSignal?.aborted ?? false };
}

async function fixOne(
  finding: LocalFinding,
  branch: FixBranch,
  baseline: Baseline,
  rescan: Rescan,
  options: RunFixesOptions,
): Promise<FixResult> {
  const started = Date.now();
  const base = resultBase(finding, options.model, branch.name);
  const refusal = fixRefusal(finding, options.protectedPaths);
  if (refusal) return { ...base, status: 'skipped', error: refusal, durationMs: 0 };

  const workspace = await Workspace.open(branch.tree, {
    denied: [...options.protectedPaths],
    writable: { readOnly: [CONFIG_FILE, `${DECISIONS_FILE.split('/')[0]}/`] },
  });
  const { model, limits } = options;
  const session = new FixSession(toSubject(finding), workspace, {
    model: model.model,
    pricing: model.pricing,
    budget: new SpendBudget(limits.maxUsd, limits.maxTokens),
    maxSteps: limits.maxSteps,
    abortSignal: options.abortSignal,
    effort: model.effort,
    forcedToolChoice: model.capabilities.forcedToolChoice,
    promptCaching: model.capabilities.promptCaching,
    earlier: options.earlier?.get(finding.fingerprint),
    onStep: (progress) => options.onEvent?.({ type: 'step', finding, progress, maxSteps: limits.maxSteps }),
  });
  const sources = rescanSources(finding, options.sources);

  let attempt: FixAttempt | undefined;
  let verification: Verification | null = null;
  const finish = async (status: FixStatus, extra: Partial<FixResult> = {}): Promise<FixResult> => {
    const committed = extra.commit != null;
    if (!committed) await discardChanges(branch);
    return {
      ...base,
      status,
      summary: attempt?.submission?.summary ?? null,
      notes: attempt?.submission?.notes ?? [],
      changedFiles: attempt?.changedFiles ?? [],
      verification,
      steps: attempt?.steps ?? 0,
      inputTokens: attempt?.inputTokens ?? 0,
      outputTokens: attempt?.outputTokens ?? 0,
      costUsd: attempt?.costUsd ?? 0,
      durationMs: Date.now() - started,
      ...extra,
    };
  };

  try {
    for (let attempts = 1; ; attempts += 1) {
      attempt = attempts === 1 ? await session.start() : await session.retry(retryPrompt(verification!));
      const counted = { attempts };
      if (attempt.status === 'skipped_budget') return finish('stopped_at_limit', { ...counted, error: attempt.error ?? 'the limit ran out' });
      if (attempt.status === 'failed') return finish('failed', { ...counted, error: attempt.error ?? 'the model failed' });
      if (attempt.submission?.outcome === 'gave_up') return finish('gave_up', counted);
      if (attempt.changedFiles.length === 0) return finish('failed', { ...counted, error: 'the model changed no files' });

      const diff = await uncommittedDiff(branch, attempt.changedFiles);
      options.onEvent?.({ type: 'verify', finding, scanners: sources.map((source) => ('scanner' in source ? source.scanner : source.report)) });
      const checked = await verifyFix({ finding, tree: branch.tree, sources, changedFiles: attempt.changedFiles, diff, baseline, rescan });
      verification = checked.verification;

      if (sources.length === 0 && verification.problems.length === 0) {
        if (!options.allowUnverified) {
          return finish('unverified', { ...counted, error: 'no scanner that reported this finding can run again; --allow-unverified commits it anyway' });
        }
        const commit = await commitFix(branch, attempt.changedFiles, commitMessage(finding, attempt.submission!, model, false));
        return finish('committed_unverified', { ...counted, commit });
      }
      if (verification.passed) {
        const commit = await commitFix(branch, attempt.changedFiles, commitMessage(finding, attempt.submission!, model, true));
        baseline.accept(checked.after, verification.scanners);
        return finish('fixed', { ...counted, commit });
      }
      if (attempts >= MAX_ATTEMPTS || !session.canRetry() || options.abortSignal?.aborted) {
        return finish('failed', { ...counted, error: verification.problems.join('; ') });
      }
      options.onEvent?.({ type: 'retry', finding, problems: verification.problems });
    }
  } catch (error) {
    return finish('failed', { error: (error as Error).message });
  }
}

function retryPrompt(verification: Verification): string {
  return [
    `The fix did not pass. ${verification.scanners.join(', ')} ran again on your change and found:`,
    ...verification.problems.map((problem) => `- ${problem}`),
    '',
    'Your edits are still in the files. Fix the cause, then call submit_fix again.',
  ].join('\n');
}

function commitMessage(finding: LocalFinding, submission: FixSubmission, model: ResolvedModel, verified: boolean): string {
  const title = finding.title.length > 60 ? `${finding.title.slice(0, 57)}...` : finding.title;
  return [
    `fix(security): ${title}`,
    '',
    submission.summary,
    ...(submission.notes.length > 0 ? ['', 'For the reviewer:', ...submission.notes.map((note) => `- ${note}`)] : []),
    ...(verified ? [] : ['', 'Not verified: no scanner that reported this finding could run again.']),
    '',
    `Minotaur-Finding: ${finding.fingerprint}`,
    `Minotaur-Model: ${model.spec.id}`,
  ].join('\n');
}

function resultBase(finding: LocalFinding, model: ResolvedModel, branch: string): Omit<FixResult, 'status' | 'durationMs'> {
  return {
    version: 1,
    finding: {
      id: finding.id,
      fingerprint: finding.fingerprint,
      kind: finding.kind,
      severity: finding.severity,
      title: finding.title,
      location: finding.location
        ? {
            path: finding.location.path,
            ...(finding.location.startLine ? { startLine: finding.location.startLine } : {}),
            ...(finding.location.endLine ? { endLine: finding.location.endLine } : {}),
          }
        : null,
    },
    branch,
    commit: null,
    summary: null,
    notes: [],
    changedFiles: [],
    verification: null,
    attempts: 0,
    model: model.spec.id,
    promptVersion: FIX_PROMPT_VERSION,
    steps: 0,
    inputTokens: 0,
    outputTokens: 0,
    costUsd: 0,
    error: null,
  };
}
