/**
 * Fixing findings on a branch of their own.
 *
 * Each finding is fixed in a worktree at the scanned commit, and the fix only
 * counts once the scanner that reported the finding runs again and no longer
 * reports it. A fix that passes becomes one commit; one that does not is
 * undone, so the next finding starts from the last good commit.
 *
 * Code and configuration are fixed by a model. A dependency with a known
 * fixed version is upgraded by its package manager, and only falls back to a
 * model when that is not possible.
 *
 * A batch can have a spend cap of its own. Reaching it is a checkpoint, not
 * an end: the person is asked whether to go on, and each "yes" allows one more
 * cap's worth. The fix in progress waits, with its conversation, for the
 * answer.
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
  applyUpgrade,
  chooseVersion,
  compareVersions,
  LOCKFILES,
  planUpgrade,
  relock,
  ToolMissingError,
  UpgradeError,
  type Runner,
  type UpgradePlan,
} from './upgrade.js';
import {
  changedPaths,
  closeFixBranch,
  commitFix,
  commitsOnBranch,
  discardChanges,
  fixedOnBranch,
  openFixBranch,
  uncommittedDiff,
  type FixBranch,
} from './worktree.js';

/** A fix gets one more try after the scanner says it did not work. */
export const MAX_ATTEMPTS = 2;

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
  /** The person chose to stop at the batch's checkpoint while this fix was in progress. */
  | 'stopped_at_cap'
  /** The run stopped before this finding. */
  | 'not_tried'
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
  /** The model, or the package manager, that made the change. */
  model: string;
  promptVersion: string;
  steps: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  durationMs: number;
  error: string | null;
}

/** Why a finding cannot be fixed here, or null when it can. */
export function fixRefusal(finding: LocalFinding, protectedPaths: ReadonlySet<string>): string | null {
  if (finding.kind === 'secret') {
    return 'a model never fixes a secret, because it would have to read the credential; move it out of the code and rotate it';
  }
  const path = finding.location?.path;
  if (!path) return 'the scanner gave no file for this finding';
  const reason = protectedReason(path, protectedPaths);
  if (reason === 'credential_file') return `${path} is a credential file, so it is never sent to a model`;
  if (reason === 'secret_finding') return `${path} contains a detected secret, so it is never sent to a model`;
  return null;
}

function isDependency(finding: LocalFinding): boolean {
  return finding.kind === 'sca' || finding.kind === 'license';
}

/** Scanner sources that can run again for this finding: the ones that reported it. Report files cannot. */
export function rescanSources(finding: LocalFinding, sources: readonly SourceConfig[]): SourceConfig[] {
  const reporters = new Set(reportedBy(finding));
  return sources.filter((source) => 'scanner' in source && reporters.has(source.scanner));
}

/**
 * The version to upgrade a package to. Several findings of one package in one
 * file are fixed by one upgrade, so it has to reach the highest version any
 * of them needs.
 */
export function upgradeVersion(finding: LocalFinding, batch: readonly LocalFinding[]): string | null {
  const same = batch.filter(
    (other) => other.kind === 'sca' && other.package?.name === finding.package?.name && other.location?.path === finding.location?.path,
  );
  const versions = [finding, ...same]
    .map((other) => chooseVersion(other.package?.version, other.package?.fixedVersion))
    .filter((version): version is string => version !== null);
  return versions.sort(compareVersions).at(-1) ?? null;
}

/**
 * What the scanners reported before any fix, updated as fixes are committed,
 * so a finding a scanner reported all along never counts as new, and one an
 * earlier fix removed is not fixed twice.
 */
export class Baseline {
  private findings: LocalFinding[];
  private readonly known: Set<string>;
  private readonly fixedBy = new Map<string, string>();

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

  /** The commit that made the scanners stop reporting this finding, if one did. */
  resolvedBy(finding: LocalFinding): string | undefined {
    return this.fixedBy.get(finding.fingerprint);
  }

  /** After `commit`: what these scanners report now is the new normal. */
  accept(findings: readonly LocalFinding[], scanners: readonly string[], commit: string): void {
    const rescanned = new Set(scanners);
    const now = new Set(findings.map((finding) => finding.fingerprint));
    const covered = (finding: LocalFinding) => reportedBy(finding).some((tool) => rescanned.has(tool));
    for (const finding of this.findings) {
      if (covered(finding) && !now.has(finding.fingerprint) && !this.fixedBy.has(finding.fingerprint)) this.fixedBy.set(finding.fingerprint, commit);
    }
    this.findings = [...this.findings.filter((finding) => !covered(finding)), ...findings];
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
  | { type: 'upgrade'; finding: LocalFinding; description: string }
  | { type: 'verify'; finding: LocalFinding; scanners: string[] }
  | { type: 'retry'; finding: LocalFinding; problems: string[] }
  | { type: 'resumed'; alreadyOnBranch: number }
  | { type: 'done'; result: FixResult };

/** What a person is shown at the batch's checkpoint. */
export interface Checkpoint {
  spentUsd: number;
  capUsd: number;
  /** The finding in progress, which waits for the answer. */
  current: LocalFinding;
  results: readonly FixResult[];
  /** Findings not started yet, the current one left out. */
  remaining: number;
}

export interface RunFixesOptions {
  target: Target;
  /** The findings to fix, in order. */
  findings: readonly LocalFinding[];
  /** Everything the scan reported, which the rescans are compared with. */
  scanned: readonly LocalFinding[];
  protectedPaths: ReadonlySet<string>;
  /** Null when none is configured: package manager upgrades still work, and every other fix fails with `noModel`. */
  model: ResolvedModel | null;
  /** Why there is no model, for the findings that need one. */
  noModel?: string | undefined;
  /** The limits for each finding. */
  limits: TriageLimits;
  /** The batch's cap in US dollars. Each time it is reached, `onCheckpoint` decides whether to allow as much again. */
  maxTotalUsd?: number | undefined;
  /** Resolves true to continue. Without it, the run stops at the cap. */
  onCheckpoint?: ((checkpoint: Checkpoint) => Promise<boolean>) | undefined;
  /** The configured sources. Only the scanners among them run again. */
  sources: readonly SourceConfig[];
  includeIgnored: boolean;
  branch: string;
  cache: string;
  force?: boolean;
  /** Continue the branch from an earlier run, skipping what it already fixed. */
  resume?: boolean;
  allowUnverified?: boolean;
  /** Earlier exploitability checks, by fingerprint. */
  earlier?: ReadonlyMap<string, EarlierCheck>;
  managed?: EnsureOptions;
  abortSignal?: AbortSignal;
  onEvent?: (event: FixEvent) => void;
  /** For tests: how the tree is scanned again. */
  rescan?: Rescan;
  /** For tests: how package managers run. */
  runTool?: Runner;
}

export interface FixRun {
  /** The branch with the commits, or null when nothing was committed and it was removed. */
  branch: string | null;
  results: FixResult[];
  /** True when Ctrl-C stopped the run before every finding was tried. */
  interrupted: boolean;
  /** True when the person, or the lack of one to ask, stopped the run at the batch's cap. */
  stoppedAtCap: boolean;
  /** Findings a resumed run skipped because the branch already has their commit. */
  alreadyOnBranch: number;
}

/** Shared by every finding in one run. */
interface RunState {
  branch: FixBranch;
  baseline: Baseline;
  rescan: Rescan;
  batch: SpendBudget | undefined;
  results: FixResult[];
  remaining: number;
  stoppedAtCap: boolean;
}

export async function runFixes(options: RunFixesOptions): Promise<FixRun> {
  const branch = await openFixBranch(options.target, options.branch, options.cache, { force: options.force ?? false, resume: options.resume ?? false });
  const rescan: Rescan =
    options.rescan ??
    ((tree, sources) => collectFindings(tree, sources, { includeIgnored: options.includeIgnored, managed: options.managed ?? {} }));
  const state: RunState = {
    branch,
    baseline: new Baseline(options.scanned),
    rescan,
    batch: options.maxTotalUsd === undefined ? undefined : new SpendBudget(options.maxTotalUsd),
    results: [],
    remaining: 0,
    stoppedAtCap: false,
  };
  let kept = false;
  let todo = [...options.findings];
  let alreadyOnBranch = 0;
  try {
    if (options.resume) {
      const done = await fixedOnBranch(branch);
      todo = todo.filter((finding) => !done.has(finding.fingerprint));
      alreadyOnBranch = options.findings.length - todo.length;
      options.onEvent?.({ type: 'resumed', alreadyOnBranch });
      // Earlier commits may have fixed more than they name, so the branch is scanned once as it is now.
      if ((await commitsOnBranch(branch)) > 0) {
        const scanners = options.sources.filter((source) => 'scanner' in source);
        const now = await rescan(branch.tree, scanners);
        state.baseline.accept(now.findings, scanners.map((source) => ('scanner' in source ? source.scanner : '')), 'an earlier commit on the branch');
      }
    }
    for (const [index, finding] of todo.entries()) {
      if (options.abortSignal?.aborted || state.stoppedAtCap) {
        state.results.push({ ...resultBase(finding, options.model?.spec.id ?? 'none', branch.name), status: 'not_tried', durationMs: 0 });
        continue;
      }
      state.remaining = todo.length - index - 1;
      options.onEvent?.({ type: 'start', finding, index, total: todo.length });
      const result = await fixOne(finding, state, options);
      state.results.push(result);
      options.onEvent?.({ type: 'done', result });
    }
  } finally {
    ({ kept } = await closeFixBranch(branch));
  }
  if (!kept) for (const result of state.results) result.branch = null;
  return {
    branch: kept ? branch.name : null,
    results: state.results,
    interrupted: options.abortSignal?.aborted ?? false,
    stoppedAtCap: state.stoppedAtCap,
    alreadyOnBranch,
  };
}

/** What `fixOne` builds a result from, as the fix goes. */
interface Progress {
  attempt?: FixAttempt | undefined;
  verification: Verification | null;
  summary: string | null;
  notes: string[];
  changedFiles: string[];
  model: string;
}

async function fixOne(finding: LocalFinding, state: RunState, options: RunFixesOptions): Promise<FixResult> {
  const started = Date.now();
  const { branch, baseline } = state;
  const refusal = fixRefusal(finding, options.protectedPaths);
  if (refusal) return { ...resultBase(finding, options.model?.spec.id ?? 'none', branch.name), status: 'skipped', error: refusal, durationMs: 0 };

  const earlierFix = baseline.resolvedBy(finding);
  if (earlierFix) {
    return {
      ...resultBase(finding, 'none', branch.name),
      status: 'fixed',
      commit: /^[0-9a-f]{40,64}$/.test(earlierFix) ? earlierFix : null,
      summary: `The scanners stopped reporting it after ${/^[0-9a-f]{7}/.test(earlierFix) ? `commit ${earlierFix.slice(0, 7)}` : earlierFix}, so it needed no change of its own.`,
      durationMs: 0,
    };
  }

  const progress: Progress = { verification: null, summary: null, notes: [], changedFiles: [], model: options.model?.spec.id ?? 'none' };
  const finish = async (status: FixStatus, extra: Partial<FixResult> = {}): Promise<FixResult> => {
    if (extra.commit == null) await discardChanges(branch);
    const attempt = progress.attempt;
    return {
      ...resultBase(finding, progress.model, branch.name),
      status,
      summary: attempt?.submission?.summary ?? progress.summary,
      notes: [...progress.notes, ...(attempt?.submission?.notes ?? [])],
      changedFiles: progress.changedFiles,
      verification: progress.verification,
      steps: attempt?.steps ?? 0,
      inputTokens: attempt?.inputTokens ?? 0,
      outputTokens: attempt?.outputTokens ?? 0,
      costUsd: attempt?.costUsd ?? 0,
      durationMs: Date.now() - started,
      ...extra,
    };
  };

  try {
    let guidance: string | undefined;
    let dependencyDir: string | undefined;
    if (isDependency(finding)) {
      const plan = await planUpgrade(branch.tree, finding, upgradeVersion(finding, options.findings));
      if (plan.kind === 'unsupported') return finish('skipped', { error: plan.reason });
      if (plan.kind === 'command') {
        const upgraded = await upgradeWithTool(finding, plan, state, options, progress);
        if (upgraded.done) return finish(upgraded.status, upgraded.extra);
        // The package manager refused, such as a version the manifest does not allow: a model may change the manifest.
        guidance = `${upgraded.guidance}\n\nMinotaur tried the package manager first, and it refused: ${upgraded.error}`;
        dependencyDir = plan.dir;
        progress.notes = [];
        await discardChanges(branch);
      } else {
        guidance = plan.guidance;
        dependencyDir = plan.dir;
      }
    }
    return await fixWithModel(finding, state, options, progress, finish, { guidance, dependencyDir });
  } catch (error) {
    return finish('failed', { error: (error as Error).message });
  }
}

type Finish = (status: FixStatus, extra?: Partial<FixResult>) => Promise<FixResult>;

/** The package manager's upgrade, verified. `done: false` hands the finding to the model. */
async function upgradeWithTool(
  finding: LocalFinding,
  plan: Extract<UpgradePlan, { kind: 'command' }>,
  state: RunState,
  options: RunFixesOptions,
  progress: Progress,
): Promise<{ done: true; status: FixStatus; extra: Partial<FixResult> } | { done: false; error: string; guidance: string }> {
  const description = `${plan.manager}: ${plan.name} to ${plan.version}${plan.direct ? '' : ' with an override'}`;
  options.onEvent?.({ type: 'upgrade', finding, description });
  progress.model = plan.manager;
  progress.summary = `Upgraded ${plan.name} to ${plan.version} with ${plan.manager}${plan.direct ? '' : ', as an override because it is not a direct dependency'}.`;
  const guidance = [
    `Upgrade ${plan.name} to ${plan.version} or later by changing its version where the project declares it.`,
    `Do not edit lockfiles: they are read-only. When you submit, Minotaur updates them with ${plan.manager}.`,
  ].join('\n');
  try {
    progress.notes = await applyUpgrade(state.branch.tree, plan, options.runTool);
  } catch (error) {
    if (error instanceof ToolMissingError) return { done: true, status: 'failed', extra: { error: error.message } };
    if (error instanceof UpgradeError && plan.manager === 'cargo') return { done: false, error: error.message, guidance };
    if (error instanceof UpgradeError) return { done: true, status: 'failed', extra: { error: error.message } };
    throw error;
  }
  const verdict = await verifyAndCommit(finding, state, options, progress, { summary: progress.summary, notes: progress.notes, outcome: 'fixed' });
  return { done: true, ...verdict };
}

async function fixWithModel(
  finding: LocalFinding,
  state: RunState,
  options: RunFixesOptions,
  progress: Progress,
  finish: Finish,
  extra: { guidance?: string | undefined; dependencyDir?: string | undefined },
): Promise<FixResult> {
  const { branch } = state;
  const { model, limits } = options;
  if (!model) return finish('failed', { error: `this fix needs a model. ${options.noModel ?? 'No model is configured.'}` });
  const workspace = await Workspace.open(branch.tree, {
    denied: [...options.protectedPaths],
    writable: { readOnly: [CONFIG_FILE, `${DECISIONS_FILE.split('/')[0]}/`], readOnlyNames: LOCKFILES },
  });
  progress.model = model.spec.id;
  const session = new FixSession(toSubject(finding), workspace, {
    model: model.model,
    pricing: model.pricing,
    budget: new SpendBudget(limits.maxUsd, limits.maxTokens),
    pauseAt: state.batch,
    maxSteps: limits.maxSteps,
    abortSignal: options.abortSignal,
    effort: model.effort,
    forcedToolChoice: model.capabilities.forcedToolChoice,
    promptCaching: model.capabilities.promptCaching,
    guidance: extra.guidance,
    earlier: options.earlier?.get(finding.fingerprint),
    onStep: (step) => options.onEvent?.({ type: 'step', finding, progress: step, maxSteps: limits.maxSteps }),
  });

  for (let attempts = 1; ; attempts += 1) {
    progress.attempt = attempts === 1 ? await session.start() : await session.retry(retryPrompt(progress.verification!));
    while (progress.attempt.status === 'paused') {
      if (!(await checkpoint(finding, state, options))) {
        state.stoppedAtCap = true;
        return finish('stopped_at_cap', { attempts, error: 'stopped at the batch cap' });
      }
      progress.attempt = await session.resume();
    }
    const attempt = progress.attempt;
    const counted = { attempts };
    if (attempt.status === 'skipped_budget') return finish('stopped_at_limit', { ...counted, error: attempt.error ?? 'the limit ran out' });
    if (attempt.status === 'failed') return finish('failed', { ...counted, error: attempt.error ?? 'the model failed' });
    if (attempt.submission?.outcome === 'gave_up') return finish('gave_up', counted);

    if (extra.dependencyDir !== undefined && finding.package?.name) {
      try {
        const command = await relock(branch.tree, extra.dependencyDir, finding.package.name, options.runTool);
        if (command) options.onEvent?.({ type: 'upgrade', finding, description: `updating the lockfile: ${command}` });
      } catch (error) {
        if (error instanceof ToolMissingError || !(error instanceof UpgradeError)) throw error;
        const problem = `the lockfile could not be updated after your change: ${error.message}`;
        progress.verification = { scanners: [], passed: false, problems: [problem] };
        if (attempts >= MAX_ATTEMPTS || !session.canRetry()) return finish('failed', { ...counted, error: problem });
        options.onEvent?.({ type: 'retry', finding, problems: progress.verification.problems });
        continue;
      }
    }

    const verdict = await verifyAndCommit(finding, state, options, progress, attempt.submission!);
    if (verdict.status !== 'failed' || verdict.extra.commit || attempts >= MAX_ATTEMPTS || !session.canRetry() || options.abortSignal?.aborted) {
      return finish(verdict.status, { ...counted, ...verdict.extra });
    }
    options.onEvent?.({ type: 'retry', finding, problems: progress.verification?.problems ?? [] });
  }
}

/** Asks whether to go on past the batch's cap, and raises it by one cap when the answer is yes. */
async function checkpoint(finding: LocalFinding, state: RunState, options: RunFixesOptions): Promise<boolean> {
  const batch = state.batch!;
  if (!options.onCheckpoint || options.abortSignal?.aborted) return false;
  const go = await options.onCheckpoint({
    spentUsd: batch.spentUsd,
    capUsd: batch.limitUsd,
    current: finding,
    results: state.results,
    remaining: state.remaining,
  });
  if (go) batch.extend(options.maxTotalUsd!);
  return go;
}

/** Rescans the change and commits it when it passes. Leaves the edits in place when it does not. */
async function verifyAndCommit(
  finding: LocalFinding,
  state: RunState,
  options: RunFixesOptions,
  progress: Progress,
  submission: FixSubmission,
): Promise<{ status: FixStatus; extra: Partial<FixResult> }> {
  const { branch, baseline } = state;
  const changed = await changedPaths(branch);
  progress.changedFiles = changed;
  if (changed.length === 0) {
    const problem = 'nothing changed: the files are the same as in the last commit';
    progress.verification = { scanners: [], passed: false, problems: [problem] };
    return { status: 'failed', extra: { error: problem } };
  }

  const sources = rescanSources(finding, options.sources);
  const diff = await uncommittedDiff(branch, changed);
  options.onEvent?.({ type: 'verify', finding, scanners: sources.map((source) => ('scanner' in source ? source.scanner : source.report)) });
  const checked = await verifyFix({ finding, tree: branch.tree, sources, changedFiles: changed, diff, baseline, rescan: state.rescan });
  const verification = checked.verification;
  progress.verification = verification;

  if (sources.length === 0 && verification.problems.length === 0) {
    if (!options.allowUnverified) {
      return { status: 'unverified', extra: { error: 'no scanner that reported this finding can run again; --allow-unverified commits it anyway' } };
    }
    const commit = await commitFix(branch, changed, commitMessage(finding, submission, progress.model, false));
    return { status: 'committed_unverified', extra: { commit } };
  }
  if (!verification.passed) return { status: 'failed', extra: { error: verification.problems.join('; ') } };
  const commit = await commitFix(branch, changed, commitMessage(finding, submission, progress.model, true));
  baseline.accept(checked.after, verification.scanners, commit);
  return { status: 'fixed', extra: { commit } };
}

function retryPrompt(verification: Verification): string {
  const ran = verification.scanners.length > 0 ? `${verification.scanners.join(', ')} ran again on your change and found:` : 'Your change did not pass:';
  return [`The fix did not pass. ${ran}`, ...verification.problems.map((problem) => `- ${problem}`), '', 'Your edits are still in the files. Fix the cause, then call submit_fix again.'].join('\n');
}

function commitMessage(finding: LocalFinding, submission: FixSubmission, by: string, verified: boolean): string {
  const title = finding.title.length > 60 ? `${finding.title.slice(0, 57)}...` : finding.title;
  const scope = isDependency(finding) ? 'deps' : 'security';
  return [
    `fix(${scope}): ${title}`,
    '',
    submission.summary,
    ...(submission.notes.length > 0 ? ['', 'For the reviewer:', ...submission.notes.map((note) => `- ${note}`)] : []),
    ...(verified ? [] : ['', 'Not verified: no scanner that reported this finding could run again.']),
    '',
    `Minotaur-Finding: ${finding.fingerprint}`,
    `Minotaur-Fixed-By: ${by}`,
  ].join('\n');
}

function resultBase(finding: LocalFinding, model: string, branch: string): Omit<FixResult, 'status' | 'durationMs'> {
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
    model,
    promptVersion: FIX_PROMPT_VERSION,
    steps: 0,
    inputTokens: 0,
    outputTokens: 0,
    costUsd: 0,
    error: null,
  };
}
