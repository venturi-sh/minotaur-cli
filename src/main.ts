/**
 * The `minotaur` command.
 *
 *   minotaur scan [PATH]            list findings from the configured sources
 *   minotaur triage ID [PATH]       decide whether one finding is exploitable
 *   minotaur mark ID STATE [PATH]   record a person's decision about a finding
 *
 * Results go to stdout and everything else to stderr, so `--json` output can
 * be piped or redirected without progress mixed into it.
 */

import { realpath, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { FOCUS_LEVELS, SEVERITIES, focusRank, severityRank, type Focus, type Severity } from './core/index.js';

import { advisoryCacheDir, lookupAdvisories, rankFindings } from './advisories.js';

import { loadConfig, sourceFromFlag, type Config, type SourceConfig } from './config.js';
import { browse, type Loaded } from './interactive/app.js';
import type { ScanReporter } from './interactive/loading.js';
import type { ModelStatus } from './interactive/state.js';
import { resolveModel, type ResolvedModel } from './model.js';
import {
  COLOR,
  PLAIN,
  readFindingsFile,
  renderFindingTable,
  renderSourceOutcome,
  renderSummary,
  renderTriageResult,
  toFindingsFile,
} from './output.js';
import { cacheDir } from './managed.js';
import { describeAge, readCachedScan, scanCacheDir, scanKey, writeCachedScan } from './scan-cache.js';
import {
  NATIVE_SCANNERS,
  collectFindings,
  defaultSources,
  resolveFinding,
  secretPaths,
  type CollectResult,
  type LocalFinding,
} from './sources.js';
import {
  DEFAULT_MAX_STEPS,
  DEFAULT_MAX_USD,
  describeLimits,
  describeModel,
  earlierFrom,
  identityOf,
  loadEarlierCheck,
  refusalFor,
  runTriage,
  type RunTriageOptions,
  type TriageLimits,
  type TriageResult,
} from './triage.js';
import { checkCacheDir, loadChecks, saveCheck, type CachedCheck, type CheckScope } from './check-cache.js';
import {
  DECISIONS_FILE,
  DECISION_LABEL,
  DECISION_STATES,
  applyDecisions,
  decider,
  isClosed,
  liftProtected,
  loadDecisions,
  parseDecisionState,
  saveDecision,
  type Decision,
} from './decisions.js';
import { CommitError, describeCommit, resolveTarget, stillCommitted, targetNotes, treeFor, type Target } from './commit.js';

const VERSION = '0.1.0';

const HELP = `minotaur ${VERSION}

Usage:
  minotaur [options]                      Browse the findings here and check them one at a time
  minotaur scan [PATH] [options]          List findings from the configured sources
  minotaur triage ID [PATH] [options]     Decide whether one finding is exploitable
  minotaur mark ID DECISION [PATH]        Record your own decision about a finding:
                                          false-positive, accepted-risk, fixed, confirmed,
                                          or open to remove it

Sources (all commands):
  --commit REF           The commit to look at: a hash, branch or tag (default HEAD).
                         On HEAD with no uncommitted changes this is your working tree;
                         otherwise a clean copy of the commit, so uncommitted changes
                         and installed dependencies are left out.
  --source NAME|FILE     A scanner (${NATIVE_SCANNERS.join(', ')}) or a report file
                         (SARIF, or a supported scanner's JSON). Repeatable. Overrides
                         .minotaur.yml. Default: trivy, opengrep, and any other installed
                         scanner. Trivy and Opengrep are downloaded when missing.
  --include-ignored      Also list findings in files git ignores, such as dependencies,
                         build output and caches
  --rescan               Scan again even when nothing changed since the last scan.
                         A scan of a commit is reused for up to 24 hours while the
                         sources and scanners stay the same.

scan:
  --min-severity LEVEL   Hide findings below this severity (${SEVERITIES.join(', ')})
  --focus LEVEL          Show only findings rated at least this likely to matter:
                         likely, maybe (the default) or noise. Style and correctness
                         rules and code in tests are rated noise; see "Focus" in the README.
  --all                  Show every finding, the noise too (the same as --focus noise)
  --json                 Write the findings as JSON, which "triage --findings" accepts

triage:
  --findings FILE        Read findings from "scan --json" output instead of re-running sources
  --model PROVIDER:MODEL anthropic:claude-opus-5-5, or openai-compatible:MODEL for a server you run
  --base-url URL         Address of an OpenAI-compatible server, e.g. http://localhost:11434/v1
  --effort LEVEL         Anthropic effort: low, medium, high, xhigh, max (default medium)
  --max-steps N          Model calls allowed (default ${DEFAULT_MAX_STEPS})
  --max-usd N            Spend cap in US dollars (default ${DEFAULT_MAX_USD})
  --max-tokens N         Token cap, useful for a local model that costs nothing per token
  --continue-from FILE   Dig deeper from an earlier "triage --json" result
  --recheck              Ask the model again even when an earlier check still applies.
                         A check is reused on the commit it was made on, and on a later
                         commit while every file it read and search it ran stay the same.
  --json                 Write the result as JSON

mark:
  --reason TEXT          Why, for the people who review the decision
  --findings FILE        Find the id in "scan --json" output instead of scanning

  Decisions go to ${DECISIONS_FILE}, meant to be committed. False positives,
  accepted risks and fixed findings are hidden unless --all. A secret marked a
  false positive no longer keeps its file away from checks.

Environment:
  ANTHROPIC_API_KEY, MINOTAUR_API_KEY, MINOTAUR_MODEL, MINOTAUR_BASE_URL,
  MINOTAUR_CACHE_DIR (where downloaded scanners, the last scans, checks and copies
  of commits are kept)
`;

export class UsageError extends Error {}

const OPTIONS = {
  commit: { type: 'string' },
  source: { type: 'string', multiple: true },
  json: { type: 'boolean' },
  'include-ignored': { type: 'boolean' },
  rescan: { type: 'boolean' },
  recheck: { type: 'boolean' },
  'min-severity': { type: 'string' },
  focus: { type: 'string' },
  all: { type: 'boolean' },
  findings: { type: 'string' },
  model: { type: 'string' },
  'base-url': { type: 'string' },
  effort: { type: 'string' },
  'max-steps': { type: 'string' },
  'max-usd': { type: 'string' },
  'max-tokens': { type: 'string' },
  'continue-from': { type: 'string' },
  reason: { type: 'string' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'v' },
} as const;

type Values = ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true }>>['values'];

export async function main(argv: readonly string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({ args: [...argv], options: OPTIONS, allowPositionals: true });
  } catch (error) {
    throw new UsageError((error as Error).message);
  }
  const { values, positionals } = parsed;
  if (values.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  const [command, ...rest] = positionals;
  if (!command && !values.help && process.stdin.isTTY && process.stdout.isTTY) {
    return interactive(await repoRoot(undefined), values);
  }
  if (values.help || !command) {
    process.stdout.write(HELP);
    return command || values.help ? 0 : 2;
  }

  if (command === 'scan') {
    if (rest.length > 1) throw new UsageError('scan takes at most one path');
    return scan(await repoRoot(rest[0]), values);
  }
  if (command === 'triage') {
    const [id, path, ...extra] = rest;
    if (!id) throw new UsageError('triage needs a finding id; run "minotaur scan" to list them');
    if (extra.length > 0) throw new UsageError('triage takes a finding id and at most one path');
    return triage(id, await repoRoot(path), values);
  }
  if (command === 'mark') {
    const [id, state, path, ...extra] = rest;
    if (!id || !state) throw new UsageError('mark needs a finding id and a decision, such as "minotaur mark 3f9a1c2e false-positive"');
    if (extra.length > 0) throw new UsageError('mark takes a finding id, a decision and at most one path');
    return mark(id, state, await repoRoot(path), values);
  }
  throw new UsageError(`unknown command "${command}"; expected scan, triage or mark`);
}

/** Where the command was typed. Package scripts run from the package, and record the real place in INIT_CWD. */
function invocationDir(): string {
  return process.env['INIT_CWD'] ?? process.cwd();
}

function fromInvocation(path: string): string {
  return resolve(invocationDir(), path);
}

async function repoRoot(path: string | undefined): Promise<string> {
  const root = await realpath(fromInvocation(path ?? '.')).catch(() => {
    throw new UsageError(`${path} does not exist`);
  });
  if (!(await stat(root)).isDirectory()) throw new UsageError(`${path} is not a directory`);
  return root;
}

async function target(root: string, ref: string | undefined): Promise<Target> {
  try {
    return await resolveTarget(root, ref);
  } catch (error) {
    if (error instanceof CommitError) throw new UsageError(error.message);
    throw error;
  }
}

/** "/repo at commit 3f9a1c2 (Fix the login redirect)", or just the directory without a commit. */
function describeTarget(target: Target): string {
  return target.commit ? `${target.repo} at ${describeCommit(target.commit)}` : target.repo;
}

/** Says which commit a `scan` or `triage` looks at, before anything else. */
function announce(target: Target): void {
  info(`Looking at ${describeTarget(target)}`);
  for (const note of targetNotes(target)) info(note);
}

async function sourcesFor(target: Target, tree: string, values: Values, config: Config): Promise<SourceConfig[]> {
  if (values.source?.length) {
    try {
      return values.source.map((value) => {
        const source = sourceFromFlag(value, NATIVE_SCANNERS);
        return 'report' in source ? { ...source, report: fromInvocation(source.report) } : source;
      });
    } catch (error) {
      throw new UsageError((error as Error).message);
    }
  }
  // A report is produced outside git, so a relative path names a file beside the configuration, not in the commit.
  if (config.sources?.length) {
    return config.sources.map((source) => ('report' in source ? { ...source, report: resolve(target.repo, source.report) } : source));
  }
  const sources = await defaultSources(tree);
  if (sources.length === 0) {
    throw new UsageError(`${describeTarget(target)} has no files the default scanners look at; pass a report with --source FILE`);
  }
  return sources;
}

/** Progress as plain lines on stderr, for `scan` and `triage`. */
function stderrReporter(): ScanReporter {
  return {
    step: () => {},
    sources: (names) => info(`Scanning with ${names.join(', ')}`),
    start: () => {},
    done: (outcome) => info(renderSourceOutcome(outcome)),
    note: info,
  };
}

interface Gathered extends CollectResult {
  /** The directory scanned, which checks read too. */
  tree: string;
  cachedAt?: number;
}

/**
 * Rates and orders the findings. Done after every scan, cached or not, since
 * the exploitation evidence moves daily and the focus settings may have changed.
 */
async function ranked(collected: Gathered, config: Config, reporter: ScanReporter): Promise<Gathered> {
  const ids = collected.findings.flatMap((finding) => (finding.kind === 'sca' ? finding.vulnerabilityIds : []));
  if (ids.length > 0) reporter.step('Checking which dependencies are being exploited');
  const advisories = await lookupAdvisories(advisoryCacheDir(cacheDir()), ids);
  if (advisories.note) reporter.note(advisories.note);
  return { ...collected, findings: rankFindings(collected.findings, advisories.risks, config.focus) };
}

async function gather(target: Target, values: Values, config: Config, reporter: ScanReporter = stderrReporter()): Promise<Gathered> {
  return decided(await rated(target, values, config, reporter), await loadDecisions(target.repo));
}

/** Scanned and rated, before the decisions people made. */
async function rated(target: Target, values: Values, config: Config, reporter: ScanReporter): Promise<Gathered> {
  return ranked(await scanned(target, values, config, reporter), config, reporter);
}

/** With the decisions from the working tree's decisions file, which may not be committed yet. */
function decided(collected: Gathered, decisions: ReadonlyMap<string, Decision>): Gathered {
  const findings = applyDecisions(collected.findings, decisions);
  return { ...collected, findings, protectedPaths: [...liftProtected(collected.protectedPaths, findings)].sort() };
}

async function scanned(target: Target, values: Values, config: Config, reporter: ScanReporter): Promise<Gathered> {
  if (target.copy && target.commit) reporter.step(`Copying ${target.commit.short} out of git`);
  const tree = await treeFor(target, cacheDir());
  reporter.step('Working out which scanners apply');
  const sources = await sourcesFor(target, tree, values, config);
  const includeIgnored = values['include-ignored'] ?? false;
  const cache = scanCacheDir(cacheDir());
  reporter.step('Looking for an earlier scan of this commit');
  const key = await scanKey(target, tree, sources, includeIgnored).catch(() => null);
  if (key && !values.rescan) {
    const cached = await readCachedScan(cache, target.repo, key);
    if (cached) {
      reporter.note(`Using the scan of this commit from ${describeAge(Date.now() - cached.createdAt)} (--rescan runs it again)`);
      return { ...cached.result, tree, cachedAt: cached.createdAt };
    }
  }

  reporter.sources(sources.map((source) => ('scanner' in source ? source.scanner : source.report)));
  const collected = await collectFindings(tree, sources, {
    onStart: reporter.start,
    onSource: reporter.done,
    managed: { onDownload: reporter.note },
    includeIgnored,
    reportRoot: target.repo,
  });
  if (key) {
    await writeCachedScan(cache, target.repo, key, collected).catch((error: Error) => reporter.note(`Could not keep the scan for next time: ${error.message}`));
  }
  return { ...collected, tree };
}

function scopeOf(target: Target): CheckScope {
  return { repo: target.repo, commit: target.commit?.sha ?? null, copy: target.copy };
}

/** Keeps finished checks for this commit, unless the working tree moved away from it while the check ran. */
function keeper(target: Target, model: ResolvedModel): RunTriageOptions['keep'] {
  const dir = checkCacheDir(cacheDir());
  return async (result, inputs) => {
    if (target.commit && !(await stillCommitted(target))) return;
    await saveCheck(dir, scopeOf(target), result, inputs, identityOf(model));
  };
}

async function scan(root: string, values: Values): Promise<number> {
  const { config } = await loadConfig(root);
  const minimum = parseSeverity(values['min-severity']);
  const where = await target(root, values.commit);
  announce(where);
  const focus = parseFocus(values.focus, values.all ?? false);
  const collected = await gather(where, values, config);
  const severe = minimum
    ? collected.findings.filter((finding) => severityRank(finding.severity) >= severityRank(minimum))
    : collected.findings;
  // JSON keeps the noise unless asked otherwise: a script or an agent filters on the focus field itself.
  const floor = focus ?? (values.json ? 'noise' : 'maybe');
  // Marked false positive, accepted or fixed: shown only when everything is asked for.
  const open = floor === 'noise' ? severe : severe.filter((finding) => !isClosed(finding));
  const closed = severe.length - open.length;
  const shown = open.filter((finding) => focusRank(finding.focus ?? 'maybe') >= focusRank(floor));
  const noise = open.filter((finding) => finding.focus === 'noise').length - shown.filter((finding) => finding.focus === 'noise').length;

  if (values.json) {
    const file = toFindingsFile(root, where.commit?.sha ?? null, shown, collected.sources, collected.protectedPaths);
    process.stdout.write(`${JSON.stringify(file, null, 2)}\n`);
    return 0;
  }
  const style = process.stdout.isTTY ? COLOR : PLAIN;
  process.stdout.write(`\n${renderFindingTable(shown, style, process.stdout.columns ?? 120)}\n\n`);
  const belowFocus = open.length - shown.length - noise;
  const focusNotes = [
    ...(closed > 0 ? [`${closed} marked false positive, accepted risk or fixed (--all shows them)`] : []),
    ...(noise > 0 ? [`${noise} hidden as likely noise (--all shows them)`] : []),
    ...(belowFocus > 0 ? [`${belowFocus} below --focus ${floor} not shown`] : []),
  ];
  process.stdout.write(`${renderSummary(shown, collected.findings.length - severe.length, collected.ignored, focusNotes)}\n`);
  if (where.commit) process.stdout.write(style.dim(`On ${describeCommit(where.commit)}.\n`));
  if (shown.some((finding) => finding.kind === 'sca' || finding.kind === 'sast')) {
    process.stdout.write(style.dim('Run "minotaur triage ID" to check whether a finding is exploitable.\n'));
  }
  return 0;
}

/** `minotaur` on its own: scan, then browse the findings and check them one at a time. */
async function interactive(root: string, values: Values): Promise<number> {
  const { config } = await loadConfig(root);
  const limits = triageLimits(values, config);
  let model: ResolvedModel | null = null;
  let status: ModelStatus;
  try {
    model = resolveModel(modelFlags(values), config, process.env);
    status = { ok: true, destination: describeModel(model), limits: describeLimits(model, limits) };
  } catch (error) {
    // Browsing works without a model; the view explains how to set one up when a check is asked for.
    status = { ok: false, error: (error as Error).message };
  }

  let where = await target(root, values.commit);
  const checkCache = checkCacheDir(cacheDir());
  let protectedPaths: ReadonlySet<string> = new Set();
  let tree = root;
  // The last scan before decisions, so a new decision is applied to it without scanning again.
  let undecided: Gathered | null = null;
  // Every check loaded from the cache, across rescans, so the summary lists only the ones run now.
  const reusedResults = new Set<TriageResult>();
  const load = async (reporter: ScanReporter, { rescan }: { rescan: boolean }): Promise<Loaded> => {
    // HEAD or the working tree may have moved since the view opened.
    if (rescan) where = await target(root, values.commit);
    undecided = await rated(where, rescan ? { ...values, rescan: true } : values, config, reporter);
    const collected = decided(undecided, await loadDecisions(root));
    protectedPaths = new Set(collected.protectedPaths);
    tree = collected.tree;
    reporter.step('Looking for earlier checks that still apply');
    const reused = model
      ? await loadChecks(checkCache, scopeOf(where), tree, collected.findings, identityOf(model), protectedPaths)
      : new Map<string, CachedCheck>();
    const earlierResults = new Map([...reused].map(([fingerprint, check]) => [fingerprint, check.result]));
    for (const result of earlierResults.values()) reusedResults.add(result);
    const notes = [
      ...targetNotes(where),
      ...(collected.cachedAt ? [`From the scan ${describeAge(Date.now() - collected.cachedAt)}; press r to scan again.`] : []),
      ...(reused.size > 0 ? [`${reused.size} earlier check${reused.size === 1 ? '' : 's'} still appl${reused.size === 1 ? 'ies' : 'y'}.`] : []),
    ];
    return {
      findings: collected.findings,
      ignored: collected.ignored,
      protectedPaths,
      results: earlierResults,
      message: notes.length > 0 ? notes.join(' ') : null,
      commit: commitLabel(where),
    };
  };

  const session = await browse({
    root,
    commit: commitLabel(where),
    load,
    model: status,
    maxSteps: limits.maxSteps,
    check: (finding, options) => {
      if (!model) return Promise.reject(new Error('no model is configured'));
      const earlier = options.continueFrom
        ? { check: earlierFrom(options.continueFrom, finding, 'the earlier check'), from: 'the earlier check' }
        : undefined;
      return runTriage({
        root: tree,
        finding,
        protectedPaths,
        model,
        limits,
        earlier,
        keep: keeper(where, model),
        onStep: options.onStep,
        abortSignal: options.signal,
      });
    },
    decide: async (finding, state, reason) => {
      const decisions = await saveDecision(root, finding, state, { reason, by: await decider(root) });
      const collected = decided(undecided!, decisions);
      protectedPaths = new Set(collected.protectedPaths);
      return { findings: collected.findings, protectedPaths, file: DECISIONS_FILE };
    },
    input: process.stdin,
    output: process.stdout,
  });

  const results = session.filter((result) => !reusedResults.has(result));
  if (results.length > 0) {
    const cost = results.reduce((sum, result) => sum + result.costUsd, 0);
    process.stdout.write(`${results.length} check${results.length === 1 ? '' : 's'} this session${cost > 0 ? `, $${cost.toFixed(2)}` : ''}:\n`);
    for (const result of results) {
      const answer = result.status === 'succeeded' ? (result.exploitability ?? 'no answer') : 'no answer';
      process.stdout.write(`  ${result.finding.id}  ${answer.replace('_', ' ')}  ${result.finding.title}\n`);
    }
  }
  return 0;
}

function commitLabel(where: Target): string | null {
  return where.commit ? `${where.commit.short} ${where.commit.subject}`.trim() : null;
}

function modelFlags(values: Values) {
  return { model: values.model, baseUrl: values['base-url'], effort: values.effort };
}

function triageLimits(values: Values, config: Config): TriageLimits {
  const limits = {
    maxSteps: positiveNumber(values['max-steps'], '--max-steps') ?? config.triage?.maxSteps ?? DEFAULT_MAX_STEPS,
    maxUsd: positiveNumber(values['max-usd'], '--max-usd') ?? config.triage?.maxUsd ?? DEFAULT_MAX_USD,
    maxTokens: positiveNumber(values['max-tokens'], '--max-tokens') ?? config.triage?.maxTokens,
  };
  if (!Number.isInteger(limits.maxSteps) || limits.maxSteps < 2) throw new UsageError('--max-steps must be a whole number of at least 2');
  return limits;
}

async function triage(id: string, root: string, values: Values): Promise<number> {
  const { config } = await loadConfig(root);
  const model = resolveModel(modelFlags(values), config, process.env);
  const limits = triageLimits(values, config);

  const file = values.findings ? await readFindingsFile(fromInvocation(values.findings)) : null;
  // Findings from "scan --json" belong to the commit they were scanned on.
  const where = await target(root, values.commit ?? file?.commit ?? undefined);
  announce(where);
  if (file?.commit && where.commit && file.commit !== where.commit.sha) {
    info(`The findings file is from commit ${file.commit.slice(0, 7)}, so its line numbers may not match ${where.commit.short}.`);
  }
  const gathered = file ? { ...file, tree: await treeFor(where, cacheDir()) } : await gather(where, values, config);
  const { protectedPaths: listed, tree } = gathered;
  // Decisions may have changed since a findings file was written, so they are read again.
  const findings = file ? applyDecisions(file.findings, await loadDecisions(root)) : gathered.findings;
  const protectedPaths = liftProtected([...listed, ...secretPaths(findings)], findings);
  const finding = resolveFinding(findings, id);
  const refusal = refusalFor(finding, protectedPaths);
  if (refusal) throw new Error(refusal);
  const continueFrom = values['continue-from'];
  const earlier = continueFrom
    ? { check: await loadEarlierCheck(fromInvocation(continueFrom), finding), from: continueFrom }
    : undefined;

  if (!earlier && !values.recheck) {
    const checks = await loadChecks(checkCacheDir(cacheDir()), scopeOf(where), tree, [finding], identityOf(model), protectedPaths);
    const reused = checks.get(finding.fingerprint);
    if (reused) {
      const age = describeAge(Date.now() - reused.createdAt);
      const why = reused.carriedFrom
        ? `It was made on ${reused.carriedFrom}, and the files it read have not changed since`
        : 'It was made on this commit';
      info(`\nReusing the check of ${finding.id} from ${age}. ${why}, so nothing was sent to the model (--recheck runs it again).`);
      return writeTriageResult(reused.result, values);
    }
  }

  info(`\nChecking ${finding.id}: ${finding.title}`);
  info(`Code is sent to ${describeModel(model)}.`);
  info(`Limits: ${describeLimits(model, limits)}.`);
  if (earlier) info(`Continuing from the earlier check in ${earlier.from}.`);

  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  const seen = new Set<string>();
  try {
    const result = await runTriage({
      root: tree,
      finding,
      protectedPaths,
      model,
      limits,
      earlier,
      keep: keeper(where, model),
      abortSignal: controller.signal,
      onStep: (progress) => {
        for (const input of progress.inputs) {
          if (!seen.has(input.path)) {
            seen.add(input.path);
            info(`  looked at ${input.path}`);
          }
        }
        const tokens = (progress.inputTokens + progress.outputTokens).toLocaleString('en-US');
        const cost = progress.costUsd > 0 ? `, $${progress.costUsd.toFixed(2)}` : '';
        info(`  step ${progress.steps} of at most ${limits.maxSteps}: ${tokens} tokens so far${cost}`);
      },
    });

    return writeTriageResult(result, values);
  } finally {
    process.removeListener('SIGINT', stop);
  }
}

/** `minotaur mark ID STATE`: records what a person decided about a finding. */
async function mark(id: string, stateName: string, root: string, values: Values): Promise<number> {
  const state = parseDecisionState(stateName);
  if (!state) {
    const names = [...DECISION_STATES, 'open'].map((name) => name.replace('_', '-')).join(', ');
    throw new UsageError(`"${stateName}" is not a decision; use one of ${names}`);
  }
  // Undoing a decision on a finding the scan no longer reports needs no scan.
  const recorded = [...(await loadDecisions(root)).values()].filter((decision) => decision.fingerprint.startsWith(id.toLowerCase()));
  let finding: Pick<LocalFinding, 'id' | 'fingerprint' | 'title' | 'location' | 'kind'>;
  if (state === 'open' && recorded.length === 1) {
    const decision = recorded[0]!;
    finding = {
      id: decision.fingerprint.slice(0, 8),
      fingerprint: decision.fingerprint,
      title: decision.title ?? 'finding',
      kind: 'sast',
      ...(decision.path ? { location: { path: decision.path } } : {}),
    };
  } else {
    const { config } = await loadConfig(root);
    const file = values.findings ? await readFindingsFile(fromInvocation(values.findings)) : null;
    let findings: readonly LocalFinding[];
    if (file) {
      findings = file.findings;
    } else {
      const where = await target(root, values.commit);
      announce(where);
      findings = (await gather(where, values, config)).findings;
    }
    finding = resolveFinding(findings, id);
  }

  const reason = values.reason?.trim();
  await saveDecision(root, finding, state, { reason, by: await decider(root) });
  if (state === 'open') {
    process.stdout.write(`${finding.id} is open again; its decision is removed from ${DECISIONS_FILE}.\n`);
    return 0;
  }
  process.stdout.write(`Marked ${finding.id} (${finding.title}) as ${DECISION_LABEL[state]} in ${DECISIONS_FILE}.\n`);
  if (state === 'false_positive' && finding.kind === 'secret' && finding.location) {
    process.stdout.write(`Checks may now read ${finding.location.path} and send it to the model, unless another secret is found in it.\n`);
  }
  if (!reason) info('Add --reason TEXT next time, so reviewers know why.');
  info(`Commit ${DECISIONS_FILE} to share the decision with the team.`);
  return 0;
}

function writeTriageResult(result: TriageResult, values: Values): number {
  if (values.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else process.stdout.write(`\n${renderTriageResult(result, process.stdout.isTTY ? COLOR : PLAIN)}\n`);
  return result.status === 'succeeded' ? 0 : 1;
}

function parseSeverity(value: string | undefined): Severity | undefined {
  if (value === undefined) return undefined;
  if (!(SEVERITIES as readonly string[]).includes(value)) {
    throw new UsageError(`--min-severity must be one of ${SEVERITIES.join(', ')}`);
  }
  return value as Severity;
}

function parseFocus(value: string | undefined, all: boolean): Focus | undefined {
  if (all) {
    if (value !== undefined && value !== 'noise') throw new UsageError('--all and --focus ask for different things; use one');
    return 'noise';
  }
  if (value === undefined) return undefined;
  if (!(FOCUS_LEVELS as readonly string[]).includes(value)) throw new UsageError(`--focus must be one of ${FOCUS_LEVELS.join(', ')}`);
  return value as Focus;
}

function positiveNumber(value: string | undefined, flag: string): number | undefined {
  if (value === undefined) return undefined;
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) throw new UsageError(`${flag} must be a positive number`);
  return number;
}

function info(message: string): void {
  process.stderr.write(`${message}\n`);
}

/** 0 when the command did its job, 1 when it could not, 2 when it was called wrongly. */
export function exitCodeFor(error: unknown): number {
  return error instanceof UsageError ? 2 : 1;
}
