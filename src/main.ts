/**
 * The `minotaur` command.
 *
 *   minotaur scan [PATH]            list findings from the configured sources
 *   minotaur triage ID [PATH]       decide whether one finding is exploitable
 *   minotaur brief ID [PATH]        the commit, the files to read, and how to answer
 *   minotaur verdict ID [PATH]      store an answer an agent worked out itself
 *   minotaur fix ID... [PATH]       fix findings on a new branch, checked by a rescan
 *   minotaur mark ID STATE [PATH]   record a person's decision about a finding
 *   minotaur config [PATH]          choose scanners and a model, and write .minotaur.yml
 *   minotaur auth login [PROVIDER]  sign in to Anthropic or OpenAI, when no API key is set
 *
 * Results go to stdout and everything else to stderr, so `--json` output can
 * be piped or redirected without progress mixed into it.
 */

import { readFile, realpath, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

import packageJson from '../package.json' with { type: 'json' };

import { FOCUS_LEVELS, SEVERITIES, focusRank, severityRank, type Focus, type Severity } from './core/index.js';

import { advisoryCacheDir, lookupAdvisories, rankFindings } from './advisories.js';

import { chooseAuthProvider, consoleLogin, consoleLogout, formatAuthStatus, openAILogin, openAILogout, parseAuthProvider } from './auth.js';
import { configureRepository } from './configure-ui.js';
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
  renderFixRun,
  renderSourceOutcome,
  renderSummary,
  renderTriageResult,
  toFindingsFile,
  withChecks,
} from './output.js';
import { cacheDir } from './managed.js';
import { installedScanners } from './scanners/index.js';
import { describeAge, matchCachedScan, readCachedScan, scanCacheDir, scanKey, writeCachedScan } from './scan-cache.js';
import {
  NATIVE_SCANNERS,
  collectFindings,
  defaultSources,
  scanCovers,
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
  toSubject,
  type RunTriageOptions,
  type TriageLimits,
  type TriageResult,
} from './triage.js';
import { checkCacheDir, loadChecks, saveCheck, type CachedCheck, type CheckIdentity, type CheckScope } from './check-cache.js';
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
import { agentIdentity, buildBrief, reviewVerdict } from './review.js';
import { agentFixInstructions, renderFixRequest, type EarlierCheck } from './agent/index.js';
import { protectedReason } from './core/index.js';
import { planUpgrade } from './upgrade.js';
import { runFixes, upgradeVersion, verifyAgentFix, type Checkpoint, type FixEvent, type FixResult } from './fix.js';
import {
  closeFixBranch,
  DEFAULT_BRANCH,
  discardChanges,
  commitDiff,
  existingFixBranch,
  fixedOnBranch,
  openFixBranch,
  pendingFixes,
  readClaim,
  uncommittedDiff,
  workingCopy,
  WorktreeError,
  writeClaim,
} from './worktree.js';
import type { FixView } from './interactive/state.js';

// From package.json, so a release cannot report the wrong version.
const VERSION = packageJson.version;

/** What a run of several fixes may spend before Minotaur asks whether to go on. */
const DEFAULT_MAX_TOTAL_USD = 10;

const HELP = `minotaur ${VERSION}

Usage:
  minotaur [PATH] [options]               Browse the findings in PATH, or here if omitted
  minotaur scan [PATH] [options]          List findings from the configured sources
  minotaur triage ID [PATH] [options]     Ask a model whether one finding is exploitable
  minotaur brief ID [PATH] [options]      What to read, and how to judge one finding
  minotaur verdict ID [PATH] [options]    Store an answer you worked out yourself
  minotaur fix ID... [PATH] [options]     Fix findings on a new branch, and check each
  minotaur fix --all [PATH] [options]     fix by running the scanner again
  minotaur mark ID DECISION [PATH]        Record your own decision about a finding:
                                          false-positive, accepted-risk, fixed, confirmed,
                                          or open to remove it
  minotaur auth login [PROVIDER]          Sign in. PROVIDER is anthropic or openai.
                                          With no PROVIDER, choose one from the list.
  minotaur auth status [PROVIDER]         Show whether a key or that login would be used
  minotaur auth logout [PROVIDER]         Forget that login
  minotaur config [PATH]                  Choose scanners and a model, and write .minotaur.yml

Minotaur looks at a git repository with at least one commit. If the folder is not one,
it offers to make a repository and commit a snapshot.

Sources (all commands):
  --commit REF           The commit to look at: a hash, branch or tag (default HEAD).
                         On HEAD with no uncommitted changes this is your working tree;
                         otherwise a clean copy of the commit, so uncommitted changes
                         and installed dependencies are left out.
  --source NAME|FILE     A scanner (${NATIVE_SCANNERS.join(', ')}) or a report file
                         (SARIF, or a supported scanner's JSON). Repeatable. Overrides
                         .minotaur.yml. Default: trivy, opengrep, and any other installed
                         scanner. Trivy and Opengrep are downloaded when missing.
  --include-ignored      Also scan files git ignores, such as dependencies,
                         build output and caches, and list what they contain
  --rescan               Scan again even when nothing changed since the last scan.
                         A scan of a commit is reused for up to 24 hours while the
                         sources and scanners stay the same.

scan:
  --min-severity LEVEL   Hide findings below this severity (${SEVERITIES.join(', ')})
  --focus LEVEL          Show only findings rated at least this likely to matter:
                         likely, maybe (the default) or noise. Style and correctness
                         rules and code in tests are rated noise; see "Focus" in the README.
  --all                  Show every finding, the noise too (the same as --focus noise)
  --json                 Write the findings as JSON, which "triage --findings" accepts.
                         Each finding has "triageable" (true, or why it cannot be
                         checked) and "check" (an earlier answer, or null).
  --unchecked            Hide findings that already have an answer

To find exploitable vulnerabilities without a model key, an agent does this:
  1. minotaur scan [PATH] --json --unchecked --focus likely
  2. For each finding whose "triageable" is true:
       minotaur brief ID [PATH] --json
     Read code only in the "tree" directory. "instructions" say how to judge it,
     and "verdict" is the JSON shape of the answer.
  3. minotaur verdict ID [PATH] --json    with that JSON on stdin, or --file PATH
     Exit code 1 and a "problems" array means the JSON was rejected: fix it and
     submit again. "downgraded": true, or a non-empty "rejectedEvidence", means
     the quotes did not match the files: fix the quotes and submit again.
  4. minotaur scan [PATH] --json    is the report. "check.exploitability" is the answer.

To fix a finding without a model key, an agent does this:
  1. minotaur brief ID [PATH] --fix --json
     Edit files only in the "tree" directory: a worktree on its own branch.
     "finding" and "instructions" say what to change; "notes" may say that
     Minotaur can do it alone, such as a dependency upgrade.
  2. The "verify" command, with --message saying what changed. Exit code 0
     means the scanner no longer reports it and the fix is committed; exit 1
     and "verification.problems" say what to change before verifying again.
  3. To give up, the "discard" command removes the worktree.

triage:
  --findings FILE        Read findings from "scan --json" output instead of re-running sources
  --model PROVIDER:MODEL anthropic:claude-sonnet-5, openai:gpt-5.4, or
                         openai-compatible:MODEL for a server you run
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

brief:
  --json                 Write the brief as JSON: commit, tree, finding, instructions,
                         the verdict schema, and the command to submit
  --fix                  Brief for fixing the finding instead: a worktree to edit,
                         and the commands to verify or discard the fix
  --findings FILE        Read findings from "scan --json" instead of scanning

verdict:
  --file PATH            Read the verdict JSON from a file instead of stdin
  --agent NAME           Who answered, recorded as agent:NAME (default agent)
  --json                 Write the stored answer as JSON
  --findings FILE        Read findings from "scan --json" instead of scanning

fix:
  Edits the files in the working tree, on the current branch, and does not
  commit. A fix stays only when the scanners that reported the finding run
  again and no longer report it, report nothing as severe in the changed files,
  and the change does not silence them. A fix that fails is undone. It gets one
  more attempt first. A finding already gone from the working tree is skipped.
  Code and configuration are fixed by the model. A dependency with a known fixed
  version is upgraded by npm, pnpm, go, cargo, or in a pinned requirements file,
  without a model; the model changes the manifest when that is not possible, and
  the package manager then updates the lockfile. Secrets are never fixed.
  To give a PATH with several ids, put it last.
  --all                  Fix every open finding "scan" lists: --focus (default
                         maybe) and --min-severity choose which. Findings marked
                         false positive, accepted risk or fixed are left out.
  --max-total-usd N      Spend for the whole run before Minotaur asks whether to go
                         on (default ${DEFAULT_MAX_TOTAL_USD} for several findings). Each "yes" allows N
                         more. Without a terminal to ask, the run stops, with exit
                         code 3; the same command again continues it.
  --allow-unverified     Leave the edit even when no scanner can run again to check
                         it, such as a finding read from a report file
  --branch NAME          For "brief ID --fix" only: the worktree's branch,
                         instead of minotaur/fixes
  --force                For "brief ID --fix" only: start that branch again from
                         the commit, dropping its earlier fixes
  --verify               Check and commit what an agent changed after
                         "brief ID --fix"; --message TEXT says what it changed,
                         and --agent NAME who did it
  --discard              Remove the worktree "brief ID --fix" made
  --model, --base-url, --effort, --max-steps, --max-usd, --max-tokens
                         As for triage. The limits apply to each finding.
  --json                 Write the branch and a result for each finding as JSON
  --findings FILE        Read findings from "scan --json" instead of scanning

mark:
  --reason TEXT          Why, for the people who review the decision
  --findings FILE        Find the id in "scan --json" output instead of scanning

  Decisions go to ${DECISIONS_FILE}, meant to be committed. False positives,
  accepted risks and fixed findings are hidden unless --all. A secret marked a
  false positive no longer keeps its file away from checks.

config:
  minotaur config [PATH]     Choose which scanners to run and which model to use,
                             then write .minotaur.yml in that repository.
                             An API key is not written there. When Trivy or Opengrep is
                             chosen and missing, the wizard offers to download it.
                             On macOS, other missing scanners are installed with
                             Homebrew when it is available. When Anthropic is
                             chosen and no key or Console login is set, the
                             wizard can start "minotaur auth login".

auth:
  minotaur auth login anthropic
                         Sign in to the Claude Console with the ant command.
                         If ant is missing, Minotaur offers to install it.
                         Triage and fix use that login when no API key is set.
  minotaur auth login openai
                         Ask for an OpenAI API key and store it outside the
                         repository. This is an API key, not a ChatGPT login.
  minotaur auth login    Choose a provider from the list, when a terminal can answer.
  --no-browser           Print the address instead of opening a browser.
                         Anthropic only.
  minotaur auth status [PROVIDER]
                         Show whether an API key or a stored login would be used.
                         With no PROVIDER, show Anthropic and OpenAI.
  minotaur auth logout [PROVIDER]
                         Forget that login. Anthropic logout also logs the ant
                         command out. An environment key is left as it is.

Environment:
  ANTHROPIC_API_KEY or OPENAI_API_KEY wins over a stored login. MINOTAUR_API_KEY
  is a fallback for either. MINOTAUR_MODEL, MINOTAUR_BASE_URL, MINOTAUR_CACHE_DIR
  (where downloaded scanners, the last scans, checks and copies of commits are kept)
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
  unchecked: { type: 'boolean' },
  file: { type: 'string' },
  agent: { type: 'string' },
  force: { type: 'boolean' },
  branch: { type: 'string' },
  fix: { type: 'boolean' },
  verify: { type: 'boolean' },
  discard: { type: 'boolean' },
  message: { type: 'string' },
  'max-total-usd': { type: 'string' },
  'allow-unverified': { type: 'boolean' },
  'no-browser': { type: 'boolean' },
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
  const { command, rest } = await splitCommand(positionals);
  if (!command && !values.help && process.stdin.isTTY && process.stdout.isTTY) {
    return interactive(await repoRoot(rest[0]), values);
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
  if (command === 'brief') {
    const [id, path, ...extra] = rest;
    if (!id) throw new UsageError('brief needs a finding id; run "minotaur scan --json" to list them');
    if (extra.length > 0) throw new UsageError('brief takes a finding id and at most one path');
    return brief(id, await repoRoot(path), values);
  }
  if (command === 'verdict') {
    const [id, path, ...extra] = rest;
    if (!id) throw new UsageError('verdict needs a finding id; run "minotaur brief ID --json" first');
    if (extra.length > 0) throw new UsageError('verdict takes a finding id and at most one path');
    return verdict(id, await repoRoot(path), values);
  }
  if (command === 'fix' && (values.verify || values.discard)) {
    const [id, path, ...extra] = rest;
    if (!id || extra.length > 0) throw new UsageError(`fix --${values.verify ? 'verify' : 'discard'} takes one finding id and at most one path`);
    if (values.verify && values.discard) throw new UsageError('--verify and --discard ask for different things; use one');
    return values.verify ? verifyAgent(id, await repoRoot(path), values) : discardAgent(id, await repoRoot(path), values);
  }
  if (command === 'fix') {
    if (values.all) {
      if (rest.length > 1) throw new UsageError('fix --all takes at most one path, and no finding ids');
      return fix(null, await repoRoot(rest[0]), values);
    }
    if (rest.length === 0) throw new UsageError('fix needs finding ids, or --all; run "minotaur scan" to list them');
    const { ids, path } = await idsAndPath(rest);
    return fix(ids, await repoRoot(path), values);
  }
  if (command === 'auth') return auth(rest, values);
  if (command === 'config') {
    if (rest.length > 1) throw new UsageError('config takes at most one path');
    return configureCommand(await repoRoot(rest[0]));
  }
  throw new UsageError(`unknown command "${command}"; expected ${COMMAND_NAMES}`);
}

const COMMANDS = new Set(['scan', 'triage', 'brief', 'verdict', 'fix', 'mark', 'auth', 'config']);
const COMMAND_NAMES = 'scan, triage, brief, verdict, fix, mark, config or auth';

/**
 * The first word is a command, or a directory to browse. `minotaur .` and
 * `minotaur /path/to/proj` are the browser; `minotaur scan` stays a command
 * even when a folder of that name exists.
 */
async function splitCommand(positionals: readonly string[]): Promise<{ command: string | undefined; rest: string[] }> {
  const [first, ...rest] = positionals;
  if (!first || COMMANDS.has(first)) return { command: first, rest };
  const info = await stat(fromInvocation(first)).catch(() => null);
  if (!info?.isDirectory()) {
    throw new UsageError(`unknown command "${first}"; expected ${COMMAND_NAMES}`);
  }
  if (rest.length > 0) throw new UsageError('minotaur takes at most one path');
  return { command: undefined, rest: [first] };
}

/** Several ids, then maybe a path. The last word is the path when it names a directory. */
async function idsAndPath(words: readonly string[]): Promise<{ ids: string[]; path: string | undefined }> {
  const last = words.at(-1)!;
  const isDirectory = words.length > 1 && ((await stat(fromInvocation(last)).catch(() => null))?.isDirectory() ?? false);
  return isDirectory ? { ids: words.slice(0, -1), path: last } : { ids: [...words], path: undefined };
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

/** "/repo at commit 3f9a1c2 (Fix the login redirect)". */
function describeTarget(target: Target): string {
  return `${target.repo} at ${describeCommit(target.commit)}`;
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
async function rated(target: Target, values: Values, config: Config, reporter: ScanReporter, onFindings?: (partial: CollectResult) => void): Promise<Gathered> {
  return ranked(await scanned(target, values, config, reporter, onFindings), config, reporter);
}

/** With the decisions from the working tree's decisions file, which may not be committed yet. */
function decided(collected: Gathered, decisions: ReadonlyMap<string, Decision>): Gathered {
  const findings = applyDecisions(collected.findings, decisions);
  return { ...collected, findings, protectedPaths: [...liftProtected(collected.protectedPaths, findings)].sort() };
}

async function scanned(target: Target, values: Values, config: Config, reporter: ScanReporter, onFindings?: (partial: CollectResult) => void): Promise<Gathered> {
  if (target.copy) reporter.step(`Copying ${target.commit.short} out of git`);
  const tree = await treeFor(target, cacheDir());
  const includeIgnored = values['include-ignored'] ?? false;
  const cache = scanCacheDir(cacheDir());
  const explicitSources = (values.source?.length ?? 0) > 0 || (config.sources?.length ?? 0) > 0;
  // The default scanners are already recorded on the cached scan, so a repeat
  // launch can reuse it without walking the tree to decide which ones apply.
  if (!values.rescan && !explicitSources) {
    reporter.step('Looking for an earlier scan of this commit');
    const installed = (await installedScanners()).map((scanner) => scanner.name);
    const cached = await matchCachedScan(cache, target, tree, includeIgnored, installed).catch(() => null);
    if (cached) {
      reporter.note(`Using the scan of this commit from ${describeAge(Date.now() - cached.createdAt)} (--rescan runs it again)`);
      return { ...cached.result, tree, cachedAt: cached.createdAt };
    }
  }

  reporter.step('Working out which scanners apply');
  const sources = await sourcesFor(target, tree, values, config);
  reporter.step('Looking for an earlier scan of this commit');
  const key = await scanKey(target, tree, sources, includeIgnored).catch(() => null);
  const cached = key && !values.rescan ? await readCachedScan(cache, target.repo, key) : null;
  if (cached && scanCovers(cached.result, sources)) {
    reporter.note(`Using the scan of this commit from ${describeAge(Date.now() - cached.createdAt)} (--rescan runs it again)`);
    return { ...cached.result, tree, cachedAt: cached.createdAt };
  }

  const keep = async (partial: CollectResult) => {
    if (!key) return;
    await writeCachedScan(cache, target.repo, key, partial).catch((error: Error) => {
      reporter.note(`Could not keep the scan for next time: ${error.message}`);
    });
  };
  reporter.sources(sources.map((source) => ('scanner' in source ? source.scanner : source.report)));
  const collected = await collectFindings(tree, sources, {
    onStart: reporter.start,
    onSource: reporter.done,
    ...(onFindings ? { onFindings } : {}),
    onSettled: keep,
    ...(cached ? { resume: cached.result } : {}),
    managed: { onDownload: reporter.note },
    includeIgnored,
    reportRoot: target.repo,
  });
  return { ...collected, tree };
}

function scopeOf(target: Target): CheckScope {
  return { repo: target.repo, commit: target.commit.sha, copy: target.copy };
}

/** Keeps finished checks for this commit, unless the working tree moved away from it while the check ran. */
function keeper(target: Target, model: ResolvedModel): RunTriageOptions['keep'] {
  const dir = checkCacheDir(cacheDir());
  return async (result, inputs) => {
    if (!(await stillCommitted(target))) return;
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
  const annotated = values.json || values.unchecked ? await annotate(where, collected, shown, config, values) : shown;
  const listed = values.unchecked ? annotated.filter((finding) => !hasAnswer(finding)) : annotated;
  const pending = await pendingFixes(where.top, where.commit.sha);
  const fixedOnBranches = listed.filter((finding) => pending.has(finding.fingerprint));

  if (values.json) {
    const withFixes = listed.map((finding) => ({ ...finding, fix: pending.get(finding.fingerprint) ?? null }));
    const file = toFindingsFile(root, where.commit.sha, withFixes, collected.sources, collected.protectedPaths);
    process.stdout.write(`${JSON.stringify(file, null, 2)}\n`);
    return 0;
  }
  const style = process.stdout.isTTY ? COLOR : PLAIN;
  process.stdout.write(`\n${renderFindingTable(listed, style, process.stdout.columns ?? 120, new Set(fixedOnBranches.map((finding) => finding.fingerprint)))}\n\n`);
  const belowFocus = open.length - shown.length - noise;
  const focusNotes = [
    ...(closed > 0 ? [`${closed} marked false positive, accepted risk or fixed (--all shows them)`] : []),
    ...(noise > 0 ? [`${noise} hidden as likely noise (--all shows them)`] : []),
    ...(belowFocus > 0 ? [`${belowFocus} below --focus ${floor} not shown`] : []),
  ];
  const answered = values.unchecked ? annotated.length - listed.length : 0;
  if (answered > 0) focusNotes.push(`${answered} already checked not shown (--unchecked hides them)`);
  process.stdout.write(`${renderSummary(listed, collected.findings.length - severe.length, collected.ignored, focusNotes)}\n`);
  process.stdout.write(style.dim(`On ${describeCommit(where.commit)}.\n`));
  if (fixedOnBranches.length > 0) {
    const branches = [...new Set(fixedOnBranches.map((finding) => pending.get(finding.fingerprint)!.branch))];
    process.stdout.write(`${describeBranchFixes(fixedOnBranches.length, branches)}\n`);
    for (const branch of branches) process.stdout.write(style.dim(`  git log -p ${where.commit.short}..${branch}    then    git merge ${branch}\n`));
  }
  if (listed.some((finding) => finding.kind === 'sca' || finding.kind === 'sast')) {
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
    model = await resolveModel(modelFlags(values), config, process.env);
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
    // The list fills in as each source finishes; rated without the exploitation evidence, which is looked up once at the end.
    const decisions = await loadDecisions(root);
    const onFindings = (partial: CollectResult) => {
      const findings = applyDecisions(rankFindings(partial.findings, new Map(), config.focus), decisions);
      reporter.found?.({ findings, ignored: partial.ignored, protectedPaths: liftProtected(partial.protectedPaths, findings) });
    };
    undecided = await rated(where, rescan ? { ...values, rescan: true } : values, config, reporter, onFindings);
    const collected = decided(undecided, await loadDecisions(root));
    protectedPaths = new Set(collected.protectedPaths);
    tree = collected.tree;
    reporter.step('Looking for earlier checks that still apply');
    const reused = await loadChecks(checkCache, scopeOf(where), tree, collected.findings, model ? identityOf(model) : null, protectedPaths);
    const earlierResults = new Map([...reused].map(([fingerprint, check]) => [fingerprint, check.result]));
    for (const result of earlierResults.values()) reusedResults.add(result);
    reporter.step('Looking for fixes on branches');
    const onBranches = await fixesOnBranches(where, collected.findings);
    const notes = [
      ...targetNotes(where),
      ...(onBranches.fixes.size > 0 ? [describeBranchFixes(onBranches.fixes.size, onBranches.branches)] : []),
      ...(collected.cachedAt ? [`From the scan ${describeAge(Date.now() - collected.cachedAt)}; press r to scan again.`] : []),
      ...(reused.size > 0 ? [`${reused.size} earlier check${reused.size === 1 ? '' : 's'} still appl${reused.size === 1 ? 'ies' : 'y'}.`] : []),
    ];
    return {
      findings: collected.findings,
      ignored: collected.ignored,
      protectedPaths,
      results: earlierResults,
      fixes: onBranches.fixes,
      message: notes.length > 0 ? notes.join(' ') : null,
      commit: commitLabel(where),
    };
  };

  let pendingFix: Promise<unknown> = Promise.resolve();
  let appliedLocally = false;
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
    fix: (findings, options) => {
      const running = (async () => {
        // A branch from an earlier fix of the same findings is continued, not refused.
        const name = fixBranchName(values);
        const scanned = decided(undecided!, await loadDecisions(root)).findings;
        const run = await runFixes({
          target: where,
          findings,
          scanned,
          protectedPaths,
          model,
          noModel: status.ok ? undefined : status.error,
          limits,
          maxTotalUsd: positiveNumber(values['max-total-usd'], '--max-total-usd') ?? (findings.length > 1 ? DEFAULT_MAX_TOTAL_USD : undefined),
          onCheckpoint: options.onCheckpoint,
          sources: await sourcesFor(where, tree, values, config),
          includeIgnored: values['include-ignored'] ?? false,
          branch: name,
          cache: cacheDir(),
          allowUnverified: values['allow-unverified'] ?? false,
          abortSignal: options.signal,
          onEvent: options.onEvent,
        });
        const diffs = new Map<string, string>();
        const copy = await workingCopy(where);
        for (const result of run.results) {
          const applied = result.status === 'fixed' || result.status === 'committed_unverified';
          if (result.commit) diffs.set(result.finding.fingerprint, await commitDiff(where.top, result.commit).catch(() => ''));
          else if (applied && result.changedFiles.length > 0) {
            diffs.set(result.finding.fingerprint, await uncommittedDiff(copy, result.changedFiles).catch(() => ''));
          }
          if (applied) appliedLocally = true;
        }
        return { run, diffs };
      })();
      pendingFix = running.catch(() => undefined);
      return running;
    },
    input: process.stdin,
    output: process.stdout,
  });
  // Quitting stops a fix, which then removes its worktree; wait for that before the process ends.
  await pendingFix;
  if (appliedLocally) process.stdout.write('Edits are in the working tree. Nothing was committed.\n');

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

interface BranchFixes {
  /** By fingerprint, for the findings of this scan. */
  fixes: Map<string, FixView>;
  /** The branches they are on, newest first. */
  branches: string[];
}

/**
 * Fixes that are committed on `minotaur/` branches but not in the scanned
 * commit. The scan still reports these findings, since the code it scanned has
 * them; this is how a later run knows the work is done and waits for a merge.
 */
async function fixesOnBranches(where: Target, findings: readonly LocalFinding[]): Promise<BranchFixes> {
  const pending = await pendingFixes(where.top, where.commit.sha);
  const fixes = new Map<string, FixView>();
  const branches: string[] = [];
  const diffs = new Map<string, string>();
  for (const finding of findings) {
    const fix = pending.get(finding.fingerprint);
    if (!fix) continue;
    if (!diffs.has(fix.commit)) diffs.set(fix.commit, await commitDiff(where.top, fix.commit).catch(() => ''));
    if (!branches.includes(fix.branch)) branches.push(fix.branch);
    fixes.set(finding.fingerprint, {
      status: fix.verified ? 'fixed' : 'committed_unverified',
      branch: fix.branch,
      commit: fix.commit,
      summary: `Fixed on branch ${fix.branch}${fix.by ? ` by ${fix.by}` : ''}, not merged yet.`,
      notes: [],
      error: null,
      diff: diffs.get(fix.commit) || null,
    });
  }
  return { fixes, branches };
}

function describeBranchFixes(count: number, branches: readonly string[]): string {
  return `${count} finding${count === 1 ? ' has a fix' : 's have fixes'} on ${branches.length === 1 ? `branch ${branches[0]}` : `${branches.length} branches`}, not merged yet; merge ${branches.length === 1 ? 'it' : 'them'} to close ${count === 1 ? 'it' : 'them'}.`;
}

function fixBranchName(values: Values): string {
  return values.branch?.trim() || DEFAULT_BRANCH;
}

function commitLabel(where: Target): string {
  return `${where.commit.short} ${where.commit.subject}`.trim();
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

async function annotate(
  where: Target,
  collected: Gathered,
  findings: readonly LocalFinding[],
  config: Config,
  values: Values,
) {
  const protectedPaths = new Set(collected.protectedPaths);
  const checks = await loadChecks(checkCacheDir(cacheDir()), scopeOf(where), collected.tree, findings, await configuredIdentity(config, values), protectedPaths);
  return withChecks(findings, protectedPaths, checks);
}

function hasAnswer(finding: LocalFinding): boolean {
  const check = (finding as { check?: { exploitability: string } | null }).check;
  return check != null;
}

async function configuredIdentity(config: Config, values: Values): Promise<CheckIdentity | null> {
  try {
    return identityOf(await resolveModel(modelFlags(values), config, process.env));
  } catch {
    return null;
  }
}

/** The findings, the tree to read, and the files a check must not open. */
async function openFindings(ids: readonly string[] | null, root: string, values: Values) {
  const { config } = await loadConfig(root);
  const file = values.findings ? await readFindingsFile(fromInvocation(values.findings)) : null;
  // Findings from "scan --json" belong to the commit they were scanned on.
  const where = await target(root, values.commit ?? file?.commit ?? undefined);
  announce(where);
  if (file?.commit && file.commit !== where.commit.sha) {
    info(`The findings file is from commit ${file.commit.slice(0, 7)}, so its line numbers may not match ${where.commit.short}.`);
  }
  const gathered = file ? { ...file, tree: await treeFor(where, cacheDir()) } : await gather(where, values, config);
  // Decisions may have changed since a findings file was written, so they are read again.
  const findings = file ? applyDecisions(file.findings, await loadDecisions(root)) : gathered.findings;
  const protectedPaths = liftProtected([...(file ? file.protectedPaths : gathered.protectedPaths), ...secretPaths(findings)], findings);
  const picked = ids
    ? [...new Map(ids.map((id) => resolveFinding(findings, id)).map((finding) => [finding.fingerprint, finding])).values()]
    : openAndInFocus(findings, values);
  return { config, where, tree: gathered.tree, protectedPaths, findings: picked, scanned: findings };
}

/** What `scan` lists by default, or with the same --focus and --min-severity: for `fix --all`. */
function openAndInFocus(findings: readonly LocalFinding[], values: Values): LocalFinding[] {
  const minimum = parseSeverity(values['min-severity']);
  // For fix, --all means every finding, not every focus level as it does for scan.
  const floor = parseFocus(values.focus, false) ?? 'maybe';
  return findings.filter(
    (finding) =>
      !isClosed(finding) &&
      focusRank(finding.focus ?? 'maybe') >= focusRank(floor) &&
      (!minimum || severityRank(finding.severity) >= severityRank(minimum)),
  );
}

/** The finding, the tree to read, and the files a check must not open. */
async function openFinding(id: string, root: string, values: Values) {
  const { findings, ...opened } = await openFindings([id], root, values);
  return { ...opened, finding: findings[0]! };
}

async function triage(id: string, root: string, values: Values): Promise<number> {
  const { config } = await loadConfig(root);
  const model = await resolveModel(modelFlags(values), config, process.env);
  const limits = triageLimits(values, config);
  const { where, tree, protectedPaths, finding } = await openFinding(id, root, values);
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

/** `minotaur brief ID`: the commit, where to read it, and how to judge the finding. */
async function brief(id: string, root: string, values: Values): Promise<number> {
  if (values.fix) return briefFix(id, root, values);
  const opened = await openFinding(id, root, values);
  const checks = await loadChecks(
    checkCacheDir(cacheDir()),
    scopeOf(opened.where),
    opened.tree,
    [opened.finding],
    await configuredIdentity(opened.config, values),
    opened.protectedPaths,
  );
  const earlier = checks.get(opened.finding.fingerprint)?.result;
  const submit = ['minotaur', 'verdict', opened.finding.id, root, ...(values.commit ? ['--commit', values.commit] : []), '--json'].join(' ');
  const built = buildBrief({
    finding: opened.finding,
    tree: opened.tree,
    commit: opened.where.commit,
    submit,
    ...(earlier?.status === 'succeeded' && earlier.exploitability && earlier.rationale ? { earlier } : {}),
  });
  process.stdout.write(`${JSON.stringify(built, null, 2)}\n`);
  return 0;
}

/**
 * `minotaur brief ID --fix`: a worktree for an agent to fix the finding in,
 * and how. Run again, it returns the same worktree with the edits so far.
 */
async function briefFix(id: string, root: string, values: Values): Promise<number> {
  const { finding, where, protectedPaths } = await openFinding(id, root, values);
  if (!finding.location) throw new Error('the scanner gave no file for this finding, so there is nothing to edit');
  const name = fixBranchName(values);
  const cache = cacheDir();
  let branch = await existingFixBranch(where, name, cache).catch(() => null);
  // The worktree is shared: it is this finding's only while the agent works on it.
  if (!branch || (await readClaim(branch.worktree))?.fingerprint !== finding.fingerprint) {
    try {
      branch = await openFixBranch(where, name, cache);
    } catch (error) {
      if (error instanceof WorktreeError) throw new UsageError(error.message);
      throw error;
    }
    if ((await fixedOnBranch(branch)).has(finding.fingerprint)) {
      await closeFixBranch(branch);
      throw new UsageError(`branch ${name} already has a fix for ${finding.id}; review it with: git log -p ${where.commit.short}..${name}`);
    }
    await writeClaim(branch, { id: finding.id, fingerprint: finding.fingerprint });
  }

  const secret = finding.kind === 'secret' || protectedReason(finding.location.path, protectedPaths) !== null;
  const guidance: string[] = [];
  const notes: string[] = [];
  if (finding.kind === 'sca' || finding.kind === 'license') {
    const plan = await planUpgrade(branch.tree, finding, upgradeVersion(finding, [finding]));
    if (plan.kind === 'command') notes.push(`Minotaur can make this upgrade itself with ${plan.manager}, without a model: minotaur fix ${finding.id} ${root}`);
    if (plan.kind === 'model') guidance.push(plan.guidance);
    if (plan.kind === 'unsupported') notes.push(plan.reason);
    guidance.push('Update lockfiles only with the package manager, never by hand. Run it in the tree directory with its scripts turned off, such as npm install --ignore-scripts.');
  }
  if (secret) {
    guidance.push(
      finding.kind === 'secret'
        ? 'This finding is a credential in the code. Do not print, copy, log or repeat its value anywhere. Replace it with a read from an environment variable or the secret store the project already uses, and remove the value from the file.'
        : `${finding.location.path} also contains a credential. Do not print, copy, log or repeat it.`,
    );
    notes.push('The credential is still in the git history, so removing it from the code is not enough: rotate it.');
  }
  // A secret's snippet is the secret; it stays out of the brief.
  const subject = toSubject(finding);
  const shown = secret && subject.location ? { ...subject, location: { ...subject.location, snippet: undefined } } : subject;
  const at = [finding.id, root, '--commit', where.commit.sha, ...(values.branch ? ['--branch', values.branch] : [])];
  process.stdout.write(
    `${JSON.stringify(
      {
        commit: where.commit,
        branch: name,
        tree: branch.tree,
        finding: renderFixRequest(shown, undefined, guidance.join('\n') || undefined),
        instructions: agentFixInstructions(),
        notes,
        verify: ['minotaur', 'fix', ...at, '--verify', '--message', '"WHAT YOU CHANGED"', '--json'].join(' '),
        discard: ['minotaur', 'fix', ...at, '--discard'].join(' '),
      },
      null,
      2,
    )}\n`,
  );
  return 0;
}

/** `minotaur fix ID --verify`: rescans an agent's edits in the worktree, and commits them when they pass. */
async function verifyAgent(id: string, root: string, values: Values): Promise<number> {
  const { config } = await loadConfig(root);
  const opened = await openFinding(id, root, values);
  const { finding, where } = opened;
  const name = fixBranchName(values);
  const branch = await existingFixBranch(where, name, cacheDir()).catch((error: Error) => {
    throw new UsageError(error.message);
  });
  const claim = branch ? await readClaim(branch.worktree) : null;
  if (!branch || claim?.fingerprint !== finding.fingerprint) {
    const other = claim ? ` The worktree of ${name} has the edits for ${claim.id}.` : '';
    throw new UsageError(`there is no fix of ${finding.id} in progress; run "minotaur brief ${finding.id} ${root} --fix --json" first.${other}`);
  }
  const result = await verifyAgentFix({
    branch,
    finding,
    scanned: opened.scanned,
    sources: await sourcesFor(where, opened.tree, values, config),
    includeIgnored: values['include-ignored'] ?? false,
    allowUnverified: values['allow-unverified'] ?? false,
    by: agentIdentity(values.agent).model,
    summary: values.message?.trim() || `Fixed ${finding.title}.`,
    managed: { onDownload: info },
    onEvent: fixReporter(),
  });
  const committed = result.commit !== null;
  if (values.json) {
    process.stdout.write(`${JSON.stringify({ ...result, tree: committed ? null : branch.tree }, null, 2)}\n`);
  } else if (committed) {
    process.stdout.write(`\n${renderFixRun({ branch: name, results: [result], interrupted: false, stoppedAtCap: false, alreadyOnBranch: 0 }, where.commit.sha, process.stdout.isTTY ? COLOR : PLAIN)}\n`);
  } else {
    process.stdout.write(`\n${finding.id} is not fixed yet:\n${(result.verification?.problems ?? [result.error ?? 'unknown']).map((problem) => `  - ${problem}`).join('\n')}\n`);
    process.stdout.write(`The edits are still in ${branch.tree}. Change them and verify again, or remove them with --discard.\n`);
  }
  return committed ? 0 : 1;
}

/** `minotaur fix ID --discard`: removes an agent's worktree, and its branch when nothing was committed on it. */
async function discardAgent(id: string, root: string, values: Values): Promise<number> {
  const { finding, where } = await openFinding(id, root, values);
  const name = fixBranchName(values);
  const branch = await existingFixBranch(where, name, cacheDir()).catch(() => null);
  const claim = branch ? await readClaim(branch.worktree) : null;
  if (!branch || claim?.fingerprint !== finding.fingerprint) {
    process.stdout.write(`There is no fix of ${finding.id} in progress.\n`);
    return 0;
  }
  await discardChanges(branch);
  const { kept } = await closeFixBranch(branch);
  process.stdout.write(kept ? `Removed the edits for ${finding.id}; branch ${name} keeps its earlier fixes.\n` : `Removed the edits for ${finding.id} and the empty branch ${name}.\n`);
  return 0;
}

/** `minotaur verdict ID`: check an agent's answer against the files and keep it. */
async function verdict(id: string, root: string, values: Values): Promise<number> {
  const opened = await openFinding(id, root, values);
  const text = values.file ? await readFile(fromInvocation(values.file), 'utf8') : await readStdin();
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ problems: [`verdict is not JSON: ${(error as Error).message}`] }, null, 2)}\n`);
    return 1;
  }
  const by = agentIdentity(values.agent);
  const reviewed = await reviewVerdict({
    finding: opened.finding,
    tree: opened.tree,
    protectedPaths: opened.protectedPaths,
    raw,
    by,
  });
  if ('problems' in reviewed) {
    process.stdout.write(`${JSON.stringify({ problems: reviewed.problems }, null, 2)}\n`);
    return 1;
  }
  await saveCheck(checkCacheDir(cacheDir()), scopeOf(opened.where), reviewed.result, [], by);
  return writeTriageResult(reviewed.result, values);
}

/** `minotaur fix ID...` or `minotaur fix --all`: fix findings on a new branch, one commit each. */
async function fix(ids: readonly string[] | null, root: string, values: Values): Promise<number> {
  const { config } = await loadConfig(root);
  // Package manager upgrades need no model, so a missing one only fails the fixes that do.
  let model: ResolvedModel | null = null;
  let noModel: string | undefined;
  try {
    model = await resolveModel(modelFlags(values), config, process.env);
  } catch (error) {
    noModel = (error as Error).message;
  }
  const limits = triageLimits(values, config);
  const opened = await openFindings(ids, root, values);
  const { where, findings } = opened;
  if (findings.length === 0) {
    process.stdout.write(values.json ? `${JSON.stringify({ base: where.commit.sha, branch: null, results: [] }, null, 2)}\n` : 'Nothing to fix.\n');
    return 0;
  }
  const sources = await sourcesFor(where, opened.tree, values, config);
  const checks = await loadChecks(checkCacheDir(cacheDir()), scopeOf(where), opened.tree, findings, model ? identityOf(model) : null, opened.protectedPaths);
  const earlier = new Map<string, EarlierCheck>();
  for (const finding of findings) {
    const check = checks.get(finding.fingerprint)?.result;
    if (check?.status === 'succeeded' && check.exploitability && check.rationale) earlier.set(finding.fingerprint, earlierFrom(check, finding, 'the earlier check'));
  }
  const branch = fixBranchName(values);
  const maxTotalUsd = positiveNumber(values['max-total-usd'], '--max-total-usd') ?? (findings.length > 1 ? DEFAULT_MAX_TOTAL_USD : undefined);
  const again = ['minotaur', 'fix', ...(ids ?? ['--all']), root, '--commit', where.commit.sha].join(' ');
  const copy = await workingCopy(where);

  info(`\nFixing ${findings.length === 1 ? findings[0]!.id : `${findings.length} findings`} in the working tree, on ${copy.name}. Nothing is committed.`);
  if (model) {
    info(`Code is sent to ${describeModel(model)}.`);
    info(`Limits for each finding: ${describeLimits(model, limits)}.${maxTotalUsd ? ` Minotaur asks before the run spends more than $${maxTotalUsd}.` : ''}`);
  } else {
    info('No model is configured, so only dependencies with a known fixed version can be upgraded.');
  }

  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  const canAsk = !values.json && process.stdin.isTTY && process.stderr.isTTY;
  try {
    const run = await runFixes({
      target: where,
      findings,
      scanned: opened.scanned,
      protectedPaths: opened.protectedPaths,
      model,
      noModel,
      limits,
      maxTotalUsd,
      onCheckpoint: canAsk ? (checkpoint) => askToContinue(checkpoint, maxTotalUsd!, controller.signal) : undefined,
      sources,
      includeIgnored: values['include-ignored'] ?? false,
      branch,
      cache: cacheDir(),
      force: values.force ?? false,
      allowUnverified: values['allow-unverified'] ?? false,
      earlier,
      managed: { onDownload: info },
      abortSignal: controller.signal,
      onEvent: fixReporter(),
    });
    const unfinished = run.stoppedAtCap || run.interrupted;
    if (values.json) {
      process.stdout.write(`${JSON.stringify({ base: where.commit.sha, ...run, continue: unfinished ? again : null }, null, 2)}\n`);
    } else {
      process.stdout.write(`\n${renderFixRun(run, where.commit.sha, process.stdout.isTTY ? COLOR : PLAIN, unfinished ? again : null)}\n`);
    }
    if (run.stoppedAtCap) return 3;
    // With --all, what cannot be fixed here, such as a secret, is expected; with named ids it is a failure.
    const done = (result: FixResult) => result.status === 'fixed' || result.status === 'committed_unverified' || (!ids && result.status === 'skipped');
    return run.results.every(done) && !run.interrupted ? 0 : 1;
  } catch (error) {
    if (error instanceof WorktreeError) throw new UsageError(error.message);
    throw error;
  } finally {
    process.removeListener('SIGINT', stop);
  }
}

/** The checkpoint at the batch's cap, as a question on the terminal. Ctrl-C, or anything but yes, stops. */
async function askToContinue(checkpoint: Checkpoint, cap: number, signal: AbortSignal): Promise<boolean> {
  const count = (statuses: readonly string[]) => checkpoint.results.filter((result) => statuses.includes(result.status)).length;
  const fixed = count(['fixed', 'committed_unverified']);
  const notFixed = checkpoint.results.length - fixed;
  info(`\nThe run has spent $${checkpoint.spentUsd.toFixed(2)} of $${checkpoint.capUsd.toFixed(2)}.`);
  info(`  ${fixed} fixed, ${notFixed} not fixed, ${checkpoint.remaining} not started.`);
  info(`  In progress: ${checkpoint.current.id} ${checkpoint.current.title}`);
  const { createInterface } = await import('node:readline/promises');
  const prompt = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await prompt.question(`Continue for up to $${cap.toFixed(2)} more? [y/N] `, { signal });
    return /^y(es)?$/i.test(answer.trim());
  } catch {
    return false;
  } finally {
    prompt.close();
  }
}

/** Progress of a fix run as plain lines on stderr. */
function fixReporter(): (event: FixEvent) => void {
  return (event) => {
    if (event.type === 'start') {
      const count = event.total > 1 ? ` (${event.index + 1} of ${event.total})` : '';
      info(`\n${event.finding.id}${count}: ${event.finding.title}`);
    } else if (event.type === 'step') {
      const { progress } = event;
      const tokens = (progress.inputTokens + progress.outputTokens).toLocaleString('en-US');
      const cost = progress.costUsd > 0 ? `, $${progress.costUsd.toFixed(2)}` : '';
      const edited = progress.changedFiles.length > 0 ? `, edited ${progress.changedFiles.join(', ')}` : '';
      info(`  step ${progress.steps} of at most ${event.maxSteps}: ${tokens} tokens so far${cost}${edited}`);
    } else if (event.type === 'upgrade') {
      info(`  ${event.description}`);
    } else if (event.type === 'already_fixed') {
      info(`${event.count} already fixed on the branch.`);
    } else if (event.type === 'discarded') {
      info(`Dropped uncommitted edits on ${event.branch}${event.findingId ? ` for ${event.findingId}` : ''}.`);
    } else if (event.type === 'verify') {
      info(event.scanners.length > 0 ? `  running ${event.scanners.join(', ')} again` : '  no scanner can run again to check this fix');
    } else if (event.type === 'retry') {
      info('  not fixed yet, trying again:');
      for (const problem of event.problems) info(`    ${problem}`);
    }
  };
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
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

/** `minotaur config`: ask for scanners and a model, then write `.minotaur.yml`. */
async function configureCommand(root: string): Promise<number> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new UsageError('minotaur config needs a terminal');
  return configureRepository({ root, env: process.env, login: () => consoleLogin({ env: process.env }) });
}

/** `minotaur auth`: sign in to Anthropic or OpenAI, or show what would be used. */
async function auth(rest: readonly string[], values: Values): Promise<number> {
  const [action, providerName, ...extra] = rest;
  if (extra.length > 0) throw new UsageError('auth takes an action and one provider');
  const provider = providerName ? checkedProvider(providerName) : undefined;
  if (action === 'status') {
    process.stdout.write(`${await formatAuthStatus(process.env, provider)}\n`);
    return 0;
  }
  if (action === 'login') {
    const which = provider ?? (await offeredProvider('Sign in with which provider', action));
    if (which === 'openai') return openAILogin({ env: process.env });
    return consoleLogin({ noBrowser: values['no-browser'] === true, env: process.env });
  }
  if (action === 'logout') {
    const which = provider ?? (await offeredProvider('Log out of which provider', action));
    if (which === 'openai') return openAILogout({ env: process.env });
    return consoleLogout();
  }
  throw new UsageError('auth needs an action: login, status or logout');
}

function checkedProvider(name: string): ReturnType<typeof parseAuthProvider> {
  try {
    return parseAuthProvider(name);
  } catch (error) {
    throw new UsageError(error instanceof Error ? error.message : String(error));
  }
}

async function offeredProvider(question: string, action: string): Promise<ReturnType<typeof parseAuthProvider>> {
  try {
    return await chooseAuthProvider(question);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.startsWith('needs a provider')) throw new UsageError(`auth ${action} ${message}`);
    throw error;
  }
}

/** 0 when the command did its job, 1 when it could not, 2 when it was called wrongly. */
export function exitCodeFor(error: unknown): number {
  return error instanceof UsageError ? 2 : 1;
}
