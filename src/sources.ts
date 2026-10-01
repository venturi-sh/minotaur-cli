/**
 * Turning the configured sources into one list of findings.
 *
 * A source that fails is reported and skipped rather than failing the run:
 * one broken scanner should not hide what the others found. Only when every
 * source fails is the result an error, because an empty list would otherwise
 * read as a clean repository.
 */

import { readFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';

import { bySeverityDesc, dedupeFindings, type Finding, type Focus } from './core/index.js';
import {
  LOCAL_SCANNERS,
  detectTarget,
  installedScanners,
  isInstalled,
  localScannerByName,
  parseReport,
  ruleDirectoriesFor,
  runInstalledScanner,
  type DetectedTarget,
} from './scanners/index.js';

import type { SourceConfig } from './config.js';
import type { Decision } from './decisions.js';
import { gitIgnored, ignoredPaths, scannerSkipArgs, type IgnoredPaths } from './ignored.js';
import { ensureRules, ensureTool, isManaged, type EnsureOptions } from './managed.js';

export const SHORT_ID_LENGTH = 8;

/**
 * A finding as the CLI shows it: with a short id, and without the scanner's
 * raw payload. The focus fields are set by `rankFindings` after each scan.
 */
export type LocalFinding = Omit<Finding, 'raw'> & {
  id: string;
  focus?: Focus | undefined;
  focusReasons?: string[] | undefined;
  riskScore?: number | undefined;
  epss?: number | undefined;
  kev?: boolean | undefined;
  /** What a person decided about it, from `.minotaur/decisions.yml`. */
  decision?: Decision | undefined;
};

export interface SourceOutcome {
  source: string;
  status: 'ok' | 'failed' | 'skipped';
  findings: number;
  durationMs: number;
  error?: string;
}

export interface CollectResult {
  findings: LocalFinding[];
  sources: SourceOutcome[];
  /** Findings left out because git ignores their file. */
  ignored: number;
  /** Files with a detected secret, including ones left out of `findings`. */
  protectedPaths: string[];
}

export interface CollectOptions {
  onSource?: (outcome: SourceOutcome) => void;
  onStart?: (source: string) => void;
  /** The findings so far, after each source that found any, so they can be shown before the last source is done. */
  onFindings?: (partial: CollectResult) => void;
  /**
   * Called after every source settles, including one that found nothing.
   * Awaited before the next source starts, so a finished scanner can be kept.
   */
  onSettled?: (partial: CollectResult) => void | Promise<void>;
  /** Sources already recorded as ok or skipped are not run again. */
  resume?: CollectResult;
  /** Keep findings in files git ignores, which are left out by default. */
  includeIgnored?: boolean;
  /** Where missing scanners are downloaded to, and how the download is announced. */
  managed?: EnsureOptions;
  /** The directory a report's paths are relative to, when that is not `root`: reports are made in the working tree. */
  reportRoot?: string;
}

/** True when every source already finished, so nothing needs to run. */
export function scanCovers(result: CollectResult, sources: readonly SourceConfig[]): boolean {
  const done = new Set(
    result.sources.filter((outcome) => outcome.status === 'ok' || outcome.status === 'skipped').map((outcome) => outcome.source),
  );
  return sources.every((source) => done.has(sourceName(source)));
}

function sourceName(source: SourceConfig): string {
  return 'scanner' in source ? source.scanner : source.report;
}

export const NATIVE_SCANNERS = LOCAL_SCANNERS.map((scanner) => scanner.name);

/** A source with nothing to look at in this repository, which is not a failure. */
class NotApplicable extends Error {}

export async function collectFindings(
  root: string,
  sources: readonly SourceConfig[],
  options: CollectOptions = {},
): Promise<CollectResult> {
  const resumed = (options.resume?.sources ?? []).filter((outcome) => outcome.status === 'ok' || outcome.status === 'skipped');
  const finished = new Set(resumed.map((outcome) => outcome.source));
  const carried = options.resume ? { ignored: options.resume.ignored, protectedPaths: options.resume.protectedPaths } : undefined;
  const outcomes: SourceOutcome[] = [...resumed];
  const found: Finding[] = (options.resume?.findings ?? []).map((item) => ({ ...item }));
  let target: DetectedTarget | undefined;

  if (resumed.length > 0) {
    for (const outcome of resumed) options.onSource?.(outcome);
    if (options.onFindings && found.length > 0) options.onFindings(await assemble(root, found, outcomes, options.includeIgnored, carried));
  }

  const skipped = options.includeIgnored ? null : await ignoredPaths(root);

  for (const source of sources) {
    const name = sourceName(source);
    if (finished.has(name)) continue;
    options.onStart?.(name);
    const started = Date.now();
    try {
      let findings: Finding[];
      if ('scanner' in source) {
        target ??= await detectTarget(root);
        findings = await runScanner(root, source, target, options.managed ?? {}, skipped);
      } else {
        const path = isAbsolute(source.report) ? source.report : resolve(root, source.report);
        findings = (await parseReport(await readFile(path, 'utf8'), options.reportRoot ?? root, source.format ?? undefined)).findings;
      }
      found.push(...findings);
      const outcome: SourceOutcome = { source: name, status: 'ok', findings: findings.length, durationMs: Date.now() - started };
      outcomes.push(outcome);
      options.onSource?.(outcome);
      const partial = await assemble(root, found, outcomes, options.includeIgnored, carried);
      if (options.onFindings && findings.length > 0) options.onFindings(partial);
      await options.onSettled?.(partial);
    } catch (error) {
      const outcome: SourceOutcome = {
        source: name,
        status: error instanceof NotApplicable ? 'skipped' : 'failed',
        findings: 0,
        durationMs: Date.now() - started,
        error: (error as Error).message,
      };
      outcomes.push(outcome);
      options.onSource?.(outcome);
      await options.onSettled?.(await assemble(root, found, outcomes, options.includeIgnored, carried));
    }
  }

  if (outcomes.some((outcome) => outcome.status === 'failed') && !outcomes.some((outcome) => outcome.status === 'ok')) {
    const reasons = outcomes.map((outcome) => `${outcome.source}: ${outcome.error}`).join('; ');
    throw new Error(`every source failed, so there is nothing to show (${reasons})`);
  }

  return assemble(root, found, outcomes, options.includeIgnored, carried);
}

/** Findings already left out of an earlier partial, which are not in `found` to be counted again. */
interface Carried {
  ignored: number;
  protectedPaths: readonly string[];
}

/** One list from what every source found so far: deduplicated, and without the files git ignores. */
async function assemble(
  root: string,
  found: readonly Finding[],
  outcomes: readonly SourceOutcome[],
  includeIgnored = false,
  carried?: Carried,
): Promise<CollectResult> {
  const all = toLocal(dedupeFindings(found));
  const paths = [...new Set(all.flatMap((finding) => (finding.location ? [finding.location.path] : [])))];
  const ignored = includeIgnored || paths.length === 0 ? null : await gitIgnored(root, paths);
  const findings = ignored ? all.filter((finding) => !finding.location || !ignored.has(finding.location.path)) : all;
  return {
    findings,
    sources: [...outcomes],
    ignored: all.length - findings.length + (carried?.ignored ?? 0),
    protectedPaths: [...new Set([...(carried?.protectedPaths ?? []), ...secretPaths(all)])].sort(),
  };
}

async function runScanner(
  root: string,
  source: { scanner: string; args?: string[] | undefined },
  target: DetectedTarget,
  managed: EnsureOptions,
  ignored: IgnoredPaths | null,
): Promise<Finding[]> {
  const adapter = localScannerByName(source.scanner);
  if (!adapter?.native) {
    throw new Error(`unknown scanner "${source.scanner}"; supported: ${NATIVE_SCANNERS.join(', ')}`);
  }
  let args = source.args;
  if (adapter.name === 'opengrep' && !args) {
    const directories = ruleDirectoriesFor(target);
    if (directories.length === 0) throw new NotApplicable('no code in a language the Opengrep rules cover');
    const rules = await ensureRules(managed);
    args = directories.flatMap((directory) => ['--config', join(rules, directory)]);
  }
  const skip = ignored ? scannerSkipArgs(adapter.name, ignored) : [];
  if (skip.length > 0) args = [...skip, ...(args ?? [])];
  let binary: string | undefined;
  if (!(await isInstalled(adapter.native.binary))) {
    if (!isManaged(adapter.name)) throw new Error(`${adapter.native.binary} is not installed or not on PATH`);
    binary = await ensureTool(adapter.name, managed);
  }
  return (await runInstalledScanner(adapter, root, { args, binary, target })).findings;
}

/**
 * With nothing configured: every installed scanner that applies, plus Trivy
 * and a code scanner, downloaded when missing. Trivy is always there because
 * its secret findings are what keep credential files away from the model.
 */
export async function defaultSources(root: string): Promise<SourceConfig[]> {
  const installed = new Set((await installedScanners()).map((scanner) => scanner.name));
  const wanted = new Set([...installed, 'trivy']);
  if (!installed.has('semgrep')) wanted.add('opengrep');
  const target = await detectTarget(root);
  return LOCAL_SCANNERS.filter((scanner) => wanted.has(scanner.name) && scanner.appliesTo(target)).map((scanner) => ({
    scanner: scanner.name,
  }));
}

export function toLocal(findings: readonly Finding[]): LocalFinding[] {
  return findings
    .map(({ raw: _raw, ...finding }) => ({ id: finding.fingerprint.slice(0, SHORT_ID_LENGTH), ...finding }))
    .sort(
      (a, b) =>
        bySeverityDesc(a.severity, b.severity) ||
        (a.location?.path ?? '').localeCompare(b.location?.path ?? '') ||
        a.fingerprint.localeCompare(b.fingerprint),
    );
}

/** Any unique prefix of a fingerprint names a finding, the short id included. */
export function resolveFinding(findings: readonly LocalFinding[], id: string): LocalFinding {
  const prefix = id.trim().toLowerCase();
  if (prefix.length < 4) throw new Error('a finding id needs at least 4 characters');
  const matches = findings.filter((finding) => finding.fingerprint.startsWith(prefix));
  if (matches.length === 1) return matches[0]!;
  if (matches.length === 0) {
    throw new Error(`no finding with id ${id}; run "minotaur scan" to list them, with the same sources`);
  }
  const listed = matches
    .slice(0, 5)
    .map((finding) => `${finding.fingerprint.slice(0, 12)} ${finding.title}`)
    .join(', ');
  throw new Error(`id ${id} matches ${matches.length} findings (${listed}); use more characters`);
}

/** Paths a secret finding points at. Nothing there is read by the agent or sent to a model. */
export function secretPaths(findings: readonly LocalFinding[]): Set<string> {
  return new Set(
    findings.flatMap((finding) => (finding.kind === 'secret' && finding.location?.path ? [finding.location.path] : [])),
  );
}
