/**
 * What a person reads in the terminal. Machine-readable output is `--json`;
 * this is for eyes, so it favours short lines over completeness.
 */

import { readFile } from 'node:fs/promises';

import { findingSchema, focusSchema, type Severity } from './core/index.js';
import { z } from 'zod';

import { decisionSchema, isClosed } from './decisions.js';
import type { LocalFinding, SourceOutcome } from './sources.js';
import type { FixRun, FixStatus } from './fix.js';
import { refusalFor, type TriageResult } from './triage.js';

export interface Style {
  bold(text: string): string;
  dim(text: string): string;
  inverse(text: string): string;
  red(text: string): string;
  green(text: string): string;
  yellow(text: string): string;
  severity(severity: Severity, text: string): string;
}

const same = (text: string) => text;
export const PLAIN: Style = { bold: same, dim: same, inverse: same, red: same, green: same, yellow: same, severity: (_s, t) => t };

const SEVERITY_COLOR: Record<Severity, number> = { critical: 35, high: 31, medium: 33, low: 36, info: 2, unknown: 2 };

export const COLOR: Style = {
  bold: (t) => `\u001b[1m${t}\u001b[22m`,
  dim: (t) => `\u001b[2m${t}\u001b[22m`,
  inverse: (t) => `\u001b[7m${t}\u001b[27m`,
  red: (t) => `\u001b[31m${t}\u001b[39m`,
  green: (t) => `\u001b[32m${t}\u001b[39m`,
  yellow: (t) => `\u001b[33m${t}\u001b[39m`,
  severity: (s, t) => `\u001b[${SEVERITY_COLOR[s]}m${t}\u001b[39m`,
};

export function locationOf(finding: {
  location?: { path: string; startLine?: number | undefined; endLine?: number | undefined } | null | undefined;
}): string {
  const location = finding.location;
  if (!location) return '';
  if (!location.startLine) return location.path;
  const end = location.endLine && location.endLine !== location.startLine ? `-${location.endLine}` : '';
  return `${location.path}:${location.startLine}${end}`;
}

export function toolsOf(finding: LocalFinding): string {
  return (finding.tools.length > 0 ? finding.tools : [finding.tool]).map((tool) => tool.name).join(',');
}

/** One line of exactly `width` characters: whitespace collapsed, padded, or cut with an ellipsis. */
export function fit(text: string, width: number): string {
  if (width <= 0) return '';
  const single = text.replace(/\s+/g, ' ').trim();
  return single.length <= width ? single.padEnd(width) : `${single.slice(0, Math.max(0, width - 1))}…`;
}

/** `onBranch` holds the fingerprints with a fix on a branch that is not merged yet. */
export function renderFindingTable(findings: readonly LocalFinding[], style: Style, width = 120, onBranch: ReadonlySet<string> = new Set()): string {
  if (findings.length === 0) return 'No findings.';
  const kindWidth = 6;
  const severityWidth = 8;
  const toolWidth = Math.min(20, Math.max(4, ...findings.map((finding) => toolsOf(finding).length)));
  const fixed = 2 + 8 + 2 + severityWidth + 2 + kindWidth + 2 + toolWidth + 2;
  const flexible = Math.max(30, width - fixed);
  const titleWidth = Math.ceil(flexible * 0.55);
  const locationWidth = flexible - titleWidth - 2;

  const header = [
    ' ',
    fit('ID', 8),
    fit('SEVERITY', severityWidth),
    fit('KIND', kindWidth),
    fit('TOOL', toolWidth),
    fit('TITLE', titleWidth),
    'LOCATION',
  ].join('  ');
  const rows = findings.map((finding) =>
    [
      onBranch.has(finding.fingerprint) ? style.green('⎇') : isClosed(finding) ? style.dim('✓') : finding.focus === 'likely' ? style.yellow('!') : ' ',
      finding.id,
      style.severity(finding.severity, fit(finding.severity, severityWidth)),
      fit(finding.kind, kindWidth),
      fit(toolsOf(finding), toolWidth),
      fit(finding.title, titleWidth),
      fit(locationOf(finding), locationWidth).trimEnd(),
    ].join('  '),
  );
  const legend = [
    ...(findings.some((finding) => finding.focus === 'likely' && !isClosed(finding) && !onBranch.has(finding.fingerprint)) ? [`${style.yellow('!')} likely an issue`] : []),
    ...(findings.some((finding) => isClosed(finding) && !onBranch.has(finding.fingerprint)) ? ['✓ marked false positive, accepted risk or fixed'] : []),
    ...(findings.some((finding) => onBranch.has(finding.fingerprint)) ? [`${style.green('⎇')} fixed on a branch, not merged yet`] : []),
  ];
  if (legend.length > 0) return [style.bold(header), ...rows, style.dim(legend.join('   '))].join('\n');
  return [style.bold(header), ...rows].join('\n');
}

export function renderSummary(findings: readonly LocalFinding[], belowSeverity: number, ignored = 0, extra: readonly string[] = []): string {
  const counts = new Map<string, number>();
  for (const finding of findings) counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  const parts = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
    .filter((severity) => counts.has(severity))
    .map((severity) => `${counts.get(severity)} ${severity}`);
  const total = `${findings.length} finding${findings.length === 1 ? '' : 's'}`;
  const notes = [
    ...(belowSeverity > 0 ? [`${belowSeverity} below the severity filter not shown`] : []),
    ...extra,
    ...(ignored > 0 ? [`${ignored} in files git ignores not shown (--include-ignored shows them)`] : []),
  ];
  return `${total}${parts.length > 0 ? ` (${parts.join(', ')})` : ''}${notes.map((note) => `, ${note}`).join('')}.`;
}

export function renderSourceOutcome(outcome: SourceOutcome): string {
  const seconds = (outcome.durationMs / 1000).toFixed(1);
  if (outcome.status === 'ok') return `  ${outcome.source}: ${outcome.findings} findings in ${seconds}s`;
  if (outcome.status === 'skipped') return `  ${outcome.source}: skipped, ${outcome.error}`;
  return `  ${outcome.source}: failed, ${outcome.error}`;
}

const ANSWER_LABEL: Record<string, string> = {
  exploitable: 'EXPLOITABLE',
  not_exploitable: 'NOT EXPLOITABLE',
  undetermined: 'UNDETERMINED',
};

export function renderTriageResult(result: TriageResult, style: Style): string {
  const finding = result.finding;
  const lines = [
    `${style.bold(finding.id)}  ${style.severity(finding.severity as Severity, finding.severity)}  ${finding.kind}  ${finding.tools.join(', ')}`,
    `  ${finding.title}${finding.location ? `  ${style.dim(locationOf(finding))}` : ''}`,
    '',
  ];

  if (result.status !== 'succeeded' || !result.exploitability) {
    const why = result.status === 'skipped_budget' ? 'the budget ran out' : 'the check failed';
    lines.push(`${style.bold('No answer')}: ${why}${result.error ? `, ${result.error}` : ''}.`);
  } else {
    const confidence = result.confidence === null ? '' : `  (confidence ${result.confidence.toFixed(2)})`;
    lines.push(`${style.bold(ANSWER_LABEL[result.exploitability] ?? result.exploitability)}${confidence}`);
    if (result.downgraded) lines.push(style.dim('  Downgraded because none of its citations matched the code.'));
    if (result.entryPoint) lines.push('', `${style.bold('Entry point')}: ${result.entryPoint}`);
    if (result.preconditions.length > 0) {
      lines.push('', style.bold('Preconditions'), ...result.preconditions.map((item) => `  - ${item}`));
    }
    if (result.rationale) lines.push('', style.bold('Why'), ...indent(result.rationale));
    if (result.evidence.length > 0) {
      lines.push('', style.bold('Evidence'));
      for (const item of result.evidence) {
        const span = item.endLine === item.startLine ? `${item.startLine}` : `${item.startLine}-${item.endLine}`;
        lines.push(`  ${item.path}:${span}`, ...item.quote.split('\n').slice(0, 6).map((line) => style.dim(`    ${line}`)));
      }
    }
    if (result.openQuestions.length > 0) {
      lines.push('', style.bold('Still open'), ...result.openQuestions.map((item) => `  - ${item}`));
    }
  }

  if (result.rejectedEvidence.length > 0) {
    const count = result.rejectedEvidence.length;
    lines.push('', style.dim(`${count} citation${count === 1 ? ' was' : 's were'} dropped because the code did not match.`));
  }
  lines.push('', style.dim(`Answered by ${result.model}.`), style.dim(usageLine(result)));
  return lines.join('\n');
}

export function usageLine(result: Pick<TriageResult, 'steps' | 'inputTokens' | 'outputTokens' | 'costUsd' | 'model'>): string {
  const tokens = `${result.inputTokens.toLocaleString('en-US')} input and ${result.outputTokens.toLocaleString('en-US')} output tokens`;
  const cost = result.costUsd > 0 ? `, $${result.costUsd.toFixed(2)}` : '';
  return `${result.steps} step${result.steps === 1 ? '' : 's'}, ${tokens}${cost}, ${result.model}`;
}

const FIX_LABEL: Record<FixStatus, string> = {
  fixed: 'Fixed',
  committed_unverified: 'Committed, not verified',
  unverified: 'Not committed, no scanner could verify it',
  failed: 'Not fixed',
  gave_up: 'Gave up',
  stopped_at_limit: 'Stopped at the limit',
  stopped_at_cap: 'Stopped at the batch cap',
  not_tried: 'Not tried',
  skipped: 'Skipped',
};

/** The result of `minotaur fix`: what happened to each finding, and where the commits are. */
export function renderFixRun(run: FixRun, base: string, style: Style, resume: string | null = null): string {
  const committed = run.results.filter((result) => result.commit !== null);
  const lines: string[] = [];
  for (const result of run.results) {
    const finding = result.finding;
    const label = FIX_LABEL[result.status];
    const colored = result.status === 'fixed' ? style.green(label) : result.commit ? style.yellow(label) : style.red(label);
    lines.push(
      `${style.bold(finding.id)}  ${style.severity(finding.severity as Severity, finding.severity)}  ${finding.title}${finding.location ? `  ${style.dim(locationOf(finding))}` : ''}`,
      `  ${colored}${result.commit ? ` in ${result.commit.slice(0, 7)}` : ''}${result.attempts > 1 ? style.dim(` after ${result.attempts} attempts`) : ''}`,
    );
    if (result.summary) lines.push(...indent(result.summary).map((line) => (line ? `  ${line}` : line)));
    if (result.error) lines.push(`    ${style.dim(result.error)}`);
    if (result.notes.length > 0 && result.commit) lines.push(`    ${style.bold('For the reviewer')}`, ...result.notes.map((note) => `      - ${note}`));
    if (result.steps > 0) lines.push(`    ${style.dim(usageLine(result))}`);
    lines.push('');
  }

  const total = run.results.length;
  const cost = run.results.reduce((sum, result) => sum + result.costUsd, 0);
  const done = `${committed.length} of ${total} finding${total === 1 ? '' : 's'} committed${cost > 0 ? `, $${cost.toFixed(2)}` : ''}`;
  if (run.branch) {
    lines.push(
      `${style.bold(done)} on branch ${style.bold(run.branch)}.`,
      style.dim(`Review: git log -p ${base.slice(0, 7)}..${run.branch}`),
      style.dim(`Merge:  git merge ${run.branch}`),
    );
  } else {
    lines.push(`${style.bold(done)}. No branch was kept.`);
  }
  if (run.alreadyOnBranch > 0) lines.push(style.dim(`${run.alreadyOnBranch} more ${run.alreadyOnBranch === 1 ? 'was' : 'were'} already fixed on the branch.`));
  if (run.stoppedAtCap) lines.push(style.yellow('Stopped at the spend cap for the run.'));
  if (run.interrupted) lines.push(style.yellow('Stopped with Ctrl-C before every finding was tried.'));
  if (resume) lines.push(`To continue, with the same options: ${resume}`);
  return lines.join('\n');
}

function ageOf(ms: number): string {
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 1) return 'less than a minute ago';
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  return `${Math.floor(hours / 24)} days ago`;
}

function indent(text: string): string[] {
  return text.split('\n').map((line) => (line.trim() ? `  ${line}` : ''));
}

export const findingsFileSchema = z.object({
  version: z.literal(1),
  root: z.string(),
  /** The commit scanned. Null or missing in files from before every run had a commit. */
  commit: z.string().nullable().default(null),
  findings: z.array(
    findingSchema.omit({ raw: true }).extend({
      id: z.string(),
      focus: focusSchema.optional(),
      focusReasons: z.array(z.string()).optional(),
      riskScore: z.number().optional(),
      epss: z.number().optional(),
      kev: z.boolean().optional(),
      decision: decisionSchema.optional(),
      /** True when the finding can be checked, or the reason it cannot. */
      triageable: z.union([z.literal(true), z.string()]).optional(),
      /** An earlier exploitability answer, or null when there is none. */
      check: z
        .object({
          exploitability: z.string(),
          confidence: z.number().nullable(),
          by: z.string(),
          age: z.string(),
        })
        .nullable()
        .optional(),
      /** A fix on a `minotaur/` branch that the scanned commit does not have yet, or null. */
      fix: z
        .object({ branch: z.string(), commit: z.string(), by: z.string().nullable(), verified: z.boolean() })
        .nullable()
        .optional(),
    }),
  ),
  /** Files with a detected secret, including ones whose finding was filtered out of `findings`. */
  protectedPaths: z.array(z.string()).default([]),
});
export type FindingsFile = z.infer<typeof findingsFileSchema>;

export interface RecordedCheck {
  exploitability: string;
  confidence: number | null;
  by: string;
  age: string;
}

/** A finding plus whether it can be checked, and any answer already on record. */
export type CheckedFinding = LocalFinding & {
  triageable: true | string;
  check: RecordedCheck | null;
};

/** Adds whether each finding can be checked, and any answer already on record. */
export function withChecks(
  findings: readonly LocalFinding[],
  protectedPaths: ReadonlySet<string>,
  checks: ReadonlyMap<string, { result: TriageResult; createdAt: number }>,
  now = Date.now(),
): CheckedFinding[] {
  return findings.map((finding) => {
    const cached = checks.get(finding.fingerprint);
    const answer = cached?.result.status === 'succeeded' ? cached.result.exploitability : null;
    return {
      ...finding,
      triageable: refusalFor(finding, protectedPaths) ?? true,
      check: answer
        ? { exploitability: answer, confidence: cached!.result.confidence, by: cached!.result.model, age: ageOf(now - cached!.createdAt) }
        : null,
    };
  });
}

export function toFindingsFile(
  root: string,
  commit: string,
  findings: readonly LocalFinding[],
  sources: readonly SourceOutcome[],
  protectedPaths: readonly string[],
) {
  return { version: 1 as const, root, commit, sources, protectedPaths, findings };
}

export async function readFindingsFile(
  path: string,
): Promise<{ findings: LocalFinding[]; protectedPaths: string[]; commit: string | null }> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(`could not read ${path}: ${(error as Error).message}`);
  }
  const parsed = findingsFileSchema.safeParse(raw);
  if (!parsed.success) throw new Error(`${path} is not the JSON output of "minotaur scan --json"`);
  return { findings: parsed.data.findings, protectedPaths: parsed.data.protectedPaths, commit: parsed.data.commit };
}
