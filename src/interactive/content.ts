/**
 * What the interactive view shows, as plain data: styled lines already
 * wrapped to the width they will be drawn at, and the space each part gets.
 * Kept apart from the Ink components so it can be tested without a terminal.
 */

import type { Focus, Severity } from '../core/index.js';

import { locationOf, toolsOf } from '../output.js';
import { DECISION_LABEL, type Decision } from '../decisions.js';
import type { LocalFinding } from '../sources.js';
import type { TriageResult } from '../triage.js';
import { MARK_KEYS, queuePosition, refusalOf, visibleFindings, type BrowserState, type FixView, type Marking, type Question } from './state.js';

export interface Segment {
  text: string;
  color?: string;
  backgroundColor?: string;
  bold?: boolean;
  dim?: boolean;
}

/** One terminal line of the detail page. Progress lines are drawn with live components. */
export type Line = { segments: Segment[] } | { spinner: string } | { progress: number };

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'redBright',
  high: 'red',
  medium: 'yellow',
  low: 'blue',
  info: 'gray',
  unknown: 'gray',
};

export const ACCENT = 'magenta';

/** Rows and columns for each part of the screen. */
export interface Layout {
  /** Inner width of the bordered panel. */
  inner: number;
  /** Rows inside the panel, below the list's column header in the list view. */
  body: number;
  message: string[];
}

export function layoutFor(state: BrowserState, columns: number, rows: number): Layout {
  const message = state.message ? wrap(state.message, Math.max(10, columns - 2)).slice(0, 6) : [];
  // Title, panel border, footer, and the column header in the list.
  const chrome = 1 + 2 + 1 + (state.view === 'list' ? 1 : 0);
  return { inner: Math.max(10, columns - 4), body: Math.max(1, rows - chrome - message.length), message };
}

export interface CheckLabel {
  text: string;
  color?: string;
  bold?: boolean;
  dim?: boolean;
  running?: boolean;
}

export function checkLabel(state: BrowserState, finding: LocalFinding): CheckLabel {
  if (state.running?.fingerprint === finding.fingerprint) return { text: 'checking', color: ACCENT, running: true };
  const position = queuePosition(state, finding);
  if (position !== null) return { text: `◷ queued #${position}`, color: ACCENT, dim: true };
  // A person's decision outranks the model's answer.
  if (finding.decision?.state === 'confirmed') return { text: '● confirmed', color: 'red', bold: true };
  if (finding.decision) return { text: `✓ ${DECISION_LABEL[finding.decision.state]}`, color: 'green', dim: true };
  const result = state.results.get(finding.fingerprint);
  if (!result) return { text: '' };
  if (result.status !== 'succeeded') return { text: '· no answer', dim: true };
  if (result.exploitability === 'exploitable') return { text: '▲ exploitable', color: 'red', bold: true };
  if (result.exploitability === 'not_exploitable') return { text: '✓ not exploitable', color: 'green' };
  return { text: '? unsure', color: 'yellow' };
}

/** Findings per severity, worst first, for the title bar. */
export function severityCounts(findings: readonly LocalFinding[]): Array<{ severity: Severity; count: number }> {
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  return order
    .map((severity) => ({ severity, count: findings.filter((finding) => finding.severity === severity).length }))
    .filter((entry) => entry.count > 0);
}

const text = (value: string, style: Omit<Segment, 'text'> = {}): Line => ({ segments: [{ text: value, ...style }] });
const blank: Line = { segments: [] };

export const FOCUS_LABEL: Record<Focus, string> = { likely: 'likely an issue', maybe: 'worth a look', noise: 'likely noise' };

/** "false positive, by Arno on 2026-09-29: the key is a test fixture". */
export function describeDecision(decision: Decision): string {
  const who = [decision.by ? `by ${decision.by}` : '', decision.at ? `on ${decision.at}` : ''].filter(Boolean).join(' ');
  return `${DECISION_LABEL[decision.state]}${who ? `, ${who}` : ''}${decision.reason ? `: ${decision.reason}` : ''}`;
}

/** The prompt that replaces the key hints while a finding is being marked. */
export function markingPrompt(marking: Marking): Segment[] {
  if (!marking.state) {
    return [
      { text: `Mark ${marking.finding.id} as  `, bold: true },
      ...MARK_KEYS.flatMap(([letter, state]): Segment[] => [
        { text: letter, bold: true, color: ACCENT },
        { text: ` ${state === 'open' ? 'open (undo)' : DECISION_LABEL[state]}   `, dim: true },
      ]),
      { text: 'esc', bold: true, color: ACCENT },
      { text: ' cancel', dim: true },
    ];
  }
  return [
    { text: `Why ${DECISION_LABEL[marking.state]}? `, bold: true },
    { text: marking.reason },
    { text: '▌', color: ACCENT },
    { text: '   enter saves, esc cancels', dim: true },
  ];
}

/** The whole detail page for the selected finding, before scrolling. */
export function detailLines(state: BrowserState, width: number): Line[] {
  const finding = visibleFindings(state)[state.cursor];
  if (!finding) return [];
  const lines: Line[] = [];
  const para = (value: string, style: Omit<Segment, 'text'> = {}, indent = '') => {
    for (const line of wrap(value, width, indent)) lines.push(text(line, style));
  };
  const field = (label: string, value: string) => {
    const [first = '', ...rest] = wrap(value, Math.max(10, width - 12));
    lines.push({ segments: [{ text: label.padEnd(12), dim: true }, { text: first }] });
    for (const line of rest) lines.push(text(`${' '.repeat(12)}${line}`));
  };
  const section = (title: string) => {
    lines.push(blank, { segments: [{ text: title, bold: true, color: ACCENT }, { text: ` ${'─'.repeat(Math.max(0, width - title.length - 1))}`, dim: true }] });
  };
  const quote = (value: string, max: number) => {
    for (const line of value.split('\n').slice(0, max)) {
      lines.push({ segments: [{ text: '  │ ', dim: true }, { text: line.slice(0, Math.max(0, width - 4)), dim: true }] });
    }
  };

  lines.push({
    segments: [
      { text: ` ${finding.severity.toUpperCase()} `, backgroundColor: SEVERITY_COLOR[finding.severity], color: 'black', bold: true },
      { text: `  ${finding.kind} · ${toolsOf(finding)} · `, dim: true },
      { text: finding.id, dim: true },
    ],
  });
  lines.push(blank);
  para(finding.title, { bold: true });
  if (finding.location) para(locationOf(finding), { color: 'cyan' });
  lines.push(blank);
  if (finding.decision) field('Decision', describeDecision(finding.decision));
  if (finding.focus) field('Focus', `${FOCUS_LABEL[finding.focus]}: ${(finding.focusReasons ?? []).join('; ')}`);
  if (finding.ruleId) field('Rule', finding.ruleId);
  if (finding.vulnerabilityIds.length > 0) field('Identifiers', finding.vulnerabilityIds.join(', '));
  if (finding.package) {
    const version = finding.package.version ? ` ${finding.package.version}` : '';
    const fixed = finding.package.fixedVersion ? `, fixed in ${finding.package.fixedVersion}` : ', no fixed version';
    field('Package', `${finding.package.name}${version}${fixed}`);
  }
  if (finding.description) {
    lines.push(blank);
    para(finding.description);
  }
  if (finding.location?.snippet && finding.kind !== 'secret') {
    section('Code');
    quote(finding.location.snippet, 12);
  }
  if (finding.references.length > 0) {
    section('References');
    for (const reference of finding.references.slice(0, 3)) lines.push(text(`  • ${reference}`.slice(0, width), { dim: true }));
  }

  section('Exploitability');
  lines.push(...exploitabilityLines(state, finding, width));

  const fixing = state.fixing?.current === finding.id ? state.fixing : null;
  const fix = state.fixes.get(finding.fingerprint);
  if (fixing || fix) {
    section('Fix');
    if (fixing) lines.push({ spinner: `${fixing.phase}${fixing.steps > 0 ? ` · step ${fixing.steps}` : ''}${fixing.costUsd > 0 ? ` · $${fixing.costUsd.toFixed(2)}` : ''}` });
    else if (fix) addFix(fix, width, lines, para, field);
  }
  return lines;
}

export const FIX_LABEL: Record<FixView['status'], { text: string; color: string }> = {
  fixed: { text: 'Fixed', color: 'green' },
  committed_unverified: { text: 'Committed, not verified', color: 'yellow' },
  unverified: { text: 'Not committed: no scanner could verify it', color: 'yellow' },
  failed: { text: 'Not fixed', color: 'red' },
  gave_up: { text: 'Gave up', color: 'red' },
  stopped_at_limit: { text: 'Stopped at the limit', color: 'red' },
  stopped_at_cap: { text: 'Stopped at the batch cap', color: 'yellow' },
  not_tried: { text: 'Not tried', color: 'gray' },
  skipped: { text: 'Skipped', color: 'gray' },
};

/**
 * The FIX column. Kept apart from the check: a finding can be checked and
 * fixed, or only one of them, in either order.
 */
export function fixLabel(state: BrowserState, finding: LocalFinding): CheckLabel {
  if (state.fixing?.current === finding.id) return { text: 'fixing', color: ACCENT, running: true };
  const fix = state.fixes.get(finding.fingerprint);
  if (!fix) return { text: '' };
  switch (fix.status) {
    case 'fixed':
      return { text: '⎇ on branch', color: 'green', bold: true };
    case 'committed_unverified':
      return { text: '⎇ unverified', color: 'yellow' };
    case 'unverified':
      return { text: '? not verified', color: 'yellow' };
    case 'skipped':
      return { text: "– can't fix", dim: true };
    case 'not_tried':
    case 'stopped_at_cap':
      return { text: '· not tried', dim: true };
    default:
      return { text: '✗ not fixed', color: 'red' };
  }
}

/** The outcome, where the commit is, and the patch with its added and removed lines colored. Added to `lines`. */
function addFix(
  fix: FixView,
  width: number,
  lines: Line[],
  para: (value: string, style?: Omit<Segment, 'text'>, indent?: string) => void,
  field: (label: string, value: string) => void,
): void {
  const label = FIX_LABEL[fix.status];
  lines.push({ segments: [{ text: label.text, bold: true, color: label.color }] });
  if (fix.branch) field('Branch', fix.branch);
  if (fix.commit) field('Commit', fix.commit.slice(0, 12));
  if (fix.summary) para(fix.summary);
  for (const note of fix.notes) para(`• ${note}`, { dim: true }, '  ');
  if (fix.error) para(fix.error, { color: 'red' });
  if (!fix.diff) return;
  lines.push(blank);
  const patch = fix.diff.split('\n');
  for (const line of patch.slice(0, 400)) {
    const color = line.startsWith('+') && !line.startsWith('+++') ? 'green' : line.startsWith('-') && !line.startsWith('---') ? 'red' : line.startsWith('@@') ? 'cyan' : undefined;
    lines.push({ segments: [{ text: line.slice(0, width), ...(color ? { color } : { dim: true }) }] });
  }
  if (patch.length > 400) lines.push(text(`… ${patch.length - 400} more lines; git show ${fix.commit?.slice(0, 12) ?? ''}`, { dim: true }));
}

/** The yes-or-no question in the footer. */
export function questionPrompt(question: Question): Segment[] {
  const ask = (words: string): Segment[] => [
    { text: words, bold: true },
    { text: '  y', bold: true, color: ACCENT },
    { text: ' yes   ', dim: true },
    { text: 'any other key', bold: true, color: ACCENT },
    { text: ' no', dim: true },
  ];
  if (question.kind === 'batch') {
    const count = question.findings.length;
    return ask(`Fix ${count === 1 ? 'the 1 finding' : `all ${count} findings`} shown, one commit each on one branch?`);
  }
  return [
    { text: `Spent $${question.spentUsd.toFixed(2)} of $${question.capUsd.toFixed(2)}: ${question.fixed} fixed, ${question.notFixed} not, ${question.remaining} to go.  `, dim: true },
    ...ask(`Continue ${question.current} and spend up to as much again?`),
  ];
}

function exploitabilityLines(state: BrowserState, finding: LocalFinding, width: number): Line[] {
  const lines: Line[] = [];
  const para = (value: string, style: Omit<Segment, 'text'> = {}, indent = '') => {
    for (const line of wrap(value, width, indent)) lines.push(text(line, style));
  };

  const running = state.running?.fingerprint === finding.fingerprint ? state.running : null;
  if (running) {
    const cost = running.costUsd > 0 ? ` · $${running.costUsd.toFixed(2)}` : '';
    lines.push({ spinner: `Checking, step ${running.steps} of at most ${running.maxSteps} · ${running.tokens.toLocaleString('en-US')} tokens${cost}` });
    lines.push({ progress: Math.min(100, (running.steps / Math.max(1, running.maxSteps)) * 100) });
    for (const path of running.filesRead) lines.push(text(`  looked at ${path}`.slice(0, width), { dim: true }));
    lines.push(blank, text('Ctrl+C stops the check.', { dim: true }));
    return lines;
  }

  const position = queuePosition(state, finding);
  if (position !== null) {
    const ahead = position === 1 ? 'It runs when the current check finishes.' : `${position - 1} other checks run before it.`;
    lines.push({ segments: [{ text: ` QUEUED #${position} `, backgroundColor: ACCENT, color: 'black', bold: true }] });
    para(`${ahead} Press t to take it out of the queue.`, { dim: true });
    const earlier = state.results.get(finding.fingerprint);
    if (!earlier) return lines;
    lines.push({ segments: [] }, text('The earlier check, until the new one finishes:', { dim: true }), { segments: [] });
    return [...lines, ...resultLines(earlier, width)];
  }

  const result = state.results.get(finding.fingerprint);
  if (result) return [...lines, ...resultLines(result, width)];

  const refusal = refusalOf(state, finding);
  if (refusal) {
    para(`This finding can't be checked: ${refusal}.`, { color: 'yellow' });
    return lines;
  }
  if (!state.model.ok) {
    para('Triage is not set up yet.', { color: 'yellow', bold: true });
    para(state.model.error, {}, '  ');
    return lines;
  }
  lines.push({ segments: [{ text: 'Not checked yet. Press ' }, { text: 't', bold: true, color: ACCENT }, { text: ' to ask the model whether an attacker can reach and trigger this.' }] });
  para(`Code is sent to ${state.model.destination}. Limits: ${state.model.limits}.`, { dim: true });
  return lines;
}

const VERDICT: Record<string, { label: string; color: string }> = {
  exploitable: { label: 'EXPLOITABLE', color: 'red' },
  not_exploitable: { label: 'NOT EXPLOITABLE', color: 'green' },
  undetermined: { label: 'UNDETERMINED', color: 'yellow' },
};

export function resultLines(result: TriageResult, width: number): Line[] {
  const lines: Line[] = [];
  const para = (value: string, style: Omit<Segment, 'text'> = {}, indent = '') => {
    for (const line of wrap(value, width, indent)) lines.push(text(line, style));
  };
  const heading = (title: string) => lines.push(blank, text(title, { bold: true }));

  if (result.status !== 'succeeded' || !result.exploitability) {
    const why = result.status === 'skipped_budget' ? 'the budget ran out' : 'the check failed';
    lines.push({ segments: [{ text: ' NO ANSWER ', backgroundColor: 'gray', color: 'black', bold: true }, { text: `  ${why}` }] });
    if (result.error) para(result.error, { dim: true }, '  ');
  } else {
    const verdict = VERDICT[result.exploitability] ?? { label: result.exploitability, color: 'gray' };
    const confidence = result.confidence === null ? '' : `  confidence ${Math.round(result.confidence * 100)}%`;
    lines.push({ segments: [{ text: ` ${verdict.label} `, backgroundColor: verdict.color, color: 'black', bold: true }, { text: confidence, dim: true }] });
    if (result.downgraded) para('Downgraded because none of its citations matched the code.', { dim: true });
    if (result.entryPoint) {
      heading('Entry point');
      para(result.entryPoint, {}, '  ');
    }
    if (result.preconditions.length > 0) {
      heading('Preconditions');
      for (const item of result.preconditions) para(`• ${item}`, {}, '  ');
    }
    if (result.rationale) {
      heading('Why');
      para(result.rationale, {}, '  ');
    }
    if (result.evidence.length > 0) {
      heading('Evidence');
      for (const item of result.evidence) {
        const span = item.endLine === item.startLine ? `${item.startLine}` : `${item.startLine}-${item.endLine}`;
        lines.push(text(`  ${item.path}:${span}`, { color: 'cyan' }));
        for (const line of item.quote.split('\n').slice(0, 6)) {
          lines.push({ segments: [{ text: '  │ ', dim: true }, { text: line.slice(0, Math.max(0, width - 4)), dim: true }] });
        }
      }
    }
    if (result.openQuestions.length > 0) {
      heading('Still open');
      for (const item of result.openQuestions) para(`• ${item}`, {}, '  ');
    }
  }

  if (result.rejectedEvidence.length > 0) {
    const count = result.rejectedEvidence.length;
    lines.push(blank);
    para(`${count} citation${count === 1 ? ' was' : 's were'} dropped because the code did not match.`, { dim: true });
  }
  para(`Answered by ${result.model}.`, { dim: true });
  const tokens = `${result.inputTokens.toLocaleString('en-US')} in / ${result.outputTokens.toLocaleString('en-US')} out tokens`;
  const cost = result.costUsd > 0 ? ` · $${result.costUsd.toFixed(2)}` : '';
  lines.push(blank);
  para(`${result.steps} step${result.steps === 1 ? '' : 's'} · ${tokens}${cost} · ${result.model}`, { dim: true });
  if (result.status === 'succeeded') {
    lines.push({
      segments: [
        { text: 'Press ', dim: true },
        { text: 'd', bold: true, color: ACCENT },
        { text: ' to dig deeper from this answer, or ', dim: true },
        { text: 't', bold: true, color: ACCENT },
        { text: ' to start over.', dim: true },
      ],
    });
  }
  return lines;
}

/** Word-wraps plain text to `width`. Each line starts with `indent` plus the paragraph's own indentation. */
export function wrap(value: string, width: number, baseIndent = ''): string[] {
  const out: string[] = [];
  for (const paragraph of value.split('\n')) {
    if (paragraph.trim() === '') {
      out.push('');
      continue;
    }
    const indent = baseIndent + (/^\s*/.exec(paragraph)?.[0] ?? '');
    const room = Math.max(10, width - indent.length);
    let line = '';
    for (const word of paragraph.trim().split(/\s+/)) {
      let rest = word;
      while (rest.length > room) {
        if (line) out.push(indent + line);
        line = '';
        out.push(indent + rest.slice(0, room));
        rest = rest.slice(room);
      }
      if (!rest) continue;
      if (line && line.length + 1 + rest.length > room) {
        out.push(indent + line);
        line = rest;
      } else {
        line = line ? `${line} ${rest}` : rest;
      }
    }
    if (line) out.push(indent + line);
  }
  return out;
}

/** Plain text of a line, for tests and width checks. */
export function lineText(line: Line): string {
  if ('spinner' in line) return line.spinner;
  if ('progress' in line) return '';
  return line.segments.map((segment) => segment.text).join('');
}
