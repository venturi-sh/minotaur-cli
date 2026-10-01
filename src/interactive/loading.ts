/**
 * How far the scan behind the list has got: each source with its state, plus
 * downloads and the steps before and after the scan. The list shows the
 * findings as they come in, with this in its footer.
 */

import type { LocalFinding, SourceOutcome } from '../sources.js';

/** The findings so far, rated and with the decisions applied. */
export interface Found {
  findings: readonly LocalFinding[];
  ignored: number;
  protectedPaths: ReadonlySet<string>;
}

/** How gathering the findings reports progress. */
export interface ScanReporter {
  /** Something that takes a moment and is not a source, such as working out which scanners apply. */
  step(text: string): void;
  sources(names: readonly string[]): void;
  start(name: string): void;
  done(outcome: SourceOutcome): void;
  /** Something worth reading that is not an error, such as a download. */
  note(text: string): void;
  /** The findings so far, each time a source adds some. */
  found?(found: Found): void;
}

export interface SourceRow {
  name: string;
  status: 'waiting' | 'running' | SourceOutcome['status'];
  startedAt?: number;
  outcome?: SourceOutcome;
}

export interface ScanState {
  step: string | null;
  sources: SourceRow[];
  notes: string[];
}

export type ScanEvent =
  | { type: 'step'; text: string }
  | { type: 'sources'; names: readonly string[] }
  | { type: 'start'; name: string; at: number }
  | { type: 'done'; outcome: SourceOutcome }
  | { type: 'note'; text: string };

export const INITIAL_SCAN: ScanState = { step: 'Getting ready', sources: [], notes: [] };

export function applyScanEvent(state: ScanState, event: ScanEvent): ScanState {
  switch (event.type) {
    case 'step':
      return { ...state, step: event.text };
    case 'sources':
      return { ...state, step: null, sources: event.names.map((name) => ({ name, status: 'waiting' })) };
    case 'start':
      return { ...state, step: null, sources: state.sources.map((row) => (row.name === event.name ? { ...row, status: 'running', startedAt: event.at } : row)) };
    case 'done':
      return {
        ...state,
        sources: state.sources.map((row) => (row.name === event.outcome.source ? { ...row, status: event.outcome.status, outcome: event.outcome } : row)),
      };
    case 'note':
      return { ...state, notes: [...state.notes, event.text].slice(-4) };
  }
}

/** One line for the footer when there is no room for a row per scanner. */
export function scanLabel(state: ScanState): string {
  const finished = state.sources.filter((row) => row.outcome).length;
  const count = `${finished} of ${state.sources.length} sources done`;
  const running = state.sources.find((row) => row.status === 'running');
  if (running) return `scanning with ${running.name} · ${count}`;
  if (state.step) return state.step;
  return state.sources.length > 0 ? count : 'Preparing the scan';
}

/** One scanner, or the step before any scanner has been chosen. */
export interface ScanLine {
  name: string;
  status: SourceRow['status'];
  detail: string;
}

/** How many rows the scanner list needs, including a step that is still going after the scanners. */
export function scanLineCount(state: ScanState): number {
  if (state.sources.length === 0) return 1;
  const busy = state.sources.some((row) => row.status === 'running');
  return state.sources.length + (state.step && !busy ? 1 : 0);
}

/**
 * Every scanner in run order: done, the one running, then the ones still to
 * come. `now` is only used for how long the running scanner has been going.
 */
export function scanLines(state: ScanState, now = Date.now()): ScanLine[] {
  if (state.sources.length === 0) return [{ name: '', status: 'running', detail: state.step ?? 'Preparing the scan' }];
  const lines = state.sources.map((row) => ({ name: row.name, status: row.status, detail: sourceDetail(row, now) }));
  if (state.step && !state.sources.some((row) => row.status === 'running')) {
    lines.push({ name: '', status: 'running', detail: state.step });
  }
  return lines;
}

/** The rows that fit, keeping the running scanner on screen. */
export function windowScanLines(lines: readonly ScanLine[], limit: number): ScanLine[] {
  if (limit <= 0) return [];
  if (lines.length <= limit) return [...lines];
  const running = lines.findLastIndex((line) => line.status === 'running');
  const start = Math.max(0, Math.min(running === -1 ? 0 : running, lines.length - limit));
  return lines.slice(start, start + limit);
}

function sourceDetail(row: SourceRow, now: number): string {
  if (row.status === 'waiting') return 'next';
  if (row.status === 'running') {
    const elapsed = row.startedAt === undefined ? '' : ` · ${formatDuration(now - row.startedAt)}`;
    return `running${elapsed}`;
  }
  const outcome = row.outcome;
  if (!outcome) return row.status;
  if (outcome.status === 'ok') return `done · ${findingCount(outcome.findings)} · ${formatDuration(outcome.durationMs)}`;
  const label = outcome.status === 'skipped' ? 'skipped' : 'failed';
  return outcome.error ? `${label} · ${outcome.error}` : label;
}

function findingCount(count: number): string {
  if (count === 0) return 'nothing found';
  return `${count} finding${count === 1 ? '' : 's'}`;
}

function formatDuration(ms: number): string {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  if (minutes < 60) return rest === 0 ? `${minutes}m` : `${minutes}m ${rest}s`;
  const hours = Math.floor(minutes / 60);
  const min = minutes % 60;
  return min === 0 ? `${hours}h` : `${hours}h ${min}m`;
}
