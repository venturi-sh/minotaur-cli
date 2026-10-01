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

/** One line for the footer while the scan runs: what it is doing and how far along it is. */
export function scanLabel(state: ScanState): string {
  const finished = state.sources.filter((row) => row.outcome).length;
  const count = `${finished} of ${state.sources.length} sources done`;
  const running = state.sources.find((row) => row.status === 'running');
  if (running) return `scanning with ${running.name} · ${count}`;
  if (state.step) return state.step;
  return state.sources.length > 0 ? count : 'Preparing the scan';
}
