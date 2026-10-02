/**
 * What the interactive view shows and how keys change it. Pure, so every key
 * can be tested without a terminal; anything with a side effect is returned
 * as an effect for the app to carry out.
 */

import { severityRank, type Severity } from '../core/index.js';

import { isClosed, type DecisionState } from '../decisions.js';
import type { LocalFinding } from '../sources.js';
import { refusalFor, type TriageResult } from '../triage.js';

export interface Running {
  fingerprint: string;
  steps: number;
  maxSteps: number;
  tokens: number;
  costUsd: number;
  filesRead: string[];
}

/** What the model setup allows: where code would go, or why triage cannot run. */
export type ModelStatus = { ok: true; destination: string; limits: string } | { ok: false; error: string };

export interface BrowserState {
  root: string;
  /** The commit looked at, for the header. */
  commit: string | null;
  findings: readonly LocalFinding[];
  ignored: number;
  /** Files with a detected secret, which are never sent to the model. */
  protectedPaths: ReadonlySet<string>;
  model: ModelStatus;
  minSeverity: Severity | null;
  /** Findings rated as noise are left out of the list unless this is set. */
  showNoise: boolean;
  view: 'list' | 'detail';
  /** Index into the visible findings. */
  cursor: number;
  /** First visible row of the list. */
  top: number;
  detailScroll: number;
  results: ReadonlyMap<string, TriageResult>;
  running: Running | null;
  /** Checks waiting for the running one to finish, in the order they run. */
  queue: readonly QueuedCheck[];
  /** Set while the person picks a decision for a finding, then types the reason. */
  marking: Marking | null;
  message: string | null;
  /** Set while the scan runs: the list fills in as sources finish, and nothing that needs the whole scan can start. */
  scanning: boolean;
}

export interface Marking {
  finding: LocalFinding;
  /** Null until a state is picked. */
  state: DecisionState | null;
  reason: string;
}

/** The key that picks each decision, in the order the prompt lists them. */
export const MARK_KEYS: ReadonlyArray<[string, DecisionState | 'open']> = [
  ['f', 'false_positive'],
  ['a', 'accepted_risk'],
  ['x', 'fixed'],
  ['c', 'confirmed'],
  ['o', 'open'],
];

export interface QueuedCheck {
  finding: LocalFinding;
  continueFrom?: TriageResult;
}

export interface Key {
  name?: string | undefined;
  sequence?: string | undefined;
  ctrl?: boolean | undefined;
}

export type Effect =
  | { type: 'quit' }
  | { type: 'triage'; finding: LocalFinding; continueFrom?: TriageResult }
  | { type: 'cancel' }
  | { type: 'rescan' }
  | { type: 'decide'; finding: LocalFinding; state: DecisionState | 'open'; reason: string };

export interface Update {
  state: BrowserState;
  effect?: Effect;
}

/** Lowest severity first, so pressing the key raises the bar one step at a time. */
const SEVERITY_STEPS: readonly (Severity | null)[] = [null, 'low', 'medium', 'high', 'critical'];

export function initialState(options: {
  root: string;
  commit?: string | null | undefined;
  findings: readonly LocalFinding[];
  ignored: number;
  protectedPaths: ReadonlySet<string>;
  model: ModelStatus;
  results?: ReadonlyMap<string, TriageResult> | undefined;
  message?: string | null | undefined;
  scanning?: boolean | undefined;
}): BrowserState {
  return {
    root: options.root,
    commit: options.commit ?? null,
    findings: options.findings,
    ignored: options.ignored,
    protectedPaths: options.protectedPaths,
    model: options.model,
    minSeverity: null,
    showNoise: false,
    view: 'list',
    cursor: 0,
    top: 0,
    detailScroll: 0,
    results: new Map(options.results ?? []),
    running: null,
    queue: [],
    marking: null,
    message: options.message ?? null,
    scanning: options.scanning ?? false,
  };
}

export function visibleFindings(state: BrowserState): readonly LocalFinding[] {
  const minimum = state.minSeverity;
  if (!minimum && state.showNoise) return state.findings;
  return state.findings.filter(
    (finding) => (state.showNoise || !hiddenByDefault(finding)) && (!minimum || severityRank(finding.severity) >= severityRank(minimum)),
  );
}

/** Likely noise, or marked a false positive, accepted risk or fixed. */
function hiddenByDefault(finding: LocalFinding): boolean {
  return finding.focus === 'noise' || isClosed(finding);
}

/** Findings the list leaves out until `a` is pressed. */
export function hiddenCount(state: BrowserState): number {
  return state.findings.filter(hiddenByDefault).length;
}

export function selectedFinding(state: BrowserState): LocalFinding | undefined {
  return visibleFindings(state)[state.cursor];
}

/** Why a finding can never be sent to the model, or null. */
export function refusalOf(state: BrowserState, finding: LocalFinding): string | null {
  return refusalFor(finding, state.protectedPaths);
}

/** `pageSize` is how many list rows fit on screen. */
export function handleKey(state: BrowserState, key: Key, pageSize: number): Update {
  const cleared = state.message ? { ...state, message: null } : state;
  if (state.marking) return markKey(cleared, state.marking, key);
  if (state.scanning) {
    const waiting = whileScanning(state, key);
    if (waiting) return { state: { ...cleared, message: waiting } };
  }
  if (key.ctrl && key.name === 'c') {
    if (!state.running) return quit(cleared);
    const waiting = state.queue.length;
    const message = waiting > 0 ? `Stopping the check and clearing ${waiting} queued…` : 'Stopping the check…';
    return { state: { ...cleared, queue: [], message }, effect: { type: 'cancel' } };
  }
  return state.view === 'list' ? listKey(cleared, key, pageSize) : detailKey(cleared, key, pageSize);
}

function listKey(state: BrowserState, key: Key, pageSize: number): Update {
  switch (key.name ?? key.sequence) {
    case 'up':
    case 'k':
      return { state: move(state, -1) };
    case 'down':
    case 'j':
      return { state: move(state, 1) };
    case 'pageup':
      return { state: move(state, -Math.max(1, pageSize - 1)) };
    case 'pagedown':
    case 'space':
      return { state: move(state, Math.max(1, pageSize - 1)) };
    case 'home':
    case 'g':
      return { state: move(state, -Infinity) };
    case 'end':
      return { state: move(state, Infinity) };
    case 'return':
    case 'enter':
    case 'right':
    case 'l':
      return selectedFinding(state) ? { state: { ...state, view: 'detail', detailScroll: 0 } } : { state };
    case 't':
      return startTriage(state, false);
    case 's':
      return { state: cycleSeverity(state) };
    case 'a':
      return { state: toggleNoise(state) };
    case 'r':
      return rescan(state);
    case 'm':
      return startMarking(state);
    case 'q':
    case 'escape':
      return quit(state);
    default:
      return key.sequence === 'G' ? { state: move(state, Infinity) } : { state };
  }
}

function detailKey(state: BrowserState, key: Key, pageSize: number): Update {
  switch (key.name ?? key.sequence) {
    case 'up':
    case 'k':
      return { state: { ...state, detailScroll: Math.max(0, state.detailScroll - 1) } };
    case 'down':
    case 'j':
      return { state: { ...state, detailScroll: state.detailScroll + 1 } };
    case 'pageup':
      return { state: { ...state, detailScroll: Math.max(0, state.detailScroll - pageSize) } };
    case 'pagedown':
    case 'space':
      return { state: { ...state, detailScroll: state.detailScroll + pageSize } };
    case 'escape':
    case 'left':
    case 'h':
    case 'backspace':
      return { state: { ...state, view: 'list' } };
    case 'q':
      return quit(state);
    case 't':
      return startTriage(state, false);
    case 'd':
      return startTriage(state, true);
    case 'm':
      return startMarking(state);
    default:
      if (key.sequence === ']') return { state: { ...move(state, 1), detailScroll: 0 } };
      if (key.sequence === '[') return { state: { ...move(state, -1), detailScroll: 0 } };
      return { state };
  }
}

function move(state: BrowserState, by: number): BrowserState {
  const count = visibleFindings(state).length;
  if (count === 0) return state;
  const cursor = Math.min(count - 1, Math.max(0, state.cursor + by));
  return cursor === state.cursor ? state : { ...state, cursor };
}

function cycleSeverity(state: BrowserState): BrowserState {
  const index = SEVERITY_STEPS.indexOf(state.minSeverity);
  const minSeverity = SEVERITY_STEPS[(index + 1) % SEVERITY_STEPS.length] ?? null;
  return refilter(state, { ...state, minSeverity, top: 0 });
}

function toggleNoise(state: BrowserState): BrowserState {
  const count = hiddenCount(state);
  if (count === 0) return { ...state, message: 'No finding is rated as noise or marked closed.' };
  const showNoise = !state.showNoise;
  const what = `${count} finding${count === 1 ? '' : 's'} rated as noise or marked false positive, accepted risk or fixed`;
  const message = showNoise ? `Showing ${what}. Press a to hide them again.` : `Hiding ${what}.`;
  return refilter(state, { ...state, showNoise, top: 0, message });
}

function startMarking(state: BrowserState): Update {
  const finding = selectedFinding(state);
  return finding ? { state: { ...state, marking: { finding, state: null, reason: '' } } } : { state };
}

/** While marking, every key belongs to the prompt: first the decision, then the reason. */
function markKey(state: BrowserState, marking: Marking, key: Key): Update {
  const name = key.name ?? key.sequence;
  if (name === 'escape' || (key.ctrl && key.name === 'c')) return { state: { ...state, marking: null, message: 'Nothing was marked.' } };
  const done = (decision: DecisionState | 'open', reason: string): Update => ({
    state: { ...state, marking: null },
    effect: { type: 'decide', finding: marking.finding, state: decision, reason },
  });

  if (!marking.state) {
    const picked = MARK_KEYS.find(([letter]) => letter === name)?.[1];
    if (!picked) return { state };
    if (picked === 'open') return done('open', '');
    return { state: { ...state, marking: { ...marking, state: picked } } };
  }
  if (name === 'return' || name === 'enter') return done(marking.state, marking.reason.trim());
  if (name === 'backspace') return { state: { ...state, marking: { ...marking, reason: marking.reason.slice(0, -1) } } };
  // Arrows and other named keys do nothing here; a paste arrives as one sequence.
  const typed = name === 'space' ? ' ' : key.name ? '' : (key.sequence ?? '').replace(/[\u0000-\u001f\u007f]/g, '');
  if (!typed) return { state };
  return { state: { ...state, marking: { ...marking, reason: (marking.reason + typed).slice(0, 2000) } } };
}

/**
 * Why a key has to wait for the scan, or null. Checks and marks need every
 * source in: until the secret scanner has run, the files a check must never
 * read are not known yet.
 */
function whileScanning(state: BrowserState, key: Key): string | null {
  const name = key.name ?? key.sequence;
  if (name === 'r') return 'A scan is already running.';
  const waits = ['t', 'm', ...(state.view === 'detail' ? ['d'] : [])];
  if (name && waits.includes(name)) return 'Still scanning. Checks and marks can start once the scan finishes.';
  return null;
}

/** The list after a decision changed the findings: on the same finding when it is still shown. */
export function withFindings(
  state: BrowserState,
  findings: readonly LocalFinding[],
  protectedPaths: ReadonlySet<string>,
  message: string,
): BrowserState {
  const selected = selectedFinding(state)?.fingerprint;
  const after = { ...state, findings, protectedPaths, message };
  const index = visibleFindings(after).findIndex((finding) => finding.fingerprint === selected);
  const count = visibleFindings(after).length;
  const cursor = index !== -1 ? index : Math.min(state.cursor, Math.max(0, count - 1));
  return { ...after, cursor, view: index === -1 ? 'list' : state.view };
}

/** The list as the scan fills it in: on the same finding when it is still shown, and with any message left as it is. */
export function withScanned(
  state: BrowserState,
  scanned: { findings: readonly LocalFinding[]; ignored: number; protectedPaths: ReadonlySet<string> },
): BrowserState {
  const { message } = state;
  return { ...withFindings(state, scanned.findings, scanned.protectedPaths, ''), ignored: scanned.ignored, message };
}

/** Stays on the same finding when the new filter still shows it. */
function refilter(before: BrowserState, after: BrowserState): BrowserState {
  const selected = selectedFinding(before);
  const kept = selected ? visibleFindings(after).indexOf(selected) : -1;
  return { ...after, cursor: Math.max(0, kept) };
}

/** Starts a check of the selected finding, or queues it behind the running one. Pressed on a queued finding, takes it out. */
function startTriage(state: BrowserState, deeper: boolean): Update {
  const finding = selectedFinding(state);
  if (!finding) return { state };
  if (state.running?.fingerprint === finding.fingerprint) {
    return { state: { ...state, message: `${finding.id} is being checked now; Ctrl+C stops it.` } };
  }
  const position = queuePosition(state, finding);
  if (position !== null) {
    return {
      state: {
        ...state,
        queue: state.queue.filter((item) => item.finding.fingerprint !== finding.fingerprint),
        message: `Took ${finding.id} out of the queue.`,
      },
    };
  }
  const refusal = refusalOf(state, finding);
  if (refusal) return { state: { ...state, view: 'detail', message: `This finding can't be checked: ${refusal}.` } };
  if (!state.model.ok) return { state: { ...state, message: state.model.error } };

  let check: QueuedCheck = { finding };
  if (deeper) {
    const earlier = state.results.get(finding.fingerprint);
    if (!earlier || earlier.status !== 'succeeded') {
      return { state: { ...state, message: 'There is no finished check of this finding to dig deeper from; press t to run one.' } };
    }
    check = { finding, continueFrom: earlier };
  }
  if (state.running) {
    const queue = [...state.queue, check];
    return { state: { ...state, queue, message: `Queued ${finding.id}, number ${queue.length} in line. Press t again to take it out.` } };
  }
  return { state: deeper ? state : { ...state, detailScroll: 0 }, effect: triageEffect(check) };
}

function triageEffect(check: QueuedCheck): Effect {
  return check.continueFrom
    ? { type: 'triage', finding: check.finding, continueFrom: check.continueFrom }
    : { type: 'triage', finding: check.finding };
}

/** 1 for the next check to run, or null when the finding is not queued. */
export function queuePosition(state: BrowserState, finding: LocalFinding): number | null {
  const index = state.queue.findIndex((item) => item.finding.fingerprint === finding.fingerprint);
  return index === -1 ? null : index + 1;
}

/** Once a check has finished: the next queued one, if any. */
export function nextCheck(state: BrowserState): Update {
  const [next, ...rest] = state.queue;
  if (!next || state.running) return { state };
  return { state: { ...state, queue: rest }, effect: triageEffect(next) };
}

/** A check reads the files the scan saw, so a new scan waits until no check runs or waits. */
function rescan(state: BrowserState): Update {
  if (state.running) {
    return { state: { ...state, message: 'A check is running. Wait for it to finish, or press Ctrl+C to stop it, then press r again.' } };
  }
  return { state, effect: { type: 'rescan' } };
}

function quit(state: BrowserState): Update {
  return { state, effect: { type: 'quit' } };
}

/** Moves the list window so the cursor stays on screen. */
export function withViewport(state: BrowserState, height: number): BrowserState {
  const rows = Math.max(1, height);
  let top = Math.min(state.top, Math.max(0, visibleFindings(state).length - rows));
  if (state.cursor < top) top = state.cursor;
  if (state.cursor >= top + rows) top = state.cursor - rows + 1;
  return top === state.top ? state : { ...state, top };
}
