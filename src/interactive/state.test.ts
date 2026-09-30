import { describe, expect, it } from 'vitest';

import type { LocalFinding } from '../sources.js';
import type { TriageResult } from '../triage.js';
import {
  fixableShown,
  handleKey,
  initialState,
  nextCheck,
  hiddenCount,
  queuePosition,
  selectedFinding,
  visibleFindings,
  withFindings,
  withViewport,
  type BrowserState,
} from './state.js';

function finding(id: string, overrides: Partial<LocalFinding> = {}): LocalFinding {
  return {
    id,
    fingerprint: id.padEnd(64, '0'),
    kind: 'sast',
    severity: 'medium',
    title: `finding ${id}`,
    vulnerabilityIds: [],
    references: [],
    tool: { name: 'opengrep', version: '1' },
    tools: [],
    location: { path: `src/${id}.js`, startLine: 1 },
    ...overrides,
  };
}

const findings = [
  finding('aaaa0001', { severity: 'critical' }),
  finding('aaaa0002', { severity: 'high' }),
  finding('aaaa0003', { severity: 'medium' }),
  finding('aaaa0004', { severity: 'low', kind: 'secret', location: { path: 'config/key.pem' } }),
];

function state(overrides: Partial<BrowserState> = {}): BrowserState {
  return {
    ...initialState({
      root: '/repo',
      findings,
      ignored: 0,
      protectedPaths: new Set(['config/key.pem']),
      model: { ok: true, destination: 'http://localhost:11434/v1', limits: '30 steps' },
    }),
    ...overrides,
  };
}

const key = (name: string) => ({ name });
const press = (from: BrowserState, ...names: string[]) =>
  names.reduce((current, name) => handleKey(current, key(name), 10).state, from);

describe('moving through the list', () => {
  it('moves, pages and stops at both ends', () => {
    expect(press(state(), 'down', 'j').cursor).toBe(2);
    expect(press(state(), 'down', 'down', 'down', 'down', 'down').cursor).toBe(3);
    expect(press(state(), 'up').cursor).toBe(0);
    expect(press(state(), 'end').cursor).toBe(3);
    expect(handleKey(state(), { sequence: 'G' }, 10).state.cursor).toBe(3);
    expect(press(state({ cursor: 3 }), 'home').cursor).toBe(0);
    expect(handleKey(state(), key('pagedown'), 3).state.cursor).toBe(2);
  });

  it('keeps the cursor on screen', () => {
    expect(withViewport(state({ cursor: 3 }), 2).top).toBe(2);
    expect(withViewport(state({ cursor: 0, top: 2 }), 2).top).toBe(0);
  });

  it('raises the severity bar and stays on the same finding when it is still shown', () => {
    const onHigh = press(state(), 'down');
    const filtered = press(onHigh, 's', 's', 's');
    expect(filtered.minSeverity).toBe('high');
    expect(visibleFindings(filtered).map((item) => item.id)).toEqual(['aaaa0001', 'aaaa0002']);
    expect(selectedFinding(filtered)?.id).toBe('aaaa0002');
    expect(press(filtered, 's', 's').minSeverity).toBeNull();
  });

  it('hides noise until a shows it, and a hides it again', () => {
    const noisy = state({
      findings: [finding('bbbb0001', { focus: 'likely' }), finding('bbbb0002', { focus: 'noise' }), finding('bbbb0003', { focus: 'maybe' })],
    });
    expect(hiddenCount(noisy)).toBe(1);
    expect(visibleFindings(noisy).map((item) => item.id)).toEqual(['bbbb0001', 'bbbb0003']);

    const shown = handleKey(noisy, key('a'), 10);
    expect(shown.state.showNoise).toBe(true);
    expect(visibleFindings(shown.state).map((item) => item.id)).toEqual(['bbbb0001', 'bbbb0002', 'bbbb0003']);
    expect(shown.state.message).toContain('Showing 1 finding rated as noise or marked');

    const hidden = press(shown.state, 'end', 'a');
    expect(hidden.showNoise).toBe(false);
    expect(selectedFinding(hidden)?.id).toBe('bbbb0003');
    expect(handleKey(state(), key('a'), 10).state.message).toBe('No finding is rated as noise or marked closed.');
  });
});

describe('details and checks', () => {
  it('opens the details, steps through findings there and goes back', () => {
    const detail = press(state(), 'return');
    expect(detail.view).toBe('detail');
    expect(selectedFinding(handleKey(detail, { sequence: ']' }, 10).state)?.id).toBe('aaaa0002');
    expect(press(detail, 'escape').view).toBe('list');
  });

  it('starts a check of the selected finding', () => {
    const update = handleKey(press(state(), 'down'), key('t'), 10);
    expect(update.effect).toEqual({ type: 'triage', finding: findings[1] });
    // Staying on the list lets the next finding be queued straight away.
    expect(update.state.view).toBe('list');
  });

  it('refuses secrets and files with one, before anything is sent', () => {
    const update = handleKey(state({ cursor: 3 }), key('t'), 10);
    expect(update.effect).toBeUndefined();
    expect(update.state.message).toMatch(/secret findings are never triaged/);
  });

  it('explains a missing model instead of starting', () => {
    const update = handleKey(state({ model: { ok: false, error: 'No model is configured.' } }), key('t'), 10);
    expect(update.effect).toBeUndefined();
    expect(update.state.message).toBe('No model is configured.');
  });

  it('queues checks behind the running one, and t again takes one out', () => {
    const running = state({
      running: { fingerprint: findings[0]!.fingerprint, steps: 1, maxSteps: 30, tokens: 10, costUsd: 0, filesRead: [] },
    });
    expect(handleKey(running, key('t'), 10).state.message).toMatch(/aaaa0001 is being checked now/);

    const queued = press(running, 'down', 't', 'down', 't');
    expect(queued.queue.map((item) => item.finding.id)).toEqual(['aaaa0002', 'aaaa0003']);
    expect(queuePosition(queued, findings[2]!)).toBe(2);
    expect(queued.message).toMatch(/number 2 in line/);

    const removed = press(queued, 'up', 't');
    expect(removed.queue.map((item) => item.finding.id)).toEqual(['aaaa0003']);
    expect(removed.message).toMatch(/Took aaaa0002 out of the queue/);
  });

  it('never queues what cannot be checked', () => {
    const running = state({
      running: { fingerprint: findings[0]!.fingerprint, steps: 1, maxSteps: 30, tokens: 10, costUsd: 0, filesRead: [] },
    });
    expect(press(running, 'end', 't').queue).toEqual([]);
  });

  it('starts the next queued check once the running one is done', () => {
    const waiting = state({ queue: [{ finding: findings[1]! }, { finding: findings[2]! }] });
    const next = nextCheck(waiting);
    expect(next.effect).toEqual({ type: 'triage', finding: findings[1] });
    expect(next.state.queue).toHaveLength(1);
    expect(nextCheck(state()).effect).toBeUndefined();
    const busy = { ...waiting, running: { fingerprint: 'x', steps: 0, maxSteps: 30, tokens: 0, costUsd: 0, filesRead: [] } };
    expect(nextCheck(busy).effect).toBeUndefined();
  });

  it('Ctrl+C stops the running check and clears the queue rather than quitting', () => {
    const running = state({
      running: { fingerprint: findings[0]!.fingerprint, steps: 1, maxSteps: 30, tokens: 10, costUsd: 0, filesRead: [] },
      queue: [{ finding: findings[1]! }],
    });
    const stopped = handleKey(running, { name: 'c', ctrl: true }, 10);
    expect(stopped.effect).toEqual({ type: 'cancel' });
    expect(stopped.state.queue).toEqual([]);
    expect(stopped.state.message).toMatch(/clearing 1 queued/);
    expect(handleKey(state(), { name: 'c', ctrl: true }, 10).effect).toEqual({ type: 'quit' });
  });

  it('digs deeper only from a finished check', () => {
    const detail = press(state(), 'return');
    expect(handleKey(detail, key('d'), 10).state.message).toMatch(/no finished check/);
    const result = { status: 'succeeded' } as TriageResult;
    const checked = { ...detail, results: new Map([[findings[0]!.fingerprint, result]]) };
    expect(handleKey(checked, key('d'), 10).effect).toEqual({ type: 'triage', finding: findings[0], continueFrom: result });
  });

  it('marks a finding: m, a decision, then the reason', () => {
    const typed = handleKey(press(state(), 'm', 'f'), { sequence: 'fake key' }, 10).state;
    expect(typed.marking).toMatchObject({ state: 'false_positive', reason: 'fake key' });
    // While marking, letters are text, not commands.
    const more = press(handleKey(typed, { sequence: 'q' }, 10).state, 'backspace', 'space');
    expect(more.marking?.reason).toBe('fake key ');
    const saved = handleKey(more, key('return'), 10);
    expect(saved.state.marking).toBeNull();
    expect(saved.effect).toEqual({ type: 'decide', finding: findings[0], state: 'false_positive', reason: 'fake key' });

    expect(handleKey(press(state(), 'm'), key('o'), 10).effect).toMatchObject({ type: 'decide', state: 'open', reason: '' });
    const cancelled = press(state(), 'm', 'c', 'escape');
    expect(cancelled.marking).toBeNull();
    expect(cancelled.message).toBe('Nothing was marked.');
  });

  it('hides findings marked closed, and keeps the cursor when the findings change', () => {
    const marked = [
      finding('cccc0001'),
      finding('cccc0002', { decision: { fingerprint: 'c'.repeat(64), state: 'false_positive' } }),
      finding('cccc0003', { decision: { fingerprint: 'd'.repeat(64), state: 'confirmed' } }),
    ];
    const onThird = press(state(), 'end');
    const after = withFindings(onThird, marked, new Set(), 'Marked.');
    expect(visibleFindings(after).map((item) => item.id)).toEqual(['cccc0001', 'cccc0003']);
    expect(hiddenCount(after)).toBe(1);
    expect(after.cursor).toBe(1);
  });

  it('asks for a new scan on r, but not while a check runs', () => {
    expect(handleKey(state(), key('r'), 10).effect).toEqual({ type: 'rescan' });
    const busy = handleKey(state({ running: { fingerprint: 'x', steps: 0, maxSteps: 30, tokens: 0, costUsd: 0, filesRead: [] } }), key('r'), 10);
    expect(busy.effect).toBeUndefined();
    expect(busy.state.message).toContain('A check is running');
  });

  it('clears a message on the next key, and q quits', () => {
    expect(press(state({ message: 'hello' }), 'down').message).toBeNull();
    expect(handleKey(state(), key('q'), 10).effect).toEqual({ type: 'quit' });
  });
});

describe('fix keys', () => {
  const fixing = { total: 1, index: 0, current: 'aaaa0001', steps: 0, costUsd: 0, phase: 'fixing' };

  it('fixes the selected finding, and refuses a secret with the reason', () => {
    expect(handleKey(state(), { sequence: 'f' }, 10).effect).toEqual({ type: 'fix', findings: [findings[0]] });
    const secret = handleKey(state({ showNoise: true, cursor: 3 }), { sequence: 'f' }, 10);
    expect(secret.effect).toBeUndefined();
    expect(secret.state.message).toContain('rotate it');
  });

  it('runs one job at a time', () => {
    const running = { fingerprint: findings[1]!.fingerprint, steps: 1, maxSteps: 30, tokens: 0, costUsd: 0, filesRead: [] };
    expect(handleKey(state({ running }), { sequence: 'f' }, 10).state.message).toContain('A check is running');
    expect(handleKey(state({ fixing }), { sequence: 't' }, 10).state.message).toContain('A fix is running');
    expect(handleKey(state({ fixing }), { sequence: 'r' }, 10).effect).toBeUndefined();
  });

  it('stops a fix with Ctrl+C instead of quitting', () => {
    expect(handleKey(state({ fixing }), { name: 'c', ctrl: true }, 10).effect).toEqual({ type: 'cancel' });
  });

  it('asks before fixing what is shown, leaving out what cannot be fixed, and treats only y as yes', () => {
    const asked = handleKey(state({ showNoise: true }), { sequence: 'F' }, 10).state;
    expect(asked.question).toEqual({ kind: 'batch', findings: findings.slice(0, 3) });
    // The secret is shown, but it is not counted: F would not fix it.
    expect(fixableShown(state({ showNoise: true }))).toHaveLength(3);
    expect(fixableShown(state({ showNoise: true, minSeverity: 'high' }))).toHaveLength(2);
    expect(handleKey(asked, { sequence: 'y' }, 10).effect).toEqual({ type: 'fix', findings: findings.slice(0, 3) });
    expect(handleKey(asked, { name: 'return' }, 10).effect).toBeUndefined();
    const checkpoint = state({ question: { kind: 'checkpoint', spentUsd: 10, capUsd: 10, fixed: 1, notFixed: 0, remaining: 2, current: 'aaaa0002' } });
    expect(handleKey(checkpoint, { name: 'c', ctrl: true }, 10).effect).toEqual({ type: 'answer', go: false });
    expect(handleKey(checkpoint, { sequence: 'y' }, 10).effect).toEqual({ type: 'answer', go: true });
  });
});
