import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { DECISIONS_FILE, applyDecisions, liftProtected, loadDecisions, parseDecisionState, saveDecision } from './decisions.js';
import type { LocalFinding } from './sources.js';

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'minotaur-decisions-'));
});
afterEach(() => rm(root, { recursive: true, force: true }));

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
    focus: 'maybe',
    ...overrides,
  };
}

describe('decisions file', () => {
  it('saves, reads back and removes a decision', async () => {
    const key = finding('aaaa0001', { kind: 'secret', title: 'Private key', location: { path: 'test/fixture.ts' } });
    await saveDecision(root, key, 'false_positive', { reason: ' fake key in a fixture ', by: 'Arno', now: new Date('2026-09-29T10:00:00Z') });
    const text = await readFile(join(root, DECISIONS_FILE), 'utf8');
    expect(text).toContain('# Decisions about minotaur findings');
    expect([...(await loadDecisions(root)).values()]).toEqual([
      {
        fingerprint: key.fingerprint,
        state: 'false_positive',
        reason: 'fake key in a fixture',
        title: 'Private key',
        path: 'test/fixture.ts',
        by: 'Arno',
        at: '2026-09-29',
      },
    ]);

    await saveDecision(root, key, 'open');
    expect((await loadDecisions(root)).size).toBe(0);
  });

  it('has no decisions without a file, and names the problem in a broken one', async () => {
    expect((await loadDecisions(root)).size).toBe(0);
    await mkdir(join(root, '.minotaur'));
    await writeFile(join(root, DECISIONS_FILE), 'decisions:\n  - fingerprint: abc\n    state: false_positive\n');
    await expect(loadDecisions(root)).rejects.toThrow(/decisions\.0\.fingerprint must be a full 64-character fingerprint/);
  });

  it('reads decisions the way people type them', () => {
    expect(parseDecisionState('false-positive')).toBe('false_positive');
    expect(parseDecisionState('Accepted_Risk')).toBe('accepted_risk');
    expect(parseDecisionState('open')).toBe('open');
    expect(parseDecisionState('maybe')).toBeNull();
  });
});

describe('applyDecisions', () => {
  it('attaches decisions and moves confirmed findings up with the likely ones', () => {
    const likely = finding('bbbb0001', { focus: 'likely' });
    const maybe = finding('bbbb0002');
    const decisions = new Map([[maybe.fingerprint, { fingerprint: maybe.fingerprint, state: 'confirmed' as const, by: 'Arno', reason: 'reachable from /login' }]]);
    const [first, second] = applyDecisions([likely, maybe], decisions);
    expect(first).toMatchObject({ id: 'bbbb0002', focus: 'likely', decision: { state: 'confirmed' } });
    expect(first!.focusReasons![0]).toBe('confirmed by Arno: reachable from /login');
    expect(second!.id).toBe('bbbb0001');
  });

  it('lifts the protection only when every secret in the file is a false positive', () => {
    const fake = finding('cccc0001', { kind: 'secret', location: { path: 'test/fixture.ts' } });
    const real = finding('cccc0002', { kind: 'secret', location: { path: 'test/fixture.ts', startLine: 9 } });
    const decisions = new Map([[fake.fingerprint, { fingerprint: fake.fingerprint, state: 'false_positive' as const }]]);

    expect([...liftProtected(['test/fixture.ts', 'config/.env'], applyDecisions([fake], decisions))]).toEqual(['config/.env']);
    expect([...liftProtected(['test/fixture.ts'], applyDecisions([fake, real], decisions))]).toEqual(['test/fixture.ts']);
  });
});
