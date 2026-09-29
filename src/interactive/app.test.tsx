import { PassThrough } from 'node:stream';

import { describe, expect, it } from 'vitest';

import type { LocalFinding } from '../sources.js';
import type { TriageResult } from '../triage.js';
import { browse, type BrowseOptions, type CheckOptions, type Loaded } from './app.js';
import { detailLines, lineText, wrap } from './content.js';
import { INITIAL_SCAN, applyScanEvent, duration, type ScanReporter } from './loading.js';
import { initialState } from './state.js';

const finding: LocalFinding = {
  id: 'dc407ccb',
  fingerprint: 'dc407ccb'.padEnd(64, '0'),
  kind: 'sast',
  severity: 'high',
  title: 'code-string-concat',
  description: 'User input reaches eval.',
  ruleId: 'javascript.lang.security.audit.code-string-concat',
  vulnerabilityIds: ['CWE-95'],
  references: [],
  tool: { name: 'opengrep', version: '1.30.0' },
  tools: [],
  location: { path: 'routes/a.js', startLine: 3, snippet: 'eval(req.query.code);' },
};

function result(): TriageResult {
  return {
    version: 1,
    finding: { id: finding.id, fingerprint: finding.fingerprint, kind: 'sast', severity: 'high', title: finding.title, tools: ['opengrep'], location: { path: 'routes/a.js', startLine: 3 } },
    model: 'openai-compatible:fake',
    promptVersion: 'x',
    status: 'succeeded',
    exploitability: 'exploitable',
    confidence: 0.9,
    entryPoint: 'GET /x query.code',
    preconditions: [],
    rationale: 'The query string goes straight into eval.',
    evidence: [],
    openQuestions: [],
    rejectedEvidence: [],
    downgraded: false,
    filesRead: ['routes/a.js'],
    continuedFrom: null,
    steps: 2,
    inputTokens: 1000,
    outputTokens: 100,
    costUsd: 0,
    durationMs: 5,
    error: null,
  };
}

const ANSI = /\u001b\[[0-9;?]*[A-Za-z]|\u001b\][^\u0007]*\u0007/g;

function terminal(columns = 110, rows = 30) {
  const input = Object.assign(new PassThrough(), {
    isTTY: true,
    raw: false,
    setRawMode(raw: boolean) {
      input.raw = raw;
      return input;
    },
    ref() {},
    unref() {},
  });
  let raw = '';
  const output = Object.assign(new PassThrough(), { isTTY: true, columns, rows });
  output.on('data', (chunk: Buffer) => (raw += chunk.toString('utf8')));
  return {
    input,
    output,
    raw: () => raw,
    screen: () => raw.replace(ANSI, ''),
    clear: () => (raw = ''),
  };
}

// Ink draws at most about 30 frames a second.
const tick = (ms = 80) => new Promise((resolve) => setTimeout(resolve, ms));

function options({
  loaded = {},
  ...overrides
}: Partial<BrowseOptions> & Pick<BrowseOptions, 'input' | 'output'> & { loaded?: Partial<Loaded> }): BrowseOptions {
  return {
    root: '/repo',
    commit: '3f9a1c2 Fix the login redirect',
    load: async () => ({ findings: [finding], ignored: 0, protectedPaths: new Set(), ...loaded }),
    model: { ok: true, destination: 'http://localhost:11434/v1 (openai-compatible:fake)', limits: '30 steps' },
    maxSteps: 30,
    check: () => Promise.reject(new Error('not expected')),
    decide: () => Promise.reject(new Error('not expected')),
    ...overrides,
  };
}

describe('browse', () => {
  it('opens a finding, checks it with live progress, and returns the result on quit', async () => {
    const { input, output, raw, screen, clear } = terminal();
    let release: (value: TriageResult) => void = () => {};
    const asked: CheckOptions[] = [];
    const done = browse(
      options({
        loaded: { ignored: 3 },
        check: (_finding, check) => {
          asked.push(check);
          return new Promise((resolve) => (release = resolve));
        },
        input,
        output,
      }),
    );
    await tick();

    expect(input.raw).toBe(true);
    expect(raw()).toContain('\u001b[?1049h');
    expect(screen()).toContain('dc407ccb');
    expect(screen()).toContain('● 1 high');
    expect(screen()).toContain('3 ignored');
    expect(screen()).toContain('@ 3f9a1c2 Fix the login redirect');

    input.write('\r');
    await tick();
    expect(screen()).toContain('javascript.lang.security.audit.code-string-concat');
    expect(screen()).toContain('Code is sent to http://localhost:11434/v1');

    clear();
    input.write('t');
    await tick();
    asked[0]!.onStep({ steps: 1, inputTokens: 900, outputTokens: 50, costUsd: 0, inputs: [{ path: 'routes/a.js', sha256: 'x' }] });
    await tick();
    expect(screen()).toContain('Checking, step 1 of at most 30 · 950 tokens');
    expect(screen()).toContain('looked at routes/a.js');

    release(result());
    await tick();
    expect(screen()).toContain('EXPLOITABLE');
    expect(screen()).toContain('GET /x query.code');

    input.write('q');
    const results = await done;
    expect(results).toHaveLength(1);
    expect(input.raw).toBe(false);
    expect(raw()).toContain('\u001b[?1049l');
  });

  it('runs queued checks one after the other', async () => {
    const { input, output, screen, clear } = terminal();
    const second = { ...finding, id: 'ee000002', fingerprint: 'ee000002'.padEnd(64, '0'), title: 'second finding' };
    const pending: Array<{ id: string; release: (value: TriageResult) => void }> = [];
    const done = browse(
      options({
        loaded: { findings: [finding, second] },
        check: (checked) => new Promise((resolve) => pending.push({ id: checked.id, release: resolve })),
        input,
        output,
      }),
    );
    await tick();
    input.write('t');
    await tick();
    input.write('j');
    await tick();
    input.write('t');
    await tick();
    expect(pending.map((item) => item.id)).toEqual(['dc407ccb']);
    expect(screen()).toContain('◷ queued #1');
    expect(screen()).toContain('1 queued');

    clear();
    pending[0]!.release(result());
    await tick();
    expect(pending.map((item) => item.id)).toEqual(['dc407ccb', 'ee000002']);
    expect(screen()).toContain('▲ exploitable');
    expect(screen()).toContain('checking ee000002');

    pending[1]!.release({ ...result(), finding: { ...result().finding, id: second.id, fingerprint: second.fingerprint } });
    await tick();
    input.write('q');
    expect(await done).toHaveLength(2);
  });

  it('stops a running check on Ctrl+C and keeps going', async () => {
    const { input, output, screen } = terminal();
    let signal: AbortSignal | undefined;
    const done = browse(
      options({
        check: (_finding, check) =>
          new Promise((_resolve, reject) => {
            signal = check.signal;
            check.signal.addEventListener('abort', () => reject(new Error('aborted')));
          }),
        input,
        output,
      }),
    );
    await tick();
    input.write('t');
    await tick();
    input.write('\u0003');
    await tick();
    expect(signal?.aborted).toBe(true);
    expect(screen()).toContain('The check of dc407ccb failed: aborted');
    input.write('q');
    expect(await done).toEqual([]);
  });

  it('shows earlier checks and the opening message, and never draws past the terminal width', async () => {
    const { input, output, raw, screen } = terminal(60, 20);
    const long = { ...finding, title: 'x'.repeat(300), location: { path: 'a/'.repeat(100), startLine: 1 } };
    const done = browse(
      options({
        loaded: { findings: [long], results: new Map([[finding.fingerprint, result()]]), message: '1 earlier check still applies.' },
        input,
        output,
      }),
    );
    await tick();
    expect(screen()).toContain('▲ exploitable');
    expect(screen()).toContain('1 earlier check still applies.');
    // Escape codes also move the cursor between frames, so they end a line too.
    for (const line of raw().split(ANSI).join('\n').split(/\r?\n/)) expect([...line].length).toBeLessThanOrEqual(60);
    input.write('q');
    await done;
  });
});

describe('marking', () => {
  it('asks for a decision and a reason, saves it, and hides the finding', async () => {
    const { input, output, screen, clear } = terminal();
    const saved: unknown[] = [];
    const done = browse(
      options({
        decide: async (marked, state, reason) => {
          saved.push([marked.id, state, reason]);
          return {
            findings: [{ ...finding, decision: { fingerprint: finding.fingerprint, state: 'false_positive' } }],
            protectedPaths: new Set(),
            file: '.minotaur/decisions.yml',
          };
        },
        input,
        output,
      }),
    );
    await tick();
    input.write('m');
    await tick();
    expect(screen()).toContain('Mark dc407ccb as');
    input.write('f');
    await tick();
    input.write('test only');
    await tick();
    expect(screen()).toContain('Why false positive? test only');
    clear();
    input.write('\r');
    await tick();
    expect(saved).toEqual([['dc407ccb', 'false_positive', 'test only']]);
    expect(screen()).toContain('Marked dc407ccb as false positive in .minotaur/decisions.yml');
    expect(screen()).toContain('1 hidden');
    input.write('q');
    await done;
  });
});

describe('loading', () => {
  it('shows each source while the findings are gathered, then the list', async () => {
    const { input, output, screen, clear } = terminal();
    let finish: () => void = () => {};
    let report: ScanReporter | undefined;
    const done = browse(
      options({
        load: (reporter) => {
          report = reporter;
          reporter.step('Working out which scanners apply');
          return new Promise((resolve) => (finish = () => resolve({ findings: [finding], ignored: 0, protectedPaths: new Set() })));
        },
        input,
        output,
      }),
    );
    await tick();
    expect(screen()).toContain('Preparing the scan');
    expect(screen()).toContain('Working out which scanners apply');

    report!.sources(['trivy', 'opengrep']);
    report!.start('trivy');
    report!.note('Downloading trivy 0.73.0 (47 MB) into /cache, once.');
    await tick();
    expect(screen()).toContain('Scanning, 0 of 2 sources done');
    expect(screen()).toContain('looking at dependencies, secrets and configuration');
    expect(screen()).toContain('Downloading trivy 0.73.0');

    report!.done({ source: 'trivy', status: 'ok', findings: 201, durationMs: 4100 });
    report!.start('opengrep');
    report!.done({ source: 'opengrep', status: 'skipped', findings: 0, durationMs: 1, error: 'no code' });
    await tick();
    expect(screen()).toContain('201 findings');
    expect(screen()).toContain('4.1s');
    expect(screen()).toContain('skipped, no code');

    clear();
    finish();
    await tick();
    expect(screen()).toContain('dc407ccb');
    input.write('q');
    await done;
  });

  it('scans again on r, keeping the filter, the selected finding and the checks run so far', async () => {
    const { input, output, screen, clear } = terminal();
    const second = { ...finding, id: 'ee000002', fingerprint: 'ee000002'.padEnd(64, '0'), title: 'second finding', severity: 'low' as const };
    const added = { ...finding, id: 'ff000003', fingerprint: 'ff000003'.padEnd(64, '0'), title: 'new finding' };
    const loads: boolean[] = [];
    let finish: () => void = () => {};
    const done = browse(
      options({
        load: (_reporter, { rescan }) => {
          loads.push(rescan);
          if (!rescan) return Promise.resolve({ findings: [finding, second], ignored: 0, protectedPaths: new Set() });
          return new Promise((resolve) =>
            (finish = () =>
              resolve({ findings: [added, finding, second], ignored: 0, protectedPaths: new Set(), commit: '9b8c7d6 Later commit' })),
          );
        },
        check: () => Promise.resolve(result()),
        input,
        output,
      }),
    );
    await tick();
    input.write('t');
    await tick();
    for (let press = 0; press < 3; press++) {
      input.write('s');
      await tick(20);
    }
    clear();
    input.write('j');
    await tick();
    expect(screen()).toContain('dc407ccb');
    expect(screen()).not.toContain('second finding');

    clear();
    input.write('r');
    await tick();
    expect(loads).toEqual([false, true]);
    expect(screen()).toContain('Preparing the scan');

    clear();
    finish();
    await tick();
    expect(screen()).toContain('@ 9b8c7d6 Later commit');
    expect(screen()).toContain('new finding');
    expect(screen()).not.toContain('second finding');
    expect(screen()).toMatch(/❯\s*!?\s*dc407ccb/);

    input.write('q');
    expect((await done).map((item) => item.finding.id)).toEqual(['dc407ccb']);
  });

  it('rejects with the loading error and leaves the terminal as it was', async () => {
    const { input, output, raw } = terminal();
    const failure = new Error('every source failed');
    await expect(browse(options({ load: () => Promise.reject(failure), input, output }))).rejects.toBe(failure);
    expect(input.raw).toBe(false);
    expect(raw()).toContain('\u001b[?1049l');
  });

  it('formats times', () => {
    expect(duration(4100)).toBe('4.1s');
    expect(duration(65_000)).toBe('1m 05s');
  });

  it('keeps the last few notes', () => {
    let state = applyScanEvent(INITIAL_SCAN, { type: 'sources', names: ['trivy'] });
    for (const text of ['a', 'b', 'c', 'd', 'e']) state = applyScanEvent(state, { type: 'note', text });
    expect(state.notes).toEqual(['b', 'c', 'd', 'e']);
    expect(state.step).toBeNull();
  });
});

describe('content', () => {
  it('wraps the detail page to the width it is drawn at', () => {
    const long = { ...finding, description: 'word '.repeat(80), ruleId: 'r'.repeat(200) };
    const state = { ...initialState({ root: '/r', findings: [long], ignored: 0, protectedPaths: new Set(), model: { ok: false as const, error: 'No model.' } }), view: 'detail' as const };
    const lines = detailLines(state, 50);
    expect(lines.map(lineText).join('\n')).toContain('Triage is not set up yet.');
    for (const line of lines) expect(lineText(line).length).toBeLessThanOrEqual(50);
  });

  it('wraps words and cuts ones longer than a line', () => {
    expect(wrap('one two three four', 12)).toEqual(['one two', 'three four']);
    expect(wrap('abcdefghijklmnop', 10)).toEqual(['abcdefghij', 'klmnop']);
    expect(wrap('a b', 20, '  ')).toEqual(['  a b']);
    expect(wrap('Either:\n  - one two three', 14)).toEqual(['Either:', '  - one two', '  three']);
  });
});
