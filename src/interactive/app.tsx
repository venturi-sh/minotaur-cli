/**
 * The interactive view, drawn with Ink on the alternate screen so the shell
 * is left as it was on exit. Keys go through the pure `handleKey`; this file
 * only draws the state and carries out the effects. One check runs at a time,
 * in the background, so the list stays usable while it does.
 */

import { homedir } from 'node:os';

import { ProgressBar, Spinner } from '@inkjs/ui';
import { Box, Spacer, Text, render, useApp, useInput, useWindowSize, type Key as InkKey } from 'ink';
import { useEffect, useRef, useState } from 'react';

import type { StepProgress } from '../agent/index.js';

import { CLOSED_STATES, DECISION_LABEL, type DecisionState } from '../decisions.js';
import { locationOf, toolsOf } from '../output.js';
import type { LocalFinding } from '../sources.js';
import type { Checkpoint, FixEvent, FixRun } from '../fix.js';
import type { TriageResult } from '../triage.js';
import {
  ACCENT,
  SEVERITY_COLOR,
  checkLabel,
  fixLabel,
  detailLines,
  layoutFor,
  markingPrompt,
  questionPrompt,
  severityCounts,
  type Layout,
  type Line,
  type Segment,
} from './content.js';
import { INITIAL_SCAN, Loading, applyScanEvent, type ScanEvent, type ScanReporter, type ScanState } from './loading.js';
import {
  handleKey,
  initialState,
  nextCheck,
  hiddenCount,
  fixableShown,
  selectedFinding,
  withFindings,
  visibleFindings,
  withViewport,
  type BrowserState,
  type FixView,
  type Key,
  type ModelStatus,
} from './state.js';

export interface CheckOptions {
  continueFrom?: TriageResult | undefined;
  onStep: (progress: StepProgress) => void;
  signal: AbortSignal;
}

/** What the list starts from, once the findings are gathered. */
export interface Loaded {
  findings: readonly LocalFinding[];
  ignored: number;
  protectedPaths: ReadonlySet<string>;
  /** Earlier checks that still apply, by fingerprint. */
  results?: ReadonlyMap<string, TriageResult> | undefined;
  /** Fixes on branches that are not merged yet, by fingerprint. */
  fixes?: ReadonlyMap<string, FixView> | undefined;
  /** Shown until the first key press, such as where the findings came from. */
  message?: string | null | undefined;
  /** The commit, when it changed since the view opened, such as after a new commit and a rescan. */
  commit?: string | null | undefined;
}

export interface FixOptions {
  onEvent: (event: FixEvent) => void;
  /** Resolves true to go on past the batch's cap. */
  onCheckpoint: (checkpoint: Checkpoint) => Promise<boolean>;
  signal: AbortSignal;
}

/** A finished fix run, with each commit's patch by fingerprint. */
export interface Fixed {
  run: FixRun;
  diffs: ReadonlyMap<string, string>;
}

export interface Decided {
  findings: readonly LocalFinding[];
  protectedPaths: ReadonlySet<string>;
  /** Where the decision was written, such as ".minotaur/decisions.yml". */
  file: string;
}

export interface BrowseOptions {
  root: string;
  /** The commit looked at, such as "3f9a1c2 Fix the login redirect". */
  commit: string | null;
  /** Gathers the findings while the loading screen shows its progress. `rescan` is set when the person asks for a new scan. */
  load: (reporter: ScanReporter, options: { rescan: boolean }) => Promise<Loaded>;
  model: ModelStatus;
  maxSteps: number;
  check: (finding: LocalFinding, options: CheckOptions) => Promise<TriageResult>;
  /** Records a decision and returns the findings and protected files as they are after it. */
  decide: (finding: LocalFinding, state: DecisionState | 'open', reason: string) => Promise<Decided>;
  /** Fixes findings on a branch, one commit each. */
  fix: (findings: readonly LocalFinding[], options: FixOptions) => Promise<Fixed>;
  input: NodeJS.ReadableStream & { isTTY?: boolean; setRawMode?: (raw: boolean) => unknown };
  output: NodeJS.WritableStream & { columns?: number; rows?: number };
}

type Session = Omit<BrowseOptions, 'load' | 'input' | 'output'> & Loaded;

const ANSWER: Record<string, string> = {
  exploitable: 'exploitable',
  not_exploitable: 'not exploitable',
  undetermined: 'undetermined',
};

const LIST_KEYS: ReadonlyArray<[string, string]> = [
  ['↑↓', 'move'],
  ['enter', 'open'],
  ['t', 'check'],
  ['f', 'fix'],
  ['F', 'fix all'],
  ['s', 'severity'],
  ['m', 'mark'],
  ['a', 'hidden'],
  ['r', 'rescan'],
  ['q', 'quit'],
];
const DETAIL_KEYS: ReadonlyArray<[string, string]> = [
  ['↑↓', 'scroll'],
  ['[ ]', 'prev/next'],
  ['t', 'check'],
  ['d', 'dig deeper'],
  ['f', 'fix'],
  ['m', 'mark'],
  ['esc', 'back'],
  ['q', 'quit'],
];

/** Runs until the person quits, and returns the checks they ran. Rejects when loading fails. */
export async function browse(options: BrowseOptions): Promise<TriageResult[]> {
  let results: TriageResult[] = [];
  const instance = render(<Root options={options} onQuit={(done) => (results = done)} />, {
    stdin: options.input as NodeJS.ReadStream,
    stdout: options.output as NodeJS.WriteStream,
    exitOnCtrlC: false,
    patchConsole: false,
    alternateScreen: true,
    // Only called from a terminal; CI detection would otherwise draw nothing until exit.
    interactive: true,
  });
  await instance.waitUntilExit();
  return results;
}

/** What the list keeps across a new scan. */
interface Carried {
  minSeverity: BrowserState['minSeverity'];
  showNoise: boolean;
  view: BrowserState['view'];
  /** The finding the cursor was on. */
  fingerprint: string | undefined;
}

function Root({ options, onQuit }: { options: BrowseOptions; onQuit: (results: TriageResult[]) => void }) {
  const { exit } = useApp();
  const { columns, rows } = useWindowSize();
  const [scan, setScan] = useState<ScanState>(INITIAL_SCAN);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [scans, setScans] = useState(0);
  const carried = useRef<Carried | null>(null);
  // Checks from before a new scan, by fingerprint, so quitting still lists them.
  const earlier = useRef(new Map<string, TriageResult>());
  const lastCommit = useRef(options.commit);

  useEffect(() => {
    const apply = (event: ScanEvent) => setScan((state) => applyScanEvent(state, event));
    const reporter: ScanReporter = {
      step: (text) => apply({ type: 'step', text }),
      sources: (names) => apply({ type: 'sources', names }),
      start: (name) => apply({ type: 'start', name, at: Date.now() }),
      done: (outcome) => apply({ type: 'done', outcome }),
      note: (text) => apply({ type: 'note', text }),
    };
    options
      .load(reporter, { rescan: scans > 0 })
      .then(setLoaded, (error: unknown) => exit(error instanceof Error ? error : new Error(String(error))));
  }, [scans]);

  const rescan = (state: BrowserState) => {
    for (const [fingerprint, result] of state.results) earlier.current.set(fingerprint, result);
    carried.current = {
      minSeverity: state.minSeverity,
      showNoise: state.showNoise,
      view: state.view,
      fingerprint: selectedFinding(state)?.fingerprint,
    };
    setScan(INITIAL_SCAN);
    setLoaded(null);
    setScans((count) => count + 1);
  };
  const quit = (results: TriageResult[]) => {
    const all = new Map(earlier.current);
    for (const result of results) all.set(result.finding.fingerprint, result);
    onQuit([...all.values()]);
  };

  useInput(
    (input, key) => {
      if (!(key.ctrl && input === 'c') && input !== 'q') return;
      // Raw mode keeps Ctrl+C from reaching the scanners, so stop the whole job as the terminal would have.
      exit();
      setImmediate(() => process.kill(0, 'SIGINT'));
    },
    { isActive: loaded === null },
  );

  if (loaded?.commit !== undefined) lastCommit.current = loaded.commit;
  const commit = lastCommit.current;
  if (!loaded) return <Loading root={options.root} commit={commit} state={scan} columns={columns} rows={rows} />;
  return (
    <Browser
      key={scans}
      options={{ ...options, ...loaded, commit }}
      carried={carried.current}
      onQuit={quit}
      onRescan={rescan}
    />
  );
}

function startingState(options: Session, carried: Carried | null): BrowserState {
  const start = initialState(options);
  if (!carried) return start;
  const kept = { ...start, minSeverity: carried.minSeverity, showNoise: carried.showNoise };
  const cursor = visibleFindings(kept).findIndex((finding) => finding.fingerprint === carried.fingerprint);
  return { ...kept, cursor: Math.max(0, cursor), view: cursor === -1 ? 'list' : carried.view };
}

function Browser({
  options,
  carried,
  onQuit,
  onRescan,
}: {
  options: Session;
  carried: Carried | null;
  onQuit: (results: TriageResult[]) => void;
  onRescan: (state: BrowserState) => void;
}) {
  const { exit } = useApp();
  const { columns, rows } = useWindowSize();
  const [state, setState] = useState(() => startingState(options, carried));
  // Key handlers and check callbacks read and write through this, so none of them sees a stale state.
  const current = useRef(state);
  const controller = useRef<AbortController | null>(null);

  const update = (change: (state: BrowserState) => BrowserState) => {
    current.current = change(current.current);
    setState(current.current);
  };

  const quitting = useRef(false);
  const fixController = useRef<AbortController | null>(null);
  // Set while the batch waits at its checkpoint for the person's answer.
  const answer = useRef<((go: boolean) => void) | null>(null);

  const reply = (go: boolean) => {
    const resolve = answer.current;
    answer.current = null;
    resolve?.(go);
  };

  /** Runs a fix of one or several findings in the background, and shows each outcome on the finding's page. */
  const runFix = (state: BrowserState, findings: readonly LocalFinding[]) => {
    const total = findings.length;
    update(() => ({ ...state, fixing: { total, index: 0, current: null, steps: 0, costUsd: 0, phase: 'making a worktree' } }));
    const mine = new AbortController();
    fixController.current = mine;
    const onEvent = (event: FixEvent) =>
      update((state) => {
        const fixing = state.fixing;
        if (!fixing) return state;
        switch (event.type) {
          case 'start':
            return { ...state, fixing: { ...fixing, index: event.index, current: event.finding.id, steps: 0, costUsd: 0, phase: 'fixing' } };
          case 'step':
            return { ...state, fixing: { ...fixing, steps: event.progress.steps, costUsd: event.progress.costUsd, phase: 'fixing' } };
          case 'upgrade':
            return { ...state, fixing: { ...fixing, phase: event.description } };
          case 'verify':
            return { ...state, fixing: { ...fixing, phase: event.scanners.length > 0 ? `running ${event.scanners.join(', ')} again` : 'checking' } };
          case 'retry':
            return { ...state, fixing: { ...fixing, phase: 'not fixed yet, trying again' } };
          default:
            return state;
        }
      });
    const onCheckpoint = (checkpoint: Checkpoint) =>
      new Promise<boolean>((resolve) => {
        if (mine.signal.aborted) return resolve(false);
        answer.current = resolve;
        const fixed = checkpoint.results.filter((result) => result.commit !== null).length;
        update((state) => ({
          ...state,
          question: {
            kind: 'checkpoint',
            spentUsd: checkpoint.spentUsd,
            capUsd: checkpoint.capUsd,
            fixed,
            notFixed: checkpoint.results.length - fixed,
            remaining: checkpoint.remaining,
            current: checkpoint.current.id,
          },
        }));
      });
    const settle = (change: (state: BrowserState) => Partial<BrowserState>) => {
      if (fixController.current === mine) fixController.current = null;
      reply(false);
      update((state) => ({ ...state, ...change(state), fixing: null, question: state.question?.kind === 'checkpoint' ? null : state.question }));
    };
    options.fix(findings, { onEvent, onCheckpoint, signal: mine.signal }).then(
      ({ run, diffs }) =>
        settle((state) => {
          const fixes = new Map(state.fixes);
          for (const result of run.results) {
            const view: FixView = {
              status: result.status,
              branch: result.commit ? run.branch : null,
              commit: result.commit,
              summary: result.summary,
              notes: result.notes,
              error: result.error,
              diff: diffs.get(result.finding.fingerprint) ?? null,
            };
            fixes.set(result.finding.fingerprint, view);
          }
          return { fixes, message: fixMessage(run, total) };
        }),
      (error: Error) => settle(() => ({ message: `The fix failed: ${error.message}` })),
    );
  };

  /** Marks the check as running in `state`, starts it, and runs the next queued one when it settles. */
  const run = (state: BrowserState, finding: LocalFinding, continueFrom: TriageResult | undefined) => {
    update(() => ({
      ...state,
      running: { fingerprint: finding.fingerprint, steps: 0, maxSteps: options.maxSteps, tokens: 0, costUsd: 0, filesRead: [] },
    }));
    const mine = new AbortController();
    controller.current = mine;
    const settle = (change: Partial<BrowserState>) => {
      if (controller.current === mine) controller.current = null;
      update((state) => ({ ...state, ...change, running: null }));
      if (quitting.current) return;
      const { state: after, effect } = nextCheck(current.current);
      if (effect?.type === 'triage') run(after, effect.finding, effect.continueFrom);
    };
    options
      .check(finding, {
        continueFrom,
        signal: mine.signal,
        onStep: (progress) =>
          update((state) => {
            if (state.running?.fingerprint !== finding.fingerprint) return state;
            return {
              ...state,
              running: {
                ...state.running,
                steps: progress.steps,
                tokens: progress.inputTokens + progress.outputTokens,
                costUsd: progress.costUsd,
                filesRead: [...new Set([...state.running.filesRead, ...progress.inputs.map((item) => item.path)])],
              },
            };
          }),
      })
      .then(
        (result) => {
          const answer = result.exploitability && result.status === 'succeeded' ? ANSWER[result.exploitability] : 'no answer';
          settle({
            results: new Map(current.current.results).set(finding.fingerprint, result),
            message: mine.signal.aborted ? `Stopped the check of ${finding.id}.` : `${finding.id}: ${answer}.`,
          });
        },
        (error: Error) => settle({ message: `The check of ${finding.id} failed: ${error.message}` }),
      );
  };

  useInput((input, key) => {
    try {
      const layout = layoutFor(current.current, columns, rows);
      const shown = fitToScreen(current.current, layout, columns);
      const { state: next, effect } = handleKey(shown, toKey(input, key), layout.body);
      if (effect?.type === 'quit') {
        quitting.current = true;
        controller.current?.abort();
        fixController.current?.abort();
        reply(false);
        onQuit([...next.results.values()]);
        exit();
        return;
      }
      if (effect?.type === 'rescan') {
        onRescan(next);
        return;
      }
      if (effect?.type === 'decide') {
        update(() => next);
        const { finding, state: decision, reason } = effect;
        options.decide(finding, decision, reason).then(
          (decided) => update((state) => withFindings(state, decided.findings, decided.protectedPaths, decidedMessage(finding, decision, decided))),
          (error: Error) => update((state) => ({ ...state, message: `Could not save the decision: ${error.message}` })),
        );
        return;
      }
      if (effect?.type === 'cancel') {
        controller.current?.abort();
        fixController.current?.abort();
        reply(false);
      }
      if (effect?.type === 'answer') {
        update(() => next);
        reply(effect.go);
        return;
      }
      if (effect?.type === 'fix') {
        runFix(next, effect.findings);
        return;
      }
      if (effect?.type === 'triage') {
        run(next, effect.finding, effect.continueFrom);
        return;
      }
      update(() => next);
    } catch (error) {
      quitting.current = true;
      controller.current?.abort();
      fixController.current?.abort();
      exit(error instanceof Error ? error : new Error(String(error)));
    }
  });

  const layout = layoutFor(state, columns, rows);
  const shown = fitToScreen(state, layout, columns);
  return (
    <Box flexDirection="column" width={columns} height={rows}>
      <Header state={shown} columns={columns} />
      {shown.view === 'list' ? <FindingList state={shown} layout={layout} /> : <FindingDetail state={shown} layout={layout} />}
      {layout.message.length > 0 && (
        <Box paddingX={1} height={layout.message.length}>
          <Text color="yellow">{layout.message.join('\n')}</Text>
        </Box>
      )}
      <Footer state={shown} layout={layout} />
    </Box>
  );
}

function fixMessage(run: FixRun, total: number): string {
  const committed = run.results.filter((result) => result.commit !== null).length;
  const stopped = run.stoppedAtCap ? ' Stopped at the cap; press F again to continue the branch.' : run.interrupted ? ' Stopped with Ctrl+C.' : '';
  if (total === 1 && run.results.length === 1) {
    const result = run.results[0]!;
    if (result.commit) return `${result.finding.id} is fixed on branch ${run.branch}. Open it to see the change.${stopped}`;
    return `${result.finding.id} is not fixed: ${result.error ?? result.status.replace(/_/g, ' ')}.${stopped}`;
  }
  const already = run.alreadyOnBranch > 0 ? ` ${run.alreadyOnBranch} were already on it.` : '';
  return `${committed} of ${run.results.length} fixed${run.branch ? ` on branch ${run.branch}` : ''}.${already}${stopped}`;
}

function decidedMessage(finding: LocalFinding, decision: DecisionState | 'open', decided: Decided): string {
  if (decision === 'open') return `${finding.id} is open again; its decision is removed from ${decided.file}.`;
  const lifted = decision === 'false_positive' && finding.kind === 'secret' && finding.location && !decided.protectedPaths.has(finding.location.path);
  return [
    `Marked ${finding.id} as ${DECISION_LABEL[decision]} in ${decided.file}; commit it to share the decision.`,
    ...(CLOSED_STATES.has(decision) ? ['It is hidden now; press a to show it.'] : []),
    ...(lifted ? [`Checks may now read ${finding.location!.path} and send it to the model.`] : []),
  ].join(' ');
}

/** Keeps the cursor on screen and the detail page from scrolling past its end. */
function fitToScreen(state: BrowserState, layout: Layout, _columns: number): BrowserState {
  const fitted = withViewport(state, layout.body);
  if (fitted.view !== 'detail') return fitted;
  const last = Math.max(0, detailLines(fitted, layout.inner).length - layout.body);
  return fitted.detailScroll > last ? { ...fitted, detailScroll: last } : fitted;
}

export function toKey(input: string, key: InkKey): Key {
  if (key.ctrl && input === 'c') return { name: 'c', ctrl: true };
  if (key.upArrow) return { name: 'up' };
  if (key.downArrow) return { name: 'down' };
  if (key.leftArrow) return { name: 'left' };
  if (key.rightArrow) return { name: 'right' };
  if (key.pageUp) return { name: 'pageup' };
  if (key.pageDown) return { name: 'pagedown' };
  if (key.home) return { name: 'home' };
  if (key.end) return { name: 'end' };
  if (key.return) return { name: 'return' };
  if (key.escape) return { name: 'escape' };
  if (key.backspace || key.delete) return { name: 'backspace' };
  if (input === ' ') return { name: 'space' };
  return { sequence: input };
}

function Header({ state, columns }: { state: BrowserState; columns: number }) {
  const visible = visibleFindings(state);
  const home = homedir();
  const root = state.root.startsWith(home) ? `~${state.root.slice(home.length)}` : state.root;
  return (
    <Box width={columns} height={1} paddingX={1} overflow="hidden">
      <Box flexShrink={1} overflow="hidden">
        <Text wrap="truncate-end">
          <Text bold color={ACCENT}>
            ◆ minotaur
          </Text>
          <Text dimColor>{`  ${root}`}</Text>
          {state.commit && <Text color="yellow">{`  @ ${state.commit}`}</Text>}
        </Text>
      </Box>
      <Spacer />
      <Box flexShrink={0}>
        {state.minSeverity && <Text dimColor>{`${state.minSeverity} and above  `}</Text>}
        {severityCounts(visible).map(({ severity, count }) => (
          <Text key={severity} color={SEVERITY_COLOR[severity]}>{`● ${count} ${severity}  `}</Text>
        ))}
        {visible.length === 0 && <Text dimColor>no findings  </Text>}
        {!state.showNoise && hiddenCount(state) > 0 && <Text dimColor>{`${hiddenCount(state)} hidden  `}</Text>}
        {state.ignored > 0 && <Text dimColor>{`${state.ignored} ignored`}</Text>}
      </Box>
    </Box>
  );
}

function toolWidth(findings: readonly LocalFinding[]): number {
  return Math.min(14, Math.max(4, ...findings.map((finding) => toolsOf(finding).length)));
}

/** As wide as the longest label shown, so a full branch name fits and the title keeps its room when there is none. */
function fixColumnWidth(state: BrowserState, findings: readonly LocalFinding[]): number {
  return Math.min(40, Math.max(14, ...findings.map((finding) => fixLabel(state, finding).text.length)));
}

function FindingList({ state, layout }: { state: BrowserState; layout: Layout }) {
  const findings = visibleFindings(state);
  const tool = toolWidth(findings);
  const fixWidth = fixColumnWidth(state, findings);
  const rows = findings.slice(state.top, state.top + layout.body);
  // Narrow terminals drop the columns that matter least, so the title keeps some room.
  const wide = layout.inner >= 100;
  const medium = layout.inner >= 76;
  return (
    <Box borderStyle="round" borderColor="gray" flexDirection="column" paddingX={1} height={layout.body + 3}>
      <Box height={1} columnGap={2}>
        <Box width={1} />
        <Box width={1} />
        <Cell width={8} text="ID" dim bold />
        <Cell width={10} text="SEVERITY" dim bold />
        {wide && <Cell width={6} text="KIND" dim bold />}
        <Cell width={17} text="CHECK" dim bold />
        <Cell width={fixWidth} text="FIX" dim bold />
        {wide && <Cell width={tool} text="TOOL" dim bold />}
        <Cell grow={3} text="TITLE" dim bold />
        {medium && <Cell grow={2} text="LOCATION" dim bold />}
      </Box>
      {rows.length === 0 && (
        <Text dimColor>
          {state.findings.length === 0
            ? 'No findings.'
            : state.minSeverity
              ? 'No findings at this severity; press s to show more.'
              : 'Every finding is rated as noise; press a to show them.'}
        </Text>
      )}
      {rows.map((finding, index) => {
        const selected = state.top + index === state.cursor;
        const check = checkLabel(state, finding);
        const fix = fixLabel(state, finding);
        return (
          <Box key={finding.fingerprint} height={1} columnGap={2} {...(selected ? { backgroundColor: '#2d2d44' } : {})}>
            <Box width={1}>
              <Text color={ACCENT} bold>
                {selected ? '❯' : ' '}
              </Text>
            </Box>
            <Box width={1}>
              {finding.focus === 'likely' ? (
                <Text color="yellow" bold>
                  !
                </Text>
              ) : (
                <Text> </Text>
              )}
            </Box>
            <Cell width={8} text={finding.id} dim={!selected} bold={selected} />
            <Cell width={10} text={`● ${finding.severity}`} color={SEVERITY_COLOR[finding.severity]} bold={selected} />
            {wide && <Cell width={6} text={finding.kind} dim={!selected} />}
            <Box width={17} flexShrink={0} overflow="hidden">
              {check.running ? (
                <Spinner label={check.text} />
              ) : (
                <Text wrap="truncate-end" {...styleProps(check)}>
                  {check.text}
                </Text>
              )}
            </Box>
            <Box width={fixWidth} flexShrink={0} overflow="hidden">
              {fix.running ? (
                <Spinner label={fix.text} />
              ) : (
                <Text wrap="truncate-end" {...styleProps(fix)}>
                  {fix.text}
                </Text>
              )}
            </Box>
            {wide && <Cell width={tool} text={toolsOf(finding)} dim={!selected} />}
            <Cell grow={3} text={finding.title} bold={selected} dim={finding.focus === 'noise' && !selected} />
            {medium && <Cell grow={2} text={locationOf(finding)} color="cyan" dim={!selected} />}
          </Box>
        );
      })}
    </Box>
  );
}

function Cell(props: { text: string; width?: number; grow?: number; color?: string; dim?: boolean; bold?: boolean }) {
  const size = props.width !== undefined ? { width: props.width, flexShrink: 0 } : { flexGrow: props.grow ?? 1, flexBasis: 0 };
  return (
    <Box {...size} overflow="hidden">
      <Text wrap="truncate-end" {...styleProps({ text: props.text, ...pick(props) })}>
        {props.text}
      </Text>
    </Box>
  );
}

function pick(props: { color?: string; dim?: boolean; bold?: boolean }): Omit<Segment, 'text'> {
  return {
    ...(props.color ? { color: props.color } : {}),
    ...(props.dim ? { dim: true } : {}),
    ...(props.bold ? { bold: true } : {}),
  };
}

function styleProps(segment: Segment & { dim?: boolean | undefined }) {
  return {
    ...(segment.color ? { color: segment.color } : {}),
    ...(segment.backgroundColor ? { backgroundColor: segment.backgroundColor } : {}),
    ...(segment.bold ? { bold: true } : {}),
    ...(segment.dim ? { dimColor: true } : {}),
  };
}

function FindingDetail({ state, layout }: { state: BrowserState; layout: Layout }) {
  const lines = detailLines(state, layout.inner).slice(state.detailScroll, state.detailScroll + layout.body);
  return (
    <Box borderStyle="round" borderColor="gray" flexDirection="column" paddingX={1} height={layout.body + 2}>
      {lines.map((line, index) => (
        <DetailLine key={`${state.detailScroll + index}`} line={line} width={layout.inner} />
      ))}
    </Box>
  );
}

function DetailLine({ line, width }: { line: Line; width: number }) {
  if ('spinner' in line) return <Spinner label={line.spinner} />;
  if ('progress' in line) {
    return (
      <Box width={Math.min(40, width)} height={1}>
        <ProgressBar value={line.progress} />
      </Box>
    );
  }
  if (line.segments.length === 0) return <Text> </Text>;
  return (
    <Text wrap="truncate-end">
      {line.segments.map((segment, index) => (
        <Text key={index} {...styleProps(segment)}>
          {segment.text}
        </Text>
      ))}
    </Text>
  );
}

function Footer({ state, layout }: { state: BrowserState; layout: Layout }) {
  // The count is what F would fix now, so it follows the filters.
  const keys = state.view === 'list' ? LIST_KEYS.map(([key, label]): [string, string] => (key === 'F' ? [key, `${label} (${fixableShown(state).length})`] : [key, label])) : DETAIL_KEYS;
  const running = state.running;
  const finding = running ? state.findings.find((item) => item.fingerprint === running.fingerprint) : undefined;
  const total = visibleFindings(state).length;
  const detailLength = state.view === 'detail' ? detailLines(state, layout.inner).length : 0;
  const more = state.view === 'detail' && state.detailScroll + layout.body < detailLength;
  if (state.question) {
    return (
      <Box height={1} paddingX={1} overflow="hidden">
        <Text wrap="truncate-start">
          {questionPrompt(state.question).map((segment, index) => (
            <Text key={index} bold={segment.bold ?? false} dimColor={segment.dim ?? false} {...(segment.color ? { color: segment.color } : {})}>
              {segment.text}
            </Text>
          ))}
        </Text>
      </Box>
    );
  }
  if (state.marking) {
    return (
      <Box height={1} paddingX={1} overflow="hidden">
        <Text wrap="truncate-start">
          {markingPrompt(state.marking).map((segment, index) => (
            <Text key={index} bold={segment.bold ?? false} dimColor={segment.dim ?? false} {...(segment.color ? { color: segment.color } : {})}>
              {segment.text}
            </Text>
          ))}
        </Text>
      </Box>
    );
  }
  return (
    <Box height={1} paddingX={1} overflow="hidden">
      <Box flexShrink={1} overflow="hidden">
        <Text wrap="truncate-end">
          {keys.map(([key, label]) => (
            <Text key={key}>
              <Text bold color={ACCENT}>
                {key}
              </Text>
              <Text dimColor>{` ${label}   `}</Text>
            </Text>
          ))}
        </Text>
      </Box>
      <Spacer />
      <Box flexShrink={0} marginLeft={1}>
        {state.fixing ? (
          <Spinner
            label={`fixing ${state.fixing.current ?? ''}${state.fixing.total > 1 ? ` (${state.fixing.index + 1} of ${state.fixing.total})` : ''} · ${state.fixing.phase}`}
          />
        ) : running ? (
          <Spinner
            label={`checking ${finding?.id ?? ''} · step ${running.steps}/${running.maxSteps}${state.queue.length > 0 ? ` · ${state.queue.length} queued` : ''}`}
          />
        ) : state.view === 'list' ? (
          <Text dimColor>{total > 0 ? `${state.cursor + 1} of ${total}` : ''}</Text>
        ) : (
          <Text dimColor>{more ? '↓ more' : 'end'}</Text>
        )}
      </Box>
    </Box>
  );
}
