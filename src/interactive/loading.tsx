/**
 * The screen shown while the findings are gathered: each source with its
 * state and time, plus downloads and the steps before and after the scan.
 */

import { homedir } from 'node:os';

import { Spinner } from '@inkjs/ui';
import { Box, Spacer, Text } from 'ink';
import { useEffect, useState } from 'react';

import type { SourceOutcome } from '../sources.js';
import { ACCENT } from './content.js';

/** How gathering the findings reports progress. */
export interface ScanReporter {
  /** Something that takes a moment and is not a source, such as working out which scanners apply. */
  step(text: string): void;
  sources(names: readonly string[]): void;
  start(name: string): void;
  done(outcome: SourceOutcome): void;
  /** Something worth reading that is not an error, such as a download. */
  note(text: string): void;
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

const LOOKS_AT: Record<string, string> = {
  trivy: 'dependencies, secrets and configuration',
  opengrep: 'code',
  semgrep: 'code',
  grype: 'dependencies',
  'osv-scanner': 'dependencies',
  trufflehog: 'secrets',
  checkov: 'infrastructure configuration',
};

export function duration(ms: number): string {
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const seconds = Math.floor(ms / 1000);
  return `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, '0')}s`;
}

export function Loading({
  root,
  commit,
  state,
  columns,
  rows,
}: {
  root: string;
  commit: string | null;
  state: ScanState;
  columns: number;
  rows: number;
}) {
  const running = state.sources.some((row) => row.status === 'running');
  const now = useNow(running);
  const home = homedir();
  const shown = root.startsWith(home) ? `~${root.slice(home.length)}` : root;
  const finished = state.sources.filter((row) => row.outcome).length;
  const name = Math.max(8, ...state.sources.map((row) => row.name.length)) + 2;
  return (
    <Box flexDirection="column" width={columns} height={rows}>
      <Box height={1} paddingX={1}>
        <Text wrap="truncate-end">
          <Text bold color={ACCENT}>
            ◆ minotaur
          </Text>
          <Text dimColor>{`  ${shown}`}</Text>
          {commit && <Text color="yellow">{`  @ ${commit}`}</Text>}
        </Text>
      </Box>
      <Box borderStyle="round" borderColor="gray" flexDirection="column" paddingX={2} paddingY={1} flexGrow={1}>
        <Text bold>
          {state.sources.length > 0 ? `Scanning, ${finished} of ${state.sources.length} sources done` : 'Preparing the scan'}
        </Text>
        <Box flexDirection="column" marginTop={1}>
          {state.sources.map((row) => (
            <Box key={row.name} height={1}>
              <Box width={3} flexShrink={0}>
                <Icon row={row} />
              </Box>
              <Box width={name} flexShrink={0}>
                <Text bold={row.status === 'running'} dimColor={row.status === 'waiting'}>
                  {row.name}
                </Text>
              </Box>
              <Box flexGrow={1} flexBasis={0} overflow="hidden">
                <Status row={row} />
              </Box>
              <Box width={9} flexShrink={0} justifyContent="flex-end">
                <Text dimColor>
                  {row.outcome ? duration(row.outcome.durationMs) : row.startedAt !== undefined ? duration(now - row.startedAt) : ''}
                </Text>
              </Box>
            </Box>
          ))}
          {state.step && <Spinner label={state.step} />}
        </Box>
        {state.notes.length > 0 && (
          <Box flexDirection="column" marginTop={1}>
            {state.notes.map((note, index) => (
              <Text key={index} dimColor wrap="wrap">
                {note}
              </Text>
            ))}
          </Box>
        )}
        <Spacer />
        {!running && state.sources.length === 0 ? null : (
          <Text dimColor>The first scan of a repository takes longest; later ones are reused while nothing changes.</Text>
        )}
      </Box>
      <Box height={1} paddingX={1}>
        <Text>
          <Text bold color={ACCENT}>
            ctrl+c
          </Text>
          <Text dimColor> stop</Text>
        </Text>
      </Box>
    </Box>
  );
}

function Icon({ row }: { row: SourceRow }) {
  if (row.status === 'running') return <Spinner />;
  if (row.status === 'ok') return <Text color="green">✓</Text>;
  if (row.status === 'failed') return <Text color="red">✗</Text>;
  if (row.status === 'skipped') return <Text dimColor>–</Text>;
  return <Text dimColor>○</Text>;
}

function Status({ row }: { row: SourceRow }) {
  const looksAt = LOOKS_AT[row.name];
  if (row.status === 'running') return <Text wrap="truncate-end">{looksAt ? `looking at ${looksAt}` : 'reading the report'}</Text>;
  if (row.status === 'waiting') return <Text dimColor wrap="truncate-end">waiting</Text>;
  const outcome = row.outcome;
  if (row.status === 'ok') {
    return <Text wrap="truncate-end">{`${outcome?.findings ?? 0} finding${outcome?.findings === 1 ? '' : 's'}`}</Text>;
  }
  if (row.status === 'skipped') return <Text dimColor wrap="truncate-end">{`skipped, ${outcome?.error ?? 'nothing to look at'}`}</Text>;
  return (
    <Text color="red" wrap="truncate-end">
      {`failed, ${outcome?.error ?? 'unknown error'}`}
    </Text>
  );
}

/** The current time, ticking while `active`, for elapsed times. */
function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => setNow(Date.now()), 200);
    return () => clearInterval(timer);
  }, [active]);
  return now;
}
