/**
 * The scanner adapter contract.
 *
 * Every tool answers the same four questions: do you apply to this target, how
 * do I run you, did you succeed, and how do I turn your output into canonical
 * findings. Everything tool-specific lives behind this interface so the worker
 * pipeline never grows a branch per scanner.
 */

import { readFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';

import type { Finding } from '../core/index.js';

import type { DetectedTarget } from './detect.js';
import type { Mount, SandboxSpec } from './runtime.js';

export const WORKSPACE_MOUNT = '/workspace';
export const CACHE_MOUNT = '/cache';

export interface ScanContext {
  projectId: string;
  /** Host path to the source. Mounted read-only into the sandbox. */
  workspace: string;
  /** Docker volume holding pre-warmed vulnerability databases and rulesets. */
  cacheVolume: string;
  target: DetectedTarget;
  /**
   * Reads the matched source out of the workspace. Adapters use it when their
   * tool reports a location but no code, which is what keeps a code finding's
   * identity tied to content rather than to a line number.
   */
  readSnippet?(path: string, startLine: number, endLine: number): string | undefined;
}

/** How much of a multi-line match contributes to a finding's identity. */
const MAX_SNIPPET_LINES = 20;

/**
 * A snippet reader over a workspace, with a small cache because scanners
 * usually report several findings per file.
 */
export function createSnippetReader(workspace: string): NonNullable<ScanContext['readSnippet']> {
  const root = resolve(workspace);
  const cache = new Map<string, string[] | null>();

  return (path, startLine, endLine) => {
    const absolute = isAbsolute(path) ? resolve(path) : resolve(join(root, path));
    // A scanner reporting a path outside the workspace means something is
    // wrong; reading it would be worse than returning nothing.
    if (absolute !== root && !absolute.startsWith(`${root}/`)) return undefined;

    let lines = cache.get(absolute);
    if (lines === undefined) {
      try {
        lines = readFileSync(absolute, 'utf8').split('\n');
      } catch {
        lines = null;
      }
      cache.set(absolute, lines);
    }
    if (lines === null) return undefined;

    const from = Math.max(1, startLine);
    const to = Math.min(lines.length, Math.max(from, endLine), from + MAX_SNIPPET_LINES - 1);
    const slice = lines.slice(from - 1, to).join('\n').trim();
    return slice.length > 0 ? slice : undefined;
  };
}

export interface ScannerAdapter {
  name: string;
  version: string;
  /**
   * Whether this scanner has anything to do. Skipping is meaningfully different
   * from finding nothing, and the distinction is recorded on the scan task.
   */
  appliesTo(target: DetectedTarget): boolean;
  spec(context: ScanContext): SandboxSpec;
  parse(stdout: string, context: ScanContext): Finding[];
  /**
   * Several scanners exit non-zero precisely because they found something.
   * Defaults to "zero means success".
   */
  isSuccess?(exitCode: number): boolean;
  /**
   * Refreshes databases or rulesets into the cache volume. The only place a
   * scanner is allowed network access, and never during a scan.
   */
  databaseSync?(options: DatabaseSyncOptions): SandboxSpec[];
  /**
   * Files the sync driver should materialize into a scratch directory before
   * calling `databaseSync`. Some tools only fetch the databases for ecosystems
   * they can see, so priming them requires something to look at.
   */
  primingFiles?: Readonly<Record<string, string>>;
  /**
   * Paths inside the cache volume that must exist before this scanner can run
   * offline. Checked at startup so a missing database is reported as a missing
   * database rather than as a scanner that mysteriously fails.
   */
  cachePaths?: readonly string[];
  /**
   * How to run the tool when it is installed on the machine rather than in a
   * container, as the CLI does. No sandbox: the person running it chose to.
   */
  native?: NativeCommand;
}

export interface NativeCommand {
  binary: string;
  /** Arguments used when the configuration gives none, such as Semgrep's ruleset. */
  defaultArgs?: readonly string[];
  /** The full argument list for scanning `root`, with `extra` in place of `defaultArgs`. */
  args(root: string, extra: readonly string[]): string[];
}

export interface DatabaseSyncOptions {
  cacheVolume: string;
  /** Host path to the materialized `primingFiles`, when the adapter asked for any. */
  primingDir: string;
}

export function succeeded(adapter: ScannerAdapter, exitCode: number): boolean {
  return adapter.isSuccess ? adapter.isSuccess(exitCode) : exitCode === 0;
}

/** Mounts shared by every scanner: read-only source, read-only database cache. */
export function standardMounts(context: ScanContext, cacheReadOnly = true): Mount[] {
  return [
    { type: 'bind', source: context.workspace, target: WORKSPACE_MOUNT, readOnly: true },
    { type: 'volume', source: context.cacheVolume, target: CACHE_MOUNT, readOnly: cacheReadOnly },
  ];
}

/**
 * A read-only root filesystem leaves no writable home directory, and most of
 * these tools want one.
 */
export const SANDBOX_ENV = { HOME: '/tmp', TMPDIR: '/tmp', XDG_CACHE_HOME: '/tmp' } as const;
