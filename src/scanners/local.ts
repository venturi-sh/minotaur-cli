/**
 * Scanning on the machine the CLI runs on: installed scanners, or reports a
 * person already produced.
 *
 * Both paths end in the same adapters the worker uses. Scanner output names
 * files by the absolute path of the repository, so that prefix is rewritten to
 * the sandbox mount before parsing. The adapters then strip it exactly as they
 * do for a container run, and a finding gets the same identity either way.
 */

import { spawn } from 'node:child_process';
import { access, constants, realpath } from 'node:fs/promises';
import { delimiter, isAbsolute, join, relative, sep } from 'node:path';

import type { Finding } from '../core/index.js';

import { WORKSPACE_MOUNT, createSnippetReader, succeeded, type ScanContext, type ScannerAdapter } from './adapter.js';
import type { DetectedTarget } from './detect.js';
import { LOCAL_SCANNERS, scannerByName } from './registry.js';
import { isSarif, normalizeReportedPath, parseSarif } from './sarif.js';

/** Fingerprints include a project; locally there is one, and it must not vary between runs. */
export const LOCAL_PROJECT_ID = 'local';

const EMPTY_TARGET: DetectedTarget = {
  ecosystems: [],
  languages: [],
  hasIac: false,
  hasContainerfile: false,
  hasKubernetes: false,
  hasCode: false,
  fileCount: 0,
};

const MAX_OUTPUT_BYTES = 256 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 20 * 60 * 1000;

export async function isInstalled(binary: string, path = process.env['PATH'] ?? ''): Promise<boolean> {
  const names = process.platform === 'win32' ? [`${binary}.exe`, `${binary}.cmd`, binary] : [binary];
  for (const dir of path.split(delimiter).filter(Boolean)) {
    for (const name of names) {
      try {
        await access(join(dir, name), constants.X_OK);
        return true;
      } catch {
        // Not in this directory.
      }
    }
  }
  return false;
}

/** Scanners with a native command that are on PATH, in fleet order. */
export async function installedScanners(): Promise<ScannerAdapter[]> {
  const found: ScannerAdapter[] = [];
  for (const scanner of LOCAL_SCANNERS) {
    if (scanner.native && (await isInstalled(scanner.native.binary))) found.push(scanner);
  }
  return found;
}

export interface NativeRunOptions {
  /** Replaces the scanner's default arguments. */
  args?: readonly string[] | undefined;
  /** A path to the executable, instead of looking the binary up on PATH. */
  binary?: string | undefined;
  timeoutMs?: number | undefined;
  target?: DetectedTarget | undefined;
}

export interface NativeRunResult {
  scanner: string;
  findings: Finding[];
  exitCode: number;
  durationMs: number;
  stderr: string;
}

export async function runInstalledScanner(
  adapter: ScannerAdapter,
  root: string,
  options: NativeRunOptions = {},
): Promise<NativeRunResult> {
  const native = adapter.native;
  if (!native) throw new Error(`${adapter.name} cannot run outside a container`);
  const args = native.args(root, options.args ?? native.defaultArgs ?? []);
  const started = Date.now();
  const { exitCode, stdout, stderr, timedOut } = await spawnCapture(
    options.binary ?? native.binary,
    args,
    root,
    options.timeoutMs,
  );
  if (timedOut) throw new Error(`${adapter.name} timed out`);
  if (!succeeded(adapter, exitCode)) {
    const detail = stderr.trim().split('\n').slice(-3).join(' ').slice(0, 500);
    throw new Error(`${adapter.name} exited with code ${exitCode}${detail ? `: ${detail}` : ''}`);
  }
  const findings = await parseScannerOutput(adapter, stdout, root, options.target);
  return { scanner: adapter.name, findings, exitCode, durationMs: Date.now() - started, stderr };
}

export async function parseScannerOutput(
  adapter: ScannerAdapter,
  output: string,
  root: string,
  target: DetectedTarget = EMPTY_TARGET,
): Promise<Finding[]> {
  const context = await localContext(root, target);
  const findings = adapter.parse(await remapRoot(output, root), context);
  return findings.map((finding) => withRepoPath(finding, context.workspace));
}

export const REPORT_FORMATS = ['sarif', 'semgrep', 'trivy', 'grype', 'osv-scanner', 'trufflehog', 'checkov'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

/** Recognizes a report by its shape, since file names say nothing reliable. */
export function detectReportFormat(text: string): ReportFormat | null {
  const trimmed = text.trim();
  let value: unknown;
  try {
    value = JSON.parse(trimmed);
  } catch {
    // TruffleHog writes one JSON object per line.
    const first = trimmed.split('\n').find((line) => line.trim().startsWith('{'));
    if (first && /"DetectorName"|"SourceMetadata"/.test(first)) return 'trufflehog';
    return null;
  }
  if (isSarif(value)) return 'sarif';
  if (Array.isArray(value)) return value.some(isCheckovResult) ? 'checkov' : null;
  if (typeof value !== 'object' || value === null) return null;
  const record = value as Record<string, unknown>;
  if (isCheckovResult(record)) return 'checkov';
  if ('SchemaVersion' in record || 'ArtifactName' in record) return 'trivy';
  if (Array.isArray(record['matches'])) return 'grype';
  if (Array.isArray(record['results'])) {
    const results = record['results'] as unknown[];
    if (results.some((item) => typeof item === 'object' && item !== null && 'check_id' in item)) return 'semgrep';
    if (results.some((item) => typeof item === 'object' && item !== null && ('packages' in item || 'source' in item))) {
      return 'osv-scanner';
    }
    // An empty Semgrep report still lists what it scanned.
    if ('paths' in record || 'errors' in record) return 'semgrep';
    return 'osv-scanner';
  }
  if ('DetectorName' in record) return 'trufflehog';
  return null;
}

function isCheckovResult(value: unknown): boolean {
  return typeof value === 'object' && value !== null && 'check_type' in value;
}

export async function parseReport(
  text: string,
  root: string,
  format: ReportFormat | null = detectReportFormat(text),
): Promise<{ format: ReportFormat; findings: Finding[] }> {
  if (!format) {
    throw new Error(`unrecognized report format; expected SARIF or the JSON output of ${REPORT_FORMATS.slice(1).join(', ')}`);
  }
  const context = await localContext(root, EMPTY_TARGET);
  const remapped = await remapRoot(text, root);
  if (format === 'sarif') {
    return { format, findings: parseSarif(remapped, context).map((finding) => withRepoPath(finding, context.workspace)) };
  }
  const adapter = scannerByName(format);
  if (!adapter) throw new Error(`no adapter for ${format}`);
  return { format, findings: adapter.parse(remapped, context).map((finding) => withRepoPath(finding, context.workspace)) };
}

async function localContext(root: string, target: DetectedTarget): Promise<ScanContext> {
  const workspace = await realpath(root);
  return {
    projectId: LOCAL_PROJECT_ID,
    workspace,
    cacheVolume: '',
    target,
    readSnippet: createSnippetReader(workspace),
  };
}

/**
 * Rewrites the repository's absolute path to the sandbox mount, in both its
 * plain and JSON-escaped forms, and under its realpath too, since macOS
 * reports `/private/var` for `/var`.
 */
export async function remapRoot(text: string, root: string): Promise<string> {
  const roots = [...new Set([stripTrailing(root), stripTrailing(await realpath(root))])].filter((item) => item.length > 1);
  let result = text;
  for (const item of roots.sort((a, b) => b.length - a.length)) {
    result = result.split(`${item}${sep}`).join(`${WORKSPACE_MOUNT}/`);
    const escaped = JSON.stringify(item).slice(1, -1);
    if (escaped !== item) result = result.split(`${escaped}${JSON.stringify(sep).slice(1, -1)}`).join(`${WORKSPACE_MOUNT}/`);
    if (sep === '/') result = result.split(`${item.replaceAll('/', '\\/')}\\/`).join(`${WORKSPACE_MOUNT}/`);
  }
  return result;
}

function stripTrailing(path: string): string {
  return path.length > 1 && path.endsWith(sep) ? path.slice(0, -1) : path;
}

/** The last word on a location: repository-relative, with any wrapping a tool added removed. */
function withRepoPath(finding: Finding, root: string): Finding {
  if (!finding.location) return finding;
  let path = normalizeReportedPath(finding.location.path);
  if (isAbsolute(path)) {
    const inside = relative(root, path);
    if (!inside.startsWith('..') && !isAbsolute(inside)) path = inside;
  }
  path = path.split(sep).join('/');
  return path === finding.location.path ? finding : { ...finding, location: { ...finding.location, path } };
}

function spawnCapture(
  command: string,
  args: readonly string[],
  cwd: string,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<{ exitCode: number; stdout: string; stderr: string; timedOut: boolean }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let timedOut = false;
    let overflowed = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, timeoutMs);

    child.stdout.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT_BYTES) {
        overflowed = true;
        child.kill('SIGTERM');
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (overflowed) return reject(new Error(`${command} produced more than ${MAX_OUTPUT_BYTES} bytes of output`));
      resolve({
        exitCode: code ?? -1,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
        timedOut,
      });
    });
  });
}
