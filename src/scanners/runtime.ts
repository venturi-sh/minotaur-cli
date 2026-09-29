/**
 * Sandboxed execution.
 *
 * Scanning means running third-party tooling over untrusted customer code, so
 * every scanner is confined: read-only root filesystem, no capabilities, no
 * network, non-writable source mount, and hard limits on CPU, memory, PIDs and
 * wall clock.
 *
 * `ScanRuntime` is an interface rather than a concrete class because the Docker
 * implementation is not portable everywhere. Render, in particular, does not
 * allow Docker-in-Docker, so a Fly Machines or Kubernetes Job implementation
 * will eventually sit alongside this one. Nothing above this layer should know
 * which runtime it is talking to.
 *
 * The CLI runs scanners directly on the machine (see `local.ts`) and uses only
 * the types here. They stay so the adapters match the Minotaur platform's.
 */

import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readdir } from 'node:fs/promises';

export interface Mount {
  type: 'bind' | 'volume';
  source: string;
  target: string;
  readOnly: boolean;
}

export interface SandboxSpec {
  /** Always pinned by digest. Tags are mutable and would make scans irreproducible. */
  image: string;
  args: readonly string[];
  mounts?: readonly Mount[];
  env?: Readonly<Record<string, string>>;
  /** Defaults to 'none'. Only the database sync job should ever need the network. */
  network?: 'none' | 'bridge';
  timeoutMs?: number;
  memory?: string;
  cpus?: string;
  pidsLimit?: number;
}

export interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

const DEFAULTS = {
  timeoutMs: 10 * 60 * 1000,
  memory: '2g',
  cpus: '2',
  pidsLimit: 512,
} as const;

/** Guards against a runaway scanner exhausting the worker's memory. */
const MAX_OUTPUT_BYTES = 256 * 1024 * 1024;

export interface ScanRuntime {
  run(spec: SandboxSpec): Promise<SandboxResult>;
}

export class DockerRuntime implements ScanRuntime {
  async run(spec: SandboxSpec): Promise<SandboxResult> {
    const name = `minotaur-scan-${randomUUID()}`;
    const timeoutMs = spec.timeoutMs ?? DEFAULTS.timeoutMs;
    const args = buildDockerArgs(name, spec);

    const startedAt = Date.now();
    const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let overflowed = false;

    child.stdout.on('data', (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        overflowed = true;
        void kill(name);
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));

    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      // Killing the docker CLI would orphan the container, so stop the
      // container itself and let the CLI exit on its own.
      void kill(name);
    }, timeoutMs);

    const exitCode = await new Promise<number>((resolve, reject) => {
      child.on('error', reject);
      child.on('close', (code) => resolve(code ?? -1));
    }).finally(() => clearTimeout(timer));

    if (overflowed) {
      throw new Error(`Scanner ${spec.image} produced more than ${MAX_OUTPUT_BYTES} bytes of output`);
    }

    return {
      exitCode,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8'),
      durationMs: Date.now() - startedAt,
      timedOut,
    };
  }
}

export function buildDockerArgs(name: string, spec: SandboxSpec): string[] {
  const args = [
    'run',
    '--rm',
    '--name',
    name,
    '--network',
    spec.network ?? 'none',
    '--read-only',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    String(spec.pidsLimit ?? DEFAULTS.pidsLimit),
    '--memory',
    spec.memory ?? DEFAULTS.memory,
    // Matching swap to memory stops a memory-capped container from simply
    // swapping instead of being killed.
    '--memory-swap',
    spec.memory ?? DEFAULTS.memory,
    '--cpus',
    spec.cpus ?? DEFAULTS.cpus,
    // The read-only rootfs needs a writable scratch area somewhere, and a
    // noexec tmpfs means nothing dropped there can be run.
    '--tmpfs',
    '/tmp:rw,noexec,nosuid,nodev,size=1g',
  ];

  for (const mount of spec.mounts ?? []) {
    const parts = [`type=${mount.type}`, `src=${mount.source}`, `dst=${mount.target}`];
    if (mount.readOnly) parts.push('readonly');
    args.push('--mount', parts.join(','));
  }

  for (const [key, value] of Object.entries(spec.env ?? {})) {
    args.push('--env', `${key}=${value}`);
  }

  args.push(spec.image, ...spec.args);
  return args;
}

async function kill(name: string): Promise<void> {
  await new Promise<void>((resolve) => {
    const child = spawn('docker', ['kill', name], { stdio: 'ignore' });
    child.on('close', () => resolve());
    child.on('error', () => resolve());
  });
}

/** Minimal pinned image used only to look at a mount. */
const PROBE_IMAGE =
  'alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b';

/**
 * Confirms the container can actually see the source before a scanner is
 * trusted to report on it.
 *
 * Docker does not fail when a bind mount source is outside the daemon's shared
 * paths: it mounts an empty directory instead. The scanner then runs happily
 * over nothing and reports zero findings, which is indistinguishable from a
 * clean repository. For a security product that is the worst possible failure
 * mode, so an empty mount is treated as a hard error rather than a clean bill
 * of health.
 */
export async function assertWorkspaceVisible(
  runtime: ScanRuntime,
  hostPath: string,
  target = '/workspace',
): Promise<void> {
  const hostEntries = await readdir(hostPath);
  if (hostEntries.length === 0) {
    throw new Error(`Workspace ${hostPath} is empty on the host; nothing to scan`);
  }

  const probe = await runtime.run({
    image: PROBE_IMAGE,
    args: ['sh', '-c', `ls -A ${target} | wc -l`],
    mounts: [{ type: 'bind', source: hostPath, target, readOnly: true }],
    timeoutMs: 60_000,
    memory: '128m',
    cpus: '1',
  });

  const visible = Number.parseInt(probe.stdout.trim(), 10);
  if (!Number.isFinite(visible) || visible === 0) {
    throw new Error(
      `Workspace mount is empty inside the container while the host has ${hostEntries.length} ` +
        `entries. Docker silently substitutes an empty directory when the source path is not ` +
        `shared with the daemon. Host path: ${hostPath}`,
    );
  }
}

export async function ensureVolume(name: string): Promise<void> {
  const exists = await run('docker', ['volume', 'inspect', name]);
  if (exists.code === 0) return;
  const created = await run('docker', ['volume', 'create', name]);
  if (created.code !== 0) {
    throw new Error(`Could not create docker volume ${name}: ${created.stderr}`);
  }
}

function run(command: string, args: string[]): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ['ignore', 'ignore', 'pipe'] });
    const stderr: Buffer[] = [];
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.on('close', (code) => resolve({ code: code ?? -1, stderr: Buffer.concat(stderr).toString('utf8') }));
    child.on('error', (error) => resolve({ code: -1, stderr: String(error) }));
  });
}
