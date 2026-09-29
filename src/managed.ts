/**
 * Scanners the CLI downloads when they are not installed, so a first scan
 * needs nothing but Node: Trivy for dependencies, secrets and configuration,
 * and Opengrep with its rules for code.
 *
 * Every download is pinned by version and SHA-256, and nothing is unpacked or
 * run until its checksum matches. A scanner already on PATH always wins.
 */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { access, chmod, mkdir, mkdtemp, readdir, rename, rm } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream } from 'node:stream/web';

import { OPENGREP_VERSION, TRIVY_VERSION } from './scanners/index.js';

export type Platform = 'darwin-arm64' | 'darwin-x64' | 'linux-x64' | 'linux-arm64' | 'linux-musl-x64' | 'linux-musl-arm64' | 'win32-x64';

export interface Artifact {
  url: string;
  sha256: string;
  bytes: number;
  /** How the download is packed. A bare download is the executable itself. */
  archive?: 'tar.gz' | 'zip';
}

export interface ManagedTool {
  name: string;
  version: string;
  artifacts: Partial<Record<Platform, Artifact>>;
}

const TRIVY_RELEASE = `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}`;
const OPENGREP_RELEASE = `https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}`;

export const MANAGED_TOOLS: Readonly<Record<string, ManagedTool>> = {
  trivy: {
    name: 'trivy',
    version: TRIVY_VERSION,
    artifacts: {
      'darwin-arm64': {
        url: `${TRIVY_RELEASE}_macOS-ARM64.tar.gz`,
        sha256: '80cc25faaf6378e37701202d0b4f9f43d9e413d198d594ba60fdf559fe44a683',
        bytes: 47_186_057,
        archive: 'tar.gz',
      },
      'darwin-x64': {
        url: `${TRIVY_RELEASE}_macOS-64bit.tar.gz`,
        sha256: 'd39d1374dd3e35d48621b82df9b6625fe69f9920cc67d2739ed81bb679f16f51',
        bytes: 50_886_858,
        archive: 'tar.gz',
      },
      'linux-x64': {
        url: `${TRIVY_RELEASE}_Linux-64bit.tar.gz`,
        sha256: '2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b',
        bytes: 49_875_739,
        archive: 'tar.gz',
      },
      'linux-arm64': {
        url: `${TRIVY_RELEASE}_Linux-ARM64.tar.gz`,
        sha256: '13833d97e8a1a5367471c372a173180157f593bece570e20d5d925fef552f5dd',
        bytes: 44_928_062,
        archive: 'tar.gz',
      },
      'win32-x64': {
        url: `${TRIVY_RELEASE}_windows-64bit.zip`,
        sha256: 'd2d3ad5292aae470a03eb6506db86fce81b1894592b8451cadaf60eaa22f2025',
        bytes: 51_108_725,
        archive: 'zip',
      },
    },
  },
  opengrep: {
    name: 'opengrep',
    version: OPENGREP_VERSION,
    artifacts: {
      'darwin-arm64': {
        url: `${OPENGREP_RELEASE}/opengrep_osx_arm64`,
        sha256: '0f5bc3dec09d995c61331a4017b856ede508f90d95b018d95f1dc6166be89fdd',
        bytes: 47_364_272,
      },
      'darwin-x64': {
        url: `${OPENGREP_RELEASE}/opengrep_osx_x86`,
        sha256: '650772a849a2986880982b7dea0371f96a75d354de95f94e8c1a2e6f8f6262d1',
        bytes: 48_384_448,
      },
      'linux-x64': {
        url: `${OPENGREP_RELEASE}/opengrep_manylinux_x86`,
        sha256: '35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c',
        bytes: 46_516_392,
      },
      'linux-arm64': {
        url: `${OPENGREP_RELEASE}/opengrep_manylinux_aarch64`,
        sha256: 'a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae',
        bytes: 47_982_360,
      },
      'linux-musl-x64': {
        url: `${OPENGREP_RELEASE}/opengrep_musllinux_x86`,
        sha256: 'ee21fa70714531e1eccbcb50993a871e198fb0f4ade254ef7636c433304fe4bd',
        bytes: 48_609_096,
      },
      'linux-musl-arm64': {
        url: `${OPENGREP_RELEASE}/opengrep_musllinux_aarch64`,
        sha256: '937d0f35fc05af8877f5f34e04465f2466a8da3c33c2a0d510b8a896383354ef',
        bytes: 49_809_144,
      },
      'win32-x64': {
        url: `${OPENGREP_RELEASE}/opengrep_windows_x86.exe`,
        sha256: 'b5cf4f8fe9f44e030aab2d579d96bd395c139db1f1ba66633676ff4d5ebc7c39',
        bytes: 53_652_992,
      },
    },
  },
};

/** Opengrep's copy of the Semgrep community rules, frozen by the fork in January 2025. */
const RULES_COMMIT = 'f1d2b562b414783763fd02a6ed2736eaed622efa';
export const OPENGREP_RULES: Artifact = {
  url: `https://codeload.github.com/opengrep/opengrep-rules/tar.gz/${RULES_COMMIT}`,
  sha256: '9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d',
  bytes: 1_144_289,
  archive: 'tar.gz',
};

/** Files in the rules repository that are not rules, and would abort a scan that tried to load them. */
const NOT_RULES = [
  '.github',
  'stats',
  'scripts',
  'libsonnet',
  'Pipfile',
  'Pipfile.lock',
  'Makefile',
  'template.yaml',
  'metadata-schema.yaml.schm',
  '.pre-commit-config.yaml',
];

/** Scanners the default sources rely on, and so download when they are missing. */
export function isManaged(name: string): boolean {
  return name in MANAGED_TOOLS;
}

export function cacheDir(env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): string {
  if (env['MINOTAUR_CACHE_DIR']) return env['MINOTAUR_CACHE_DIR'];
  if (platform === 'darwin') return join(homedir(), 'Library', 'Caches', 'minotaur');
  if (platform === 'win32') return join(env['LOCALAPPDATA'] ?? join(homedir(), 'AppData', 'Local'), 'minotaur');
  return join(env['XDG_CACHE_HOME'] ?? join(homedir(), '.cache'), 'minotaur');
}

export function currentPlatform(): Platform | null {
  const { platform, arch } = process;
  if (platform === 'darwin' && (arch === 'arm64' || arch === 'x64')) return `darwin-${arch}`;
  if (platform === 'win32' && arch === 'x64') return 'win32-x64';
  if (platform === 'linux' && (arch === 'arm64' || arch === 'x64')) {
    const header = (process.report?.getReport() as { header?: { glibcVersionRuntime?: string } } | undefined)?.header;
    return header?.glibcVersionRuntime ? `linux-${arch}` : `linux-musl-${arch}`;
  }
  return null;
}

export interface EnsureOptions {
  cacheDir?: string;
  platform?: Platform | null;
  onDownload?: (message: string) => void;
  fetch?: typeof fetch;
  tools?: Readonly<Record<string, ManagedTool>>;
  rules?: Artifact;
}

/** The path of a managed scanner's executable, downloading it the first time. */
export async function ensureTool(name: string, options: EnsureOptions = {}): Promise<string> {
  const tool = (options.tools ?? MANAGED_TOOLS)[name];
  if (!tool) throw new Error(`${name} is not a scanner Minotaur can download`);
  const platform = options.platform === undefined ? currentPlatform() : options.platform;
  const artifact = platform ? tool.artifacts[platform] : undefined;
  if (!artifact) {
    throw new Error(`${name} is not installed, and there is no download of it for ${process.platform}-${process.arch}`);
  }
  const root = options.cacheDir ?? cacheDir();
  const executable = platform === 'win32-x64' ? `${name}.exe` : name;
  const dir = join(root, `${name}-${tool.version}`);
  const path = join(dir, executable);
  if (await exists(path)) return path;

  options.onDownload?.(`Downloading ${name} ${tool.version} (${megabytes(artifact.bytes)}) into ${root}, once.`);
  await install(root, dir, artifact, options.fetch ?? fetch, async (staging, file) => {
    if (artifact.archive) await extract(file, staging, [executable]);
    else await rename(file, join(staging, executable));
    await chmod(join(staging, executable), 0o755);
  });
  return path;
}

/** The directory holding the Opengrep rules, one subdirectory per language, downloading them the first time. */
export async function ensureRules(options: EnsureOptions = {}): Promise<string> {
  const artifact = options.rules ?? OPENGREP_RULES;
  const root = options.cacheDir ?? cacheDir();
  // Rule ids are derived from this path, and the part after "opengrep-rules" is what identifies a rule.
  const dir = join(root, `rules-${artifact.sha256.slice(0, 12)}`);
  const rules = join(dir, 'opengrep-rules');
  if (await exists(rules)) return rules;

  options.onDownload?.(`Downloading the Opengrep rules (${megabytes(artifact.bytes)}) into ${root}, once.`);
  await install(root, dir, artifact, options.fetch ?? fetch, async (staging, file) => {
    const target = join(staging, 'opengrep-rules');
    await mkdir(target);
    await extract(file, target, [], 1);
    await pruneRules(target);
  });
  return rules;
}

/**
 * Downloads into a staging directory beside the destination and renames it
 * into place, so an interrupted download or a failed check leaves nothing
 * that looks installed.
 */
async function install(
  root: string,
  destination: string,
  artifact: Artifact,
  fetchImpl: typeof fetch,
  unpack: (staging: string, file: string) => Promise<void>,
): Promise<void> {
  await mkdir(root, { recursive: true });
  const staging = await mkdtemp(join(root, '.download-'));
  try {
    const file = join(staging, 'download');
    await download(artifact, file, fetchImpl);
    await unpack(staging, file);
    await rm(file, { force: true });
    try {
      await rename(staging, destination);
    } catch (error) {
      // Another minotaur finished the same download first.
      if (!(await exists(destination))) throw error;
    }
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

async function download(artifact: Artifact, file: string, fetchImpl: typeof fetch): Promise<void> {
  let response: Response;
  try {
    response = await fetchImpl(artifact.url, { redirect: 'follow' });
  } catch (error) {
    throw new Error(`could not download ${artifact.url}: ${(error as Error).message}`);
  }
  if (!response.ok || !response.body) throw new Error(`could not download ${artifact.url}: HTTP ${response.status}`);

  const hash = createHash('sha256');
  const hashing = new Transform({
    transform(chunk: Buffer, _encoding, done) {
      hash.update(chunk);
      done(null, chunk);
    },
  });
  await pipeline(Readable.fromWeb(response.body as ReadableStream), hashing, createWriteStream(file));
  const digest = hash.digest('hex');
  if (digest !== artifact.sha256) {
    throw new Error(
      `${artifact.url} does not match its pinned checksum (expected ${artifact.sha256}, got ${digest}), so nothing was installed`,
    );
  }
}

function extract(archive: string, into: string, members: readonly string[], stripComponents = 0): Promise<void> {
  const args = ['-xf', archive, '-C', into, ...(stripComponents ? [`--strip-components=${stripComponents}`] : []), ...members];
  return new Promise((resolve, reject) => {
    const child = spawn('tar', args, { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
    child.on('error', (error) => reject(new Error(`could not run tar to unpack a download: ${error.message}`)));
    child.on('close', (code) =>
      code === 0 ? resolve() : reject(new Error(`unpacking ${archive} failed: ${stderr.trim() || `tar exited with ${code}`}`)),
    );
  });
}

async function pruneRules(dir: string): Promise<void> {
  await Promise.all(NOT_RULES.map((name) => rm(join(dir, name), { recursive: true, force: true })));
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith('.yml')) await rm(join(dir, entry.name));
  }
  for (const entry of await readdir(dir, { recursive: true, withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith('.test.yaml')) await rm(join(entry.parentPath, entry.name));
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function megabytes(bytes: number): string {
  return `${Math.round(bytes / 1_000_000)} MB`;
}
