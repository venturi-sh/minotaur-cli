/**
 * Dependency upgrades, done by the package manager rather than a model.
 *
 * When a scanner names the fixed version and the project uses a package
 * manager Minotaur knows, the upgrade is one command, and a model would only
 * add cost and risk. A dependency the project declares is raised in its
 * manifest; one that only comes in through another package is forced with the
 * package manager's override.
 *
 * Lockfiles are only ever written by their tool. A hand-edited lockfile can
 * name the fixed version, and satisfy the scanner, while its hashes and its
 * tree are wrong. So when a model does a dependency fix it edits the manifest,
 * and `relock` runs the tool afterwards.
 *
 * Package manager scripts are turned off, since the repository is untrusted.
 * For the same reason Yarn runs as installed, never the copy a repository
 * pins with yarnPath, and a project whose .yarnrc.yml loads plugins is left
 * alone. The tools do reach their registries.
 */

import { spawn } from 'node:child_process';
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative } from 'node:path';

import { parseDocument } from 'yaml';

import { isInstalled } from './scanners/index.js';
import type { LocalFinding } from './sources.js';

export class UpgradeError extends Error {}

/** The package manager is not installed, so no one can update the lockfile here. */
export class ToolMissingError extends UpgradeError {}

/** Lockfiles a model may never write. Only their own tool does. */
export const LOCKFILES = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'bun.lockb',
  'Cargo.lock',
  'go.sum',
  'poetry.lock',
  'Pipfile.lock',
  'uv.lock',
  'pdm.lock',
  'Gemfile.lock',
  'composer.lock',
  'packages.lock.json',
  'gradle.lockfile',
  'mix.lock',
  'pubspec.lock',
  'Package.resolved',
  'conan.lock',
] as const;

type Manager = 'npm' | 'pnpm' | 'yarn' | 'go' | 'cargo' | 'pip';
type NodeManager = 'npm' | 'pnpm' | 'yarn';

/** How a dependency finding gets fixed. */
export type UpgradePlan =
  /** Minotaur runs the package manager. */
  | { kind: 'command'; manager: Manager; dir: string; name: string; version: string; direct: boolean }
  /** A model edits the manifest; `relock` then updates the lockfile, when there is one. */
  | { kind: 'model'; dir: string; guidance: string }
  /** Neither can do it here. */
  | { kind: 'unsupported'; reason: string };

/** Lockfiles in a directory whose tool can update them after a manifest edit. */
const RELOCKABLE: Record<string, Manager> = {
  'package-lock.json': 'npm',
  'pnpm-lock.yaml': 'pnpm',
  'yarn.lock': 'yarn',
  'Cargo.lock': 'cargo',
  'go.sum': 'go',
  'go.mod': 'go',
};

/**
 * The version to upgrade to. Scanners may list several, such as "4.17.21,
 * 5.0.1", one per release line: the lowest one above the current version is
 * the smallest change.
 */
export function chooseVersion(current: string | undefined, fixed: string | undefined): string | null {
  if (!fixed) return null;
  const candidates = fixed
    .split(/[,|\s]+/)
    .map((item) => item.replace(/^[<>=~^]+/, '').trim())
    .filter((item) => /^v?\d/.test(item));
  if (candidates.length === 0) return null;
  const sorted = [...candidates].sort(compareVersions);
  const above = current ? sorted.filter((item) => compareVersions(item, current) > 0) : sorted;
  return above[0] ?? null;
}

/** Numeric parts first, then a release before its prereleases. Good enough for the versions scanners report. */
export function compareVersions(a: string, b: string): number {
  const parse = (value: string) => {
    const [core = '', pre] = value.replace(/^v/, '').split(/[-+]/, 2);
    return { parts: core.split('.').map((part) => Number.parseInt(part, 10) || 0), pre };
  };
  const x = parse(a);
  const y = parse(b);
  for (let index = 0; index < Math.max(x.parts.length, y.parts.length); index += 1) {
    const diff = (x.parts[index] ?? 0) - (y.parts[index] ?? 0);
    if (diff !== 0) return diff;
  }
  if (x.pre === y.pre) return 0;
  if (x.pre === undefined) return 1;
  if (y.pre === undefined) return -1;
  return x.pre.localeCompare(y.pre);
}

/**
 * Works out how to fix a dependency finding. `version` is the version to
 * reach, which for several findings of one package is the highest they need.
 */
export async function planUpgrade(tree: string, finding: LocalFinding, version: string | null): Promise<UpgradePlan> {
  const path = finding.location?.path;
  const name = finding.package?.name;
  if (!path || !name) return { kind: 'unsupported', reason: 'the scanner did not say which file and package this is' };
  const dir = dirname(path) === '.' ? '' : dirname(path);
  const file = basename(path);
  const has = (entry: string) => exists(join(tree, dir, entry));

  if (finding.kind === 'license') {
    return modelPlan(tree, dir, file, name, [
      `The license of ${name} is not allowed here. Replace it with a package under an acceptable license, or remove it if nothing uses it.`,
      'This is best effort. If there is no safe replacement, submit gave_up and say what a person has to decide.',
    ]);
  }

  if (version) {
    if (/^requirements.*\.(txt|in)$/i.test(file) && (await pinned(join(tree, path), name))) {
      return { kind: 'command', manager: 'pip', dir, name, version, direct: true };
    }
    if ((await has('package-lock.json')) || (await has('npm-shrinkwrap.json'))) return npmPlan(tree, dir, 'npm', name, version);
    if (await has('pnpm-lock.yaml')) return npmPlan(tree, dir, 'pnpm', name, version);
    if (await has('yarn.lock')) {
      const refused = await yarnRefusal(tree, dir);
      if (refused) return { kind: 'unsupported', reason: refused };
      return npmPlan(tree, dir, 'yarn', name, version);
    }
    if (await has('go.mod')) {
      if (name === 'stdlib' || name === 'go' || name === 'toolchain') {
        return { kind: 'unsupported', reason: `this is in the Go standard library; move the go directive in go.mod to ${version} or later` };
      }
      return { kind: 'command', manager: 'go', dir, name, version: version.startsWith('v') ? version : `v${version}`, direct: true };
    }
    if (await has('Cargo.lock')) return { kind: 'command', manager: 'cargo', dir, name, version, direct: true };
  }

  const target = version ? `${version} or later` : 'a version without this advisory';
  return modelPlan(tree, dir, file, name, [
    `Upgrade ${name}${finding.package?.version ? ` from ${finding.package.version}` : ''} to ${target} by changing its version where the project declares it.`,
    'If the project does not declare it directly, pin it where the ecosystem allows, such as dependencyManagement in Maven, a constraint in Gradle, or overrides in package.json.',
  ]);
}

async function modelPlan(tree: string, dir: string, file: string, name: string, lines: string[]): Promise<UpgradePlan> {
  const locks = await lockfilesIn(join(tree, dir));
  if (locks.includes('yarn.lock')) {
    const refused = await yarnRefusal(tree, dir);
    if (refused) return { kind: 'unsupported', reason: refused };
  }
  const unsupported = locks.filter((lock) => !RELOCKABLE[lock]);
  if (unsupported.length > 0) {
    return {
      kind: 'unsupported',
      reason: `Minotaur cannot update ${unsupported.join(' and ')} yet, so ${name} has to be changed by hand`,
    };
  }
  // go.mod is how Go finds its lockfile's tool, but it is the manifest the model edits.
  const relocked = locks.filter((lock) => RELOCKABLE[lock] && lock !== 'go.mod');
  return {
    kind: 'model',
    dir,
    guidance: [
      ...lines,
      relocked.length > 0
        ? `Do not edit ${relocked.join(' or ')}: it is read-only. When you submit, Minotaur updates it with the package manager.`
        : `The finding is reported in ${join(dir, file)}.`,
    ].join('\n'),
  };
}

async function npmPlan(tree: string, dir: string, manager: NodeManager, name: string, version: string): Promise<UpgradePlan> {
  const manifest = await readJson(join(tree, dir, 'package.json'));
  const direct = ['dependencies', 'devDependencies', 'optionalDependencies'].some((field) => typeof manifest?.[field]?.[name] === 'string');
  return { kind: 'command', manager, dir, name, version, direct };
}

/** Runs a tool. The default one resolves with what the tool printed, which only `yarn --version` needs. */
export type Runner = (tool: string, args: readonly string[], cwd: string) => Promise<string | void>;

/**
 * Runs the upgrade in the worktree. Returns notes for the reviewer. Throws
 * `UpgradeError` when the package manager refuses, such as when the version
 * is outside what the manifest allows.
 */
export async function applyUpgrade(tree: string, plan: Extract<UpgradePlan, { kind: 'command' }>, run: Runner = runTool): Promise<string[]> {
  const cwd = join(tree, plan.dir);
  const spec = `${plan.name}@${plan.version}`;
  switch (plan.manager) {
    case 'pip': {
      await pinVersion(cwd, plan.name, plan.version);
      return [];
    }
    case 'go':
      await run('go', ['get', spec], cwd);
      await run('go', ['mod', 'tidy'], cwd);
      return [];
    case 'cargo':
      await run('cargo', ['update', '-p', plan.name, '--precise', plan.version], cwd);
      return [];
    case 'npm':
    case 'pnpm':
    case 'yarn': {
      const manifest = await readJson(join(cwd, 'package.json'));
      if (plan.direct) {
        const field = ['devDependencies', 'optionalDependencies'].find((name) => typeof manifest?.[name]?.[plan.name] === 'string');
        const save = field === 'devDependencies' ? ['--save-dev'] : field === 'optionalDependencies' ? ['--save-optional'] : [];
        // The package managers write "^version" by default; a project that pins exactly, or with ~, keeps doing so.
        const current = String(manifest?.[field ?? 'dependencies']?.[plan.name] ?? '');
        const exact = /^\d/.test(current) ? ['--save-exact'] : [];
        const notes: string[] = [];
        if (plan.manager === 'npm') {
          const tilde = current.startsWith('~') ? ['--save-prefix=~'] : [];
          await run('npm', ['install', spec, '--package-lock-only', ...NPM_QUIET, ...save, ...exact, ...tilde], cwd);
        } else if (plan.manager === 'yarn') {
          const flags = [
            ...(field === 'devDependencies' ? ['--dev'] : field === 'optionalDependencies' ? ['--optional'] : []),
            ...(exact.length > 0 ? ['--exact'] : current.startsWith('~') ? ['--tilde'] : []),
          ];
          await yarn(cwd, run, (classic) => ['add', spec, ...flags, ...(classic && manifest?.['workspaces'] ? ['-W'] : [])]);
        } else {
          if (current.startsWith('~')) notes.push(`pnpm writes the new range for ${plan.name} as ^${plan.version}; it was ${current}.`);
          await run('pnpm', ['add', spec, '--lockfile-only', '--ignore-scripts', ...save, ...exact, ...((await exists(join(cwd, 'pnpm-workspace.yaml'))) ? ['-w'] : [])], cwd);
        }
        return notes;
      }
      await addOverride(cwd, plan.manager, plan.name, plan.version);
      await relockIn(cwd, plan.manager, plan.name, run);
      return [
        `${plan.name} is not a direct dependency, so an override forces every copy of it to ${plan.version}. Check that the packages that use it accept that version.`,
      ];
    }
  }
}

/** After a model edited a manifest: brings the lockfile beside it up to date. Returns the command, or null when there is no lockfile. */
export async function relock(tree: string, dir: string, name: string, run: Runner = runTool): Promise<string | null> {
  const cwd = join(tree, dir);
  for (const lock of await lockfilesIn(cwd)) {
    const manager = RELOCKABLE[lock];
    if (!manager) continue;
    return relockIn(cwd, manager, name, run);
  }
  return null;
}

async function relockIn(cwd: string, manager: Manager, name: string, run: Runner): Promise<string> {
  if (manager === 'yarn') return yarn(cwd, run, () => ['install']);
  const commands: Record<Manager, [string, string[]] | null> = {
    npm: ['npm', ['install', '--package-lock-only', ...NPM_QUIET]],
    pnpm: ['pnpm', ['install', '--lockfile-only', '--ignore-scripts']],
    yarn: null,
    cargo: ['cargo', ['update', '-p', name]],
    go: ['go', ['mod', 'tidy']],
    pip: null,
  };
  const command = commands[manager];
  if (!command) return '';
  await run(command[0], command[1], cwd);
  return `${command[0]} ${command[1].join(' ')}`;
}

const NPM_QUIET = ['--ignore-scripts', '--no-audit', '--no-fund'];

/**
 * Runs a Yarn command that changes only package.json and yarn.lock. Returns
 * the command, as a person would type it.
 *
 * Yarn 2 and later has a mode for that. Yarn 1 has none: it always installs,
 * so it installs into a folder outside the tree that is thrown away. Which
 * one runs depends on Corepack and the project's packageManager field, so it
 * is asked, and it must match the lockfile's format: otherwise that Yarn
 * would rewrite the whole lockfile in its own format.
 */
async function yarn(cwd: string, run: Runner, command: (classic: boolean) => string[]): Promise<string> {
  const version = String((await run('yarn', ['--version'], cwd)) ?? '').trim();
  const major = /^(\d+)\./.exec(version)?.[1];
  if (!major) throw new UpgradeError(`could not tell which Yarn runs here: yarn --version printed "${version.slice(0, 80)}"`);
  const classic = Number(major) < 2;
  const lockIsClassic = !/^__metadata:/m.test(await readFile(join(cwd, 'yarn.lock'), 'utf8').catch(() => ''));
  if (classic !== lockIsClassic) {
    throw new ToolMissingError(
      `yarn.lock is in the Yarn ${lockIsClassic ? '1' : '2+'} format, but the yarn on PATH is ${version}; ` +
        `install the Yarn the project uses${lockIsClassic ? '' : ', such as with corepack enable'}`,
    );
  }
  const args = command(classic);
  if (!classic) {
    const shown = [...args, '--mode=update-lockfile'];
    await run('yarn', shown, cwd);
    return `yarn ${shown.join(' ')}`;
  }
  const shown = [...args, '--ignore-scripts', '--non-interactive'];
  const modules = await mkdtemp(join(tmpdir(), 'minotaur-yarn-'));
  try {
    await run('yarn', [...shown, '--modules-folder', modules], cwd);
  } finally {
    await rm(modules, { recursive: true, force: true });
    // Yarn 1 writes this beside the manifest when it fails; it is not part of the fix.
    await rm(join(cwd, 'yarn-error.log'), { force: true });
  }
  return `yarn ${shown.join(' ')}`;
}

/** Why Yarn cannot be run on this project, or null. Plugins are code from the repository that Yarn loads. */
async function yarnRefusal(tree: string, dir: string): Promise<string | null> {
  // Yarn reads .yarnrc.yml from every directory above the project as well.
  for (let at = join(tree, dir); ; at = dirname(at)) {
    const text = await readFile(join(at, '.yarnrc.yml'), 'utf8').catch(() => null);
    const plugins: unknown = text === null ? undefined : parseDocument(text).get('plugins');
    if (plugins !== undefined && plugins !== null) {
      const file = join(relative(tree, at), '.yarnrc.yml');
      return `${file} loads Yarn plugins, which are code from the repository, so Minotaur does not run Yarn here`;
    }
    if (relative(tree, at) === '' || dirname(at) === at) return null;
  }
}

async function lockfilesIn(dir: string): Promise<string[]> {
  const names = [...LOCKFILES, 'go.mod'];
  const found = await Promise.all(names.map(async (name) => ((await exists(join(dir, name))) ? name : null)));
  return found.filter((name): name is string => name !== null);
}

async function addOverride(cwd: string, manager: NodeManager, name: string, version: string): Promise<void> {
  const workspace = join(cwd, 'pnpm-workspace.yaml');
  if (manager === 'pnpm' && (await exists(workspace))) {
    // pnpm 10 reads its settings from the workspace file; the comments in it are kept.
    const document = parseDocument(await readFile(workspace, 'utf8'));
    document.setIn(['overrides', name], version);
    await writeFile(workspace, document.toString(), 'utf8');
    return;
  }
  const path = join(cwd, 'package.json');
  const text = await readFile(path, 'utf8');
  const manifest = JSON.parse(text) as Record<string, unknown>;
  if (manager === 'npm') {
    manifest['overrides'] = { ...(manifest['overrides'] as object | undefined), [name]: version };
  } else if (manager === 'yarn') {
    manifest['resolutions'] = { ...(manifest['resolutions'] as object | undefined), [name]: version };
  } else {
    const pnpm = (manifest['pnpm'] as Record<string, unknown> | undefined) ?? {};
    manifest['pnpm'] = { ...pnpm, overrides: { ...(pnpm['overrides'] as object | undefined), [name]: version } };
  }
  const indent = /^[ \t]+/m.exec(text)?.[0] ?? '  ';
  await writeFile(path, `${JSON.stringify(manifest, null, indent)}${text.endsWith('\n') ? '\n' : ''}`, 'utf8');
}

/** PEP 503: names compare case-insensitively, with runs of -, _ and . the same. */
function normalizePython(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

const PIN = /^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(\s*==\s*)([^\s;#]+)/;

async function pinned(path: string, name: string): Promise<boolean> {
  const text = await readFile(path, 'utf8').catch(() => '');
  return text.split('\n').some((line) => {
    const match = PIN.exec(line);
    return match !== null && normalizePython(match[2]!) === normalizePython(name);
  });
}

async function pinVersion(cwd: string, name: string, version: string): Promise<void> {
  // The plan was made from the file the finding names, which is in this directory.
  for (const file of await requirementFiles(cwd)) {
    const path = join(cwd, file);
    const text = await readFile(path, 'utf8');
    let changed = false;
    const lines = text.split('\n').map((line) => {
      const match = PIN.exec(line);
      if (!match || normalizePython(match[2]!) !== normalizePython(name)) return line;
      changed = true;
      return `${match[1]}${match[2]}${match[3] ?? ''}${match[4]}${version}${line.slice(match[0].length)}`;
    });
    if (changed) await writeFile(path, lines.join('\n'), 'utf8');
  }
}

async function requirementFiles(dir: string): Promise<string[]> {
  return (await readdir(dir)).filter((name) => /^requirements.*\.(txt|in)$/i.test(name));
}

async function readJson(path: string): Promise<Record<string, Record<string, unknown> | undefined> | null> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as Record<string, Record<string, unknown> | undefined>;
  } catch {
    return null;
  }
}

async function exists(path: string): Promise<boolean> {
  return (await stat(path).catch(() => null)) !== null;
}

/** Ten minutes: a first `go get` or `cargo update` can download a lot. */
const TOOL_TIMEOUT_MS = 10 * 60_000;

async function runTool(tool: string, args: readonly string[], cwd: string): Promise<string> {
  if (!(await isInstalled(tool))) throw new ToolMissingError(`${tool} is not installed or not on PATH, so the lockfile cannot be updated`);
  return new Promise<string>((done, fail) => {
    const child = spawn(tool, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: TOOL_TIMEOUT_MS,
      env: {
        ...process.env,
        CI: '1',
        npm_config_ignore_scripts: 'true',
        npm_config_audit: 'false',
        npm_config_fund: 'false',
        // Yarn: never the yarnPath copy from the repository, no scripts, and CI must not make the lockfile frozen.
        YARN_IGNORE_PATH: '1',
        YARN_ENABLE_SCRIPTS: 'false',
        YARN_ENABLE_IMMUTABLE_INSTALLS: 'false',
        // Yarn 2+ records each install in .yarn/install-state.gz, which is no part of a fix.
        YARN_INSTALL_STATE_PATH: join(tmpdir(), 'minotaur-yarn-install-state.gz'),
        COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
      },
    });
    let stdout = '';
    child.stdout!.on('data', (chunk: Buffer) => (stdout = (stdout + chunk.toString('utf8')).slice(-2_000)));
    let stderr = '';
    child.stderr!.on('data', (chunk: Buffer) => (stderr = (stderr + chunk.toString('utf8')).slice(-2_000)));
    child.on('error', (error) => fail(new UpgradeError(`${tool} could not start: ${error.message}`)));
    child.on('close', (code, signal) => {
      if (code === 0) done(stdout);
      else fail(new UpgradeError(`${tool} ${args.join(' ')} failed${signal ? ` (${signal})` : ''}: ${stderr.trim().split('\n').slice(-5).join(' ')}`));
    });
  });
}
