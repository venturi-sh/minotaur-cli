/**
 * Turning a person's choices into `.minotaur.yml`.
 *
 * The wizard rewrites the file, so a comment written by hand is replaced by
 * the header. Scanner arguments, report files, triage limits and focus rules
 * stay. An API key never does: the file is meant to be committed.
 */

import { spawn } from 'node:child_process';
import { rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { stringify } from 'yaml';
import { z } from 'zod';

import { ACP_PACKAGE, DEFAULT_ACP_COMMAND } from './agent/acp.js';
import { MODEL_PRICING } from './agent/budget.js';
import { DEFAULT_EXPLOIT_MODEL, parseModelSpec, type Provider } from './agent/model.js';
import { loadConsoleToken, type Env } from './auth.js';
import { CONFIG_FILE, configSchema, parseConfig, type Config, type SourceConfig } from './config.js';
import { ensureRules, ensureTool, isManaged, type EnsureOptions } from './managed.js';
import { isInstalled } from './scanners/index.js';
import { NATIVE_SCANNERS } from './sources.js';

const HEADER = `# Minotaur settings for this repository. Commit this file.
# An API key does not belong here. Set ANTHROPIC_API_KEY or MINOTAUR_API_KEY, or run minotaur auth login.
`;

/** What each scanner is for, in the order the wizard shows them. */
const BLURB: Record<string, string> = {
  trivy: 'dependencies, misconfiguration and secrets',
  'osv-scanner': 'dependency vulnerabilities from OSV',
  grype: 'dependency vulnerabilities, including vendored code',
  semgrep: 'code, using the Semgrep install on PATH',
  trufflehog: 'secrets, with more detectors than Trivy',
  checkov: 'infrastructure policies',
  opengrep: 'code, using the scanner Minotaur downloads',
};

export interface ScannerChoice {
  name: string;
  /** One line for the picker: the name, what it covers, and whether it is available. */
  label: string;
}

export interface ConfigChoices {
  scanners: readonly string[];
  provider: 'anthropic' | 'claude-code' | 'openai-compatible' | 'unset';
  modelId?: string;
  baseUrl?: string;
}

/** Scanners already in the file, or `fallback` when the file lists none. Unknown names are dropped. */
export function initialScanners(config: Config, fallback: readonly string[]): string[] {
  const configured = (config.sources ?? []).flatMap((source) => ('scanner' in source ? [source.scanner] : []));
  const names = configured.length > 0 ? configured : fallback;
  const known = new Set<string>(NATIVE_SCANNERS);
  return names.filter((name) => known.has(name));
}

/**
 * Homebrew formulas for scanners Minotaur does not download itself. The formula
 * name is the binary the CLI runs.
 */
export const BREW_FORMULAS: Readonly<Record<string, string>> = {
  'osv-scanner': 'osv-scanner',
  grype: 'grype',
  semgrep: 'semgrep',
  trufflehog: 'trufflehog',
  checkov: 'checkov',
};

/** Selected scanners that are not on PATH. `brew` is offered on a Mac with Homebrew. Fleet order. */
export function missingScanners(
  selected: readonly string[],
  installed: ReadonlySet<string>,
  canBrew = false,
): { download: string[]; brew: string[]; separate: string[] } {
  const chosen = new Set(selected);
  const missing = NATIVE_SCANNERS.filter((name) => chosen.has(name) && !installed.has(name));
  const brewable = (name: string) => canBrew && name in BREW_FORMULAS;
  return {
    download: missing.filter((name) => isManaged(name)),
    brew: missing.filter((name) => brewable(name)),
    separate: missing.filter((name) => !isManaged(name) && !brewable(name)),
  };
}

/** "trivy", "trivy and opengrep", or "trivy, semgrep and opengrep". */
export function nameList(names: readonly string[]): string {
  if (names.length <= 1) return names[0] ?? '';
  if (names.length === 2) return `${names[0]} and ${names[1]}`;
  return `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
}

export interface InstallRun {
  tool: (name: string, options: EnsureOptions) => Promise<void>;
  rules: (options: EnsureOptions) => Promise<void>;
}

/** Download managed scanners into the cache. Opengrep also needs its rules. */
export async function installMissing(names: readonly string[], run?: InstallRun, options: EnsureOptions = {}): Promise<void> {
  const download = run ?? {
    tool: (name, ensure) => ensureTool(name, ensure).then(() => undefined),
    rules: (ensure) => ensureRules(ensure).then(() => undefined),
  };
  const noticed = options.onDownload ?? ((message: string) => process.stderr.write(`${message}\n`));
  const ensure = { ...options, onDownload: noticed };
  for (const name of names) {
    if (!isManaged(name)) throw new Error(`${name} is not a scanner Minotaur can download`);
    await download.tool(name, ensure);
    if (name === 'opengrep') await download.rules(ensure);
  }
}

/** `brew install` for scanners that are not on PATH. One Homebrew run for the whole list. */
export async function installWithBrew(names: readonly string[], run?: (formulas: readonly string[]) => Promise<number>): Promise<void> {
  const formulas = names.map((name) => {
    const formula = BREW_FORMULAS[name];
    if (!formula) throw new Error(`${name} has no Homebrew formula`);
    return formula;
  });
  const code = await (run ?? brewInstall)(formulas);
  if (code !== 0) throw new Error(`Homebrew did not install ${nameList(names)}`);
}

function brewInstall(formulas: readonly string[]): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn('brew', ['install', ...formulas], { stdio: 'inherit' });
    child.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') reject(new Error('Homebrew is not installed'));
      else reject(error);
    });
    child.on('exit', (code) => resolve(code ?? 1));
  });
}

export function scannerChoices(installed: ReadonlySet<string>, canBrew = false): ScannerChoice[] {
  return NATIVE_SCANNERS.map((name) => {
    const note = installed.has(name) ? 'installed' : isManaged(name) ? 'downloaded if missing' : canBrew && name in BREW_FORMULAS ? 'Homebrew if missing' : 'not installed';
    return { name, label: `${name}  ${BLURB[name] ?? name}  (${note})` };
  });
}

/** Anthropic models with a known price. The check default comes first. */
export function anthropicModels(): string[] {
  const preferred = parseModelSpec(DEFAULT_EXPLOIT_MODEL).modelId;
  const known = Object.keys(MODEL_PRICING)
    .filter((id) => id.startsWith('anthropic:'))
    .map((id) => id.slice('anthropic:'.length));
  return [preferred, ...known.filter((id) => id !== preferred)];
}

/** The model recorded in the file, when it names a provider Minotaur knows. */
export function configuredModel(config: Config): { provider: Provider; modelId: string } | null {
  if (!config.model) return null;
  try {
    const spec = parseModelSpec(config.model);
    return { provider: spec.provider, modelId: spec.modelId };
  } catch {
    return null;
  }
}

export function requireModelId(provider: 'anthropic' | 'claude-code' | 'openai-compatible', value: string | undefined): string {
  const raw = (value ?? '').trim();
  const prefix = `${provider}:`;
  const id = raw.startsWith(prefix) ? raw.slice(prefix.length).trim() : raw;
  if (!id) throw new Error('a model name is required');
  if (/\s/.test(id)) throw new Error(`model name "${id}" cannot contain spaces`);
  if (provider !== 'openai-compatible' && !anthropicModels().includes(id)) {
    const kind = provider === 'anthropic' ? 'Anthropic' : 'Claude';
    throw new Error(`unknown ${kind} model "${id}"; expected one of ${anthropicModels().join(', ')}`);
  }
  return id;
}

export function requireBaseUrl(value: string | undefined): string {
  const url = (value ?? '').trim();
  if (!url) throw new Error('a base URL is required');
  // `localhost:11434` is a URL in the spec sense (scheme `localhost`), and the
  // config schema would accept it. A model server needs http or https.
  if (!z.url().safeParse(url).success || !/^https?:\/\//.test(url)) {
    throw new Error(`base URL must be an http or https address, such as http://localhost:11434/v1`);
  }
  return url;
}

/**
 * The next file. Scanner order follows the fleet, so a re-run does not shuffle
 * the diff. Choosing Anthropic or Claude Code drops `baseUrl`; choosing a local server sets it.
 */
export function applyChoices(existing: Config, choices: ConfigChoices): Config {
  if (choices.scanners.length === 0) throw new Error('pick at least one scanner');
  const unknown = choices.scanners.find((name) => !NATIVE_SCANNERS.includes(name));
  if (unknown) throw new Error(`unknown scanner "${unknown}"; expected one of ${NATIVE_SCANNERS.join(', ')}`);

  const kept = new Map(
    (existing.sources ?? []).flatMap((source) => ('scanner' in source ? [[source.scanner, source] as const] : [])),
  );
  const reports = (existing.sources ?? []).filter((source): source is Extract<SourceConfig, { report: string }> => 'report' in source);
  const chosen = new Set(choices.scanners);
  const sources: SourceConfig[] = [
    ...NATIVE_SCANNERS.filter((name) => chosen.has(name)).map((name) => kept.get(name) ?? { scanner: name }),
    ...reports,
  ];

  const next: Config = {
    sources,
    ...(existing.triage ? { triage: existing.triage } : {}),
    ...(existing.focus ? { focus: existing.focus } : {}),
  };
  if (choices.provider === 'anthropic' || choices.provider === 'claude-code') {
    next.model = `${choices.provider}:${requireModelId(choices.provider, choices.modelId ?? anthropicModels()[0])}`;
  } else if (choices.provider === 'openai-compatible') {
    next.model = `openai-compatible:${requireModelId('openai-compatible', choices.modelId)}`;
    next.baseUrl = requireBaseUrl(choices.baseUrl);
  }
  return configSchema.parse(next);
}

export function renderConfig(config: Config): string {
  const body = stringify(toDocument(config), { lineWidth: 0 });
  const text = HEADER + (body.endsWith('\n') ? body : `${body}\n`);
  parseConfig(text);
  return text;
}

export async function saveConfig(root: string, config: Config): Promise<string> {
  const text = renderConfig(config);
  const path = join(root, CONFIG_FILE);
  const staging = `${path}.${process.pid}.tmp`;
  await writeFile(staging, text);
  await rename(staging, path);
  return path;
}

/** True when an Anthropic key or a Console login is already available. */
export async function anthropicReady(env: Env): Promise<boolean> {
  if (env['ANTHROPIC_API_KEY'] || env['MINOTAUR_API_KEY']) return true;
  try {
    return (await loadConsoleToken(env)) !== null;
  } catch {
    return false;
  }
}

/** True when the Claude Code ACP adapter can be started: MINOTAUR_ACP_COMMAND is set, or the adapter is on PATH. */
export async function acpReady(env: Env): Promise<boolean> {
  if (env['MINOTAUR_ACP_COMMAND']) return true;
  return isInstalled(DEFAULT_ACP_COMMAND, env['PATH'] ?? '');
}

export const ACP_INSTALL_COMMAND = `npm install -g ${ACP_PACKAGE}`;

/** Installs the Claude Code ACP adapter with npm. Resolves with npm's exit code. */
export function installAcpAdapter(): Promise<number> {
  return new Promise((resolve, reject) => {
    const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    const child = spawn(npm, ['install', '-g', ACP_PACKAGE], { stdio: 'inherit' });
    child.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') reject(new Error(`npm is not installed. Install the adapter with: ${ACP_INSTALL_COMMAND}`));
      else reject(error);
    });
    child.on('exit', (code) => resolve(code ?? 1));
  });
}

function toDocument(config: Config): Record<string, unknown> {
  const doc: Record<string, unknown> = {};
  if (config.sources) {
    doc['sources'] = config.sources.map((source) => {
      if ('scanner' in source) return source.args ? { scanner: source.scanner, args: source.args } : { scanner: source.scanner };
      return source.format ? { report: source.report, format: source.format } : { report: source.report };
    });
  }
  if (config.model) doc['model'] = config.model;
  if (config.baseUrl) doc['baseUrl'] = config.baseUrl;
  if (config.triage) doc['triage'] = config.triage;
  if (config.focus) doc['focus'] = config.focus;
  return doc;
}
