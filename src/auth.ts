/**
 * Claude Console login, stored by `ant auth login`. Minotaur does not run
 * its own OAuth flow: it reads that login and uses it when no API key is set.
 */

import { spawn } from 'node:child_process';
import { chmod, mkdir, open, readFile, realpath, rename, stat, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import { OAUTH_BETA } from './agent/model.js';

/** How soon before expiry the access token is refreshed, in seconds. */
const REFRESH_WITHIN_SECONDS = 30;
const DEFAULT_API = 'https://api.anthropic.com';
const TOKEN_PATH = '/v1/oauth/token';
const PROFILE_NAME = /^[A-Za-z0-9_.-]+$/;

export type Env = Readonly<Record<string, string | undefined>>;

export interface ConsoleLogin {
  accessToken: string;
  email?: string;
  workspaceId?: string;
}

export interface LoadOptions {
  fetch?: typeof fetch;
  /** Epoch milliseconds. Defaults to `Date.now`. */
  now?: () => number;
  platform?: NodeJS.Platform;
}

type Run = (command: string, args: readonly string[]) => Promise<number>;

interface Stored {
  accessToken: string;
  email?: string;
  workspaceId?: string;
  /** True when the access token is inside the refresh window and was not refreshed. */
  expired: boolean;
}

/** Where `ant` keeps profiles. Null when no home directory is available. */
export function anthropicConfigDir(env: Env, platform: NodeJS.Platform = process.platform): string | null {
  if (env['ANTHROPIC_CONFIG_DIR']) return env['ANTHROPIC_CONFIG_DIR'];
  if (platform === 'win32') {
    if (env['APPDATA']) return join(env['APPDATA'], 'Anthropic');
    if (env['USERPROFILE']) return join(env['USERPROFILE'], 'AppData', 'Roaming', 'Anthropic');
    return null;
  }
  if (env['XDG_CONFIG_HOME']) return join(env['XDG_CONFIG_HOME'], 'anthropic');
  if (env['HOME']) return join(env['HOME'], '.config', 'anthropic');
  return null;
}

/**
 * The access token `ant auth login` stored, refreshed when it is about to
 * expire. Null when there is no Console login.
 */
export async function loadConsoleToken(env: Env, options: LoadOptions = {}): Promise<ConsoleLogin | null> {
  const stored = await readStored(env, options, true);
  if (!stored) return null;
  return { accessToken: stored.accessToken, ...(stored.email ? { email: stored.email } : {}), ...(stored.workspaceId ? { workspaceId: stored.workspaceId } : {}) };
}

/** What triage would use, without the token itself. */
export async function authStatusText(env: Env, options: LoadOptions = {}): Promise<string> {
  const variable = env['ANTHROPIC_API_KEY'] ? 'ANTHROPIC_API_KEY' : env['MINOTAUR_API_KEY'] ? 'MINOTAUR_API_KEY' : null;
  if (variable) return `Using ${variable} from the environment.`;
  const stored = await readStored(env, options, false);
  if (!stored) return 'Not signed in. Run minotaur auth login, or set ANTHROPIC_API_KEY.';
  const lines = ['Signed in to the Claude Console.'];
  if (stored.email) lines.push(`Account: ${stored.email}`);
  if (stored.workspaceId) lines.push(`Workspace: ${stored.workspaceId}`);
  if (stored.expired) lines.push('This login has expired. Run minotaur auth login again.');
  return lines.join('\n');
}

const INSTALL_HINT = 'ant is not installed. Install it with: brew install anthropics/tap/ant';
const NO_BREW = 'ant is not installed, and Homebrew is not available to install it. Install ant with: brew install anthropics/tap/ant';
const INSTALL_QUESTION = 'ant is not installed. Install it with Homebrew? [y/N] ';

/** Thrown when `ant` is not on PATH, so login can offer to install it. */
export class AntMissingError extends Error {
  constructor() {
    super('ant is not installed');
    this.name = 'AntMissingError';
  }
}

export interface AntCommandOptions {
  run?: Run;
  warn?: (message: string) => void;
  /** When set, used instead of the terminal question. */
  ask?: (question: string) => Promise<boolean>;
  /** When set, used instead of `brew install`. */
  install?: () => Promise<number>;
  /** When set, used instead of looking for Homebrew. */
  hasBrew?: () => Promise<boolean>;
}

/** Runs `ant auth login`. The browser prompt uses the terminal. */
export async function consoleLogin(options: AntCommandOptions & { noBrowser?: boolean; env: Env }): Promise<number> {
  const warn = options.warn ?? ((message: string) => process.stderr.write(`${message}\n`));
  const key = options.env['ANTHROPIC_API_KEY'] ? 'ANTHROPIC_API_KEY' : options.env['MINOTAUR_API_KEY'] ? 'MINOTAUR_API_KEY' : null;
  if (key) warn(`${key} is set, so Minotaur keeps using it until you unset it.`);
  const args = ['auth', 'login', ...(options.noBrowser ? ['--no-browser'] : [])];
  return runAntCommand(args, { ...options, warn });
}

/** Runs `ant auth logout`. That forgets the login for `ant` as well. */
export async function consoleLogout(options: AntCommandOptions = {}): Promise<number> {
  const warn = options.warn ?? ((message: string) => process.stderr.write(`${message}\n`));
  const code = await runAntCommand(['auth', 'logout'], { ...options, warn });
  if (code === 0) warn('This also logs the ant command out, because both use the same Console login.');
  return code;
}

async function readStored(env: Env, options: LoadOptions, refresh: boolean): Promise<Stored | null> {
  const platform = options.platform ?? process.platform;
  const dir = anthropicConfigDir(env, platform);
  if (!dir) return null;
  const profile = await profileName(env, dir);
  const config = await readConfig(join(dir, 'configs', `${profile}.json`));
  const credentialsPath = config?.credentialsPath ?? join(dir, 'credentials', `${profile}.json`);
  const credentials = await readCredentials(credentialsPath, platform);
  if (!credentials) return null;

  const now = (options.now ?? Date.now)();
  const fresh = credentials.expiresAt == null || now < credentials.expiresAt * 1000 - REFRESH_WITHIN_SECONDS * 1000;
  const workspaceId = config?.workspaceId ?? env['ANTHROPIC_WORKSPACE_ID'];
  const base = {
    ...(credentials.email ? { email: credentials.email } : {}),
    ...(workspaceId ? { workspaceId } : {}),
  };
  const clientId = config?.clientId;
  // A token inside the refresh window is still a login. It is expired only when nothing can renew it.
  if (fresh || !refresh) {
    return { accessToken: credentials.accessToken, ...base, expired: !fresh && (!clientId || !credentials.refreshToken) };
  }
  if (!clientId || !credentials.refreshToken) {
    throw new Error('The Console login has expired. Run minotaur auth login again.');
  }
  const baseURL = (config?.baseUrl ?? env['ANTHROPIC_BASE_URL'] ?? DEFAULT_API).replace(/\/$/, '');
  assertSecure(baseURL);
  const tokenUrl = `${baseURL}${TOKEN_PATH}`;
  const response = await (options.fetch ?? fetch)(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'anthropic-beta': OAUTH_BETA },
    body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: credentials.refreshToken, client_id: clientId }),
  });
  if (!response.ok) throw new Error(await refreshFailure(response));
  const issued = await readTokenResponse(response);
  const expiresAt = Math.floor(now / 1000) + issued.expiresIn;
  await writeCredentials(credentialsPath, {
    ...credentials.raw,
    version: '1.0',
    type: 'oauth_token',
    access_token: issued.accessToken,
    expires_at: expiresAt,
    refresh_token: issued.refreshToken || credentials.refreshToken,
  });
  return { accessToken: issued.accessToken, ...base, expired: false };
}

interface ProfileConfig {
  clientId?: string;
  credentialsPath?: string;
  baseUrl?: string;
  workspaceId?: string;
}

async function readConfig(path: string): Promise<ProfileConfig | null> {
  const raw = await readJson(path);
  if (raw === undefined) return null;
  if (!isRecord(raw) || !isRecord(raw['authentication'])) {
    throw new Error(`${path} has no authentication setting`);
  }
  const authentication = raw['authentication'];
  if (authentication['type'] !== 'user_oauth') {
    throw new Error(`${path} is a ${String(authentication['type'])} profile. Minotaur can only use a Console login.`);
  }
  return {
    ...(typeof authentication['client_id'] === 'string' && authentication['client_id'] ? { clientId: authentication['client_id'] } : {}),
    ...(typeof authentication['credentials_path'] === 'string' ? { credentialsPath: authentication['credentials_path'] } : {}),
    ...(typeof raw['base_url'] === 'string' ? { baseUrl: raw['base_url'] } : {}),
    ...(typeof raw['workspace_id'] === 'string' ? { workspaceId: raw['workspace_id'] } : {}),
  };
}

interface CredentialFile {
  accessToken: string;
  refreshToken?: string;
  /** Unix seconds, or null when the token does not expire. */
  expiresAt: number | null;
  email?: string;
  raw: Record<string, unknown>;
}

async function readCredentials(path: string, platform: NodeJS.Platform): Promise<CredentialFile | null> {
  await assertPrivate(path, platform);
  const raw = await readJson(path);
  if (raw === undefined) return null;
  if (!isRecord(raw)) throw new Error(`${path} is not valid JSON`);
  if (raw['type'] != null && raw['type'] !== 'oauth_token') {
    throw new Error(`${path} has unsupported type "${String(raw['type'])}"`);
  }
  if (typeof raw['access_token'] !== 'string' || !raw['access_token']) {
    throw new Error(`${path} has no access token`);
  }
  const expiresAt = raw['expires_at'];
  if (expiresAt != null && (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt))) {
    throw new Error(`${path} has an invalid expires_at`);
  }
  return {
    accessToken: raw['access_token'],
    ...(typeof raw['refresh_token'] === 'string' && raw['refresh_token'] ? { refreshToken: raw['refresh_token'] } : {}),
    expiresAt: typeof expiresAt === 'number' ? expiresAt : null,
    ...(typeof raw['account_email'] === 'string' && raw['account_email'] ? { email: raw['account_email'] } : {}),
    raw,
  };
}

/** Group and world access would let another local user replace the token. */
async function assertPrivate(path: string, platform: NodeJS.Platform): Promise<void> {
  if (platform === 'win32') return;
  let resolved = path;
  let info;
  try {
    resolved = await realpath(path);
    info = await stat(resolved);
  } catch {
    return;
  }
  const mode = info.mode & 0o777;
  if (mode & 0o066) {
    throw new Error(
      `Credentials file at ${resolved} is readable or writable by other users (mode 0o${mode.toString(8)}). Run chmod 600 ${resolved}`,
    );
  }
}

async function writeCredentials(path: string, data: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`;
  const handle = await open(tmp, 'w', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(data, null, 2)}\n`);
    await handle.sync();
  } catch (error) {
    await handle.close();
    await unlink(tmp).catch(() => undefined);
    throw error;
  }
  await handle.close();
  try {
    await rename(tmp, path);
  } catch (error) {
    await unlink(tmp).catch(() => undefined);
    throw error;
  }
  await chmod(path, 0o600);
}

function assertSecure(baseURL: string): void {
  let url: URL;
  try {
    url = new URL(baseURL);
  } catch {
    throw new Error(`Invalid Console address "${baseURL}"`);
  }
  if (url.protocol === 'https:') return;
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (url.protocol === 'http:' && (host === 'localhost' || host === '127.0.0.1' || host === '::1')) return;
  throw new Error(`Refusing to send the Console login to ${baseURL}`);
}

interface IssuedToken {
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
}

async function readTokenResponse(response: Response): Promise<IssuedToken> {
  const text = await response.text();
  if (text.length > 1_000_000) throw new Error('Console login refresh returned a response that is too large');
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error('Console login refresh returned a response that is not JSON');
  }
  if (!isRecord(body) || typeof body['access_token'] !== 'string' || !body['access_token']) {
    throw new Error('Console login refresh did not return a token');
  }
  if (body['token_type'] != null && String(body['token_type']).toLowerCase() !== 'bearer') {
    throw new Error(`Console login refresh returned an unsupported token type "${String(body['token_type'])}"`);
  }
  const expiresIn = Number(body['expires_in']);
  if (!Number.isFinite(expiresIn) || expiresIn < 0) throw new Error('Console login refresh did not say when the token expires');
  return {
    accessToken: body['access_token'],
    expiresIn,
    refreshToken: typeof body['refresh_token'] === 'string' ? body['refresh_token'] : '',
  };
}

async function refreshFailure(response: Response): Promise<string> {
  const text = await response.text().catch(() => '');
  try {
    const body = JSON.parse(text) as unknown;
    if (isRecord(body)) {
      const error = typeof body['error'] === 'string' ? body['error'] : '';
      const description = typeof body['error_description'] === 'string' ? body['error_description'] : '';
      const detail = [error, description].filter(Boolean).join(': ');
      if (detail) return `Console login could not be refreshed (${response.status} ${detail})`;
    }
  } catch {
    // The body may echo the refresh token, so it is never included.
  }
  return `Console login could not be refreshed (HTTP ${response.status})`;
}

async function profileName(env: Env, dir: string): Promise<string> {
  const fromEnv = env['ANTHROPIC_PROFILE'];
  if (fromEnv) return checkedProfile(fromEnv);
  try {
    const named = (await readFile(join(dir, 'active_config'), 'utf8')).trim();
    return checkedProfile(named || 'default');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return 'default';
    throw error;
  }
}

function checkedProfile(name: string): string {
  if (name === '.' || name === '..' || name.includes('/') || name.includes('\\') || !PROFILE_NAME.test(name)) {
    throw new Error(`profile name "${name}" is not allowed`);
  }
  return name;
}

async function readJson(path: string): Promise<unknown | undefined> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`${path} is not valid JSON`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Runs an ant command, and offers to install it first when it is missing and someone can answer. */
async function runAntCommand(args: readonly string[], options: AntCommandOptions, offered = false): Promise<number> {
  const run = options.run ?? spawnInherit;
  try {
    return await run('ant', args);
  } catch (error) {
    if (!(error instanceof AntMissingError) || offered) {
      if (error instanceof AntMissingError) throw new Error(INSTALL_HINT);
      throw error;
    }
  }
  const offeredInstall = await offerAntInstall(options);
  if (offeredInstall === 'failed') return 1;
  if (offeredInstall !== 'installed') throw new Error(INSTALL_HINT);
  return runAntCommand(args, options, true);
}

async function offerAntInstall(options: AntCommandOptions): Promise<'installed' | 'declined' | 'failed'> {
  const warn = options.warn ?? ((message: string) => process.stderr.write(`${message}\n`));
  const interactive = options.ask != null || (Boolean(process.stdin.isTTY) && Boolean(process.stderr.isTTY));
  if (!interactive) return 'declined';
  const brew = options.hasBrew ?? (() => commandOnPath('brew'));
  if (options.install == null && !(await brew())) throw new Error(NO_BREW);
  const yes = await (options.ask ?? askYes)(INSTALL_QUESTION);
  if (!yes) return 'declined';
  const code = await (options.install ?? (() => spawnInherit('brew', ['install', 'anthropics/tap/ant'])))();
  if (code !== 0) {
    warn('ant was not installed.');
    return 'failed';
  }
  return 'installed';
}

function spawnInherit(command: string, args: readonly string[]): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, [...args], { stdio: 'inherit' });
    child.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT' && command === 'ant') reject(new AntMissingError());
      else reject(error);
    });
    child.on('exit', (code) => resolve(code ?? 1));
  });
}

function commandOnPath(name: string): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn(name, ['--version'], { stdio: 'ignore' });
    child.on('error', () => resolve(false));
    child.on('exit', (code) => resolve(code === 0));
  });
}

async function askYes(question: string): Promise<boolean> {
  const { createInterface } = await import('node:readline/promises');
  const prompt = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await prompt.question(question);
    return /^y(es)?$/i.test(answer.trim());
  } catch {
    return false;
  } finally {
    prompt.close();
  }
}
