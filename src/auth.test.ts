import { EventEmitter } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { AntMissingError, anthropicConfigDir, authStatusText, consoleLogin, consoleLogout, loadConsoleToken } from './auth.js';
import { OAUTH_BETA } from './agent/model.js';

const spawnMock = vi.hoisted(() => vi.fn());

vi.mock('node:child_process', async () => {
  const actual = await vi.importActual<typeof import('node:child_process')>('node:child_process');
  return { ...actual, spawn: spawnMock };
});

const TOKEN = 'sk-ant-oat01-secret-token';
const NOW = 1_700_000_000_000;

describe('anthropicConfigDir', () => {
  it('follows the ant command: an override, then XDG, then the home directory, then Windows', () => {
    expect(anthropicConfigDir({ ANTHROPIC_CONFIG_DIR: '/override' }, 'linux')).toBe('/override');
    expect(anthropicConfigDir({ XDG_CONFIG_HOME: '/xdg' }, 'linux')).toBe('/xdg/anthropic');
    expect(anthropicConfigDir({ HOME: '/home/ada' }, 'darwin')).toBe('/home/ada/.config/anthropic');
    expect(anthropicConfigDir({ APPDATA: 'C:\\Users\\ada\\AppData\\Roaming' }, 'win32')).toBe(
      join('C:\\Users\\ada\\AppData\\Roaming', 'Anthropic'),
    );
    expect(anthropicConfigDir({}, 'linux')).toBeNull();
  });
});

describe('Console login', () => {
  let dir: string;

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it('reads the active profile and never returns the token from status', async () => {
    dir = await mkdtemp(join(tmpdir(), 'minotaur-auth-'));
    await writeFile(join(dir, 'active_config'), 'work\n');
    await writeLogin(dir, 'work', {
      credentials: {
        type: 'oauth_token',
        access_token: TOKEN,
        account_email: 'ada@example.com',
        expires_at: NOW / 1000 + 3600,
      },
      config: { authentication: { type: 'user_oauth', client_id: 'client-1' }, workspace_id: 'wrkspc_01' },
    });

    const env = { ANTHROPIC_CONFIG_DIR: dir };
    const login = await loadConsoleToken(env, { now: () => NOW });
    expect(login).toEqual({ accessToken: TOKEN, email: 'ada@example.com', workspaceId: 'wrkspc_01' });

    const status = await authStatusText(env, { now: () => NOW });
    expect(status).toBe('Signed in to the Claude Console.\nAccount: ada@example.com\nWorkspace: wrkspc_01');
    expect(status).not.toContain(TOKEN);

    expect(await authStatusText({ ...env, ANTHROPIC_API_KEY: 'sk-ant-api' })).toBe('Using ANTHROPIC_API_KEY from the environment.');
    expect(await authStatusText({ ...env, MINOTAUR_API_KEY: 'sk-min' })).toBe('Using MINOTAUR_API_KEY from the environment.');
  });

  it('refuses a credentials file other users can read', async () => {
    dir = await mkdtemp(join(tmpdir(), 'minotaur-auth-'));
    await writeLogin(dir, 'default', { credentials: { type: 'oauth_token', access_token: TOKEN }, mode: 0o644 });
    await expect(loadConsoleToken({ ANTHROPIC_CONFIG_DIR: dir })).rejects.toThrow(/chmod 600/);
  });

  it('refreshes a token that is about to expire and writes the new one back privately', async () => {
    dir = await mkdtemp(join(tmpdir(), 'minotaur-auth-'));
    await writeLogin(dir, 'default', {
      credentials: {
        type: 'oauth_token',
        access_token: TOKEN,
        refresh_token: 'refresh-1',
        account_email: 'ada@example.com',
        expires_at: NOW / 1000 + 10,
      },
      config: {
        authentication: { type: 'user_oauth', client_id: 'client-1' },
        base_url: 'http://127.0.0.1:9',
        workspace_id: 'wrkspc_01',
      },
    });
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toBe('http://127.0.0.1:9/v1/oauth/token');
      expect(JSON.parse(String(init?.body))).toEqual({
        grant_type: 'refresh_token',
        refresh_token: 'refresh-1',
        client_id: 'client-1',
      });
      expect(new Headers(init?.headers).get('anthropic-beta')).toBe(OAUTH_BETA);
      return new Response(
        JSON.stringify({ access_token: 'sk-ant-oat01-new', expires_in: 3600, refresh_token: 'refresh-2', token_type: 'Bearer' }),
        { status: 200 },
      );
    });

    const login = await loadConsoleToken({ ANTHROPIC_CONFIG_DIR: dir }, { fetch: fetchImpl, now: () => NOW });
    expect(login?.accessToken).toBe('sk-ant-oat01-new');
    const file = join(dir, 'credentials', 'default.json');
    const stored = JSON.parse(await readFile(file, 'utf8')) as { access_token: string; refresh_token: string; expires_at: number; account_email: string };
    expect(stored.access_token).toBe('sk-ant-oat01-new');
    expect(stored.refresh_token).toBe('refresh-2');
    expect(stored.expires_at).toBe(NOW / 1000 + 3600);
    expect(stored.account_email).toBe('ada@example.com');
    expect(stored.access_token).not.toBe(TOKEN);
    expect((await stat(file)).mode & 0o777).toBe(0o600);
  });

  it('does not send a refresh token to a server that is not https or local', async () => {
    dir = await mkdtemp(join(tmpdir(), 'minotaur-auth-'));
    await writeLogin(dir, 'default', {
      credentials: { type: 'oauth_token', access_token: TOKEN, refresh_token: 'refresh-1', expires_at: 1 },
      config: { authentication: { type: 'user_oauth', client_id: 'client-1' }, base_url: 'http://example.com' },
    });
    const fetchImpl = vi.fn();
    await expect(loadConsoleToken({ ANTHROPIC_CONFIG_DIR: dir }, { fetch: fetchImpl, now: () => NOW })).rejects.toThrow(
      /Refusing to send the Console login/,
    );
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('says when an expired login cannot be refreshed', async () => {
    dir = await mkdtemp(join(tmpdir(), 'minotaur-auth-'));
    await writeLogin(dir, 'default', {
      credentials: { type: 'oauth_token', access_token: TOKEN, expires_at: 1, account_email: 'ada@example.com' },
      config: { authentication: { type: 'user_oauth' } },
    });
    const env = { ANTHROPIC_CONFIG_DIR: dir };
    await expect(loadConsoleToken(env, { now: () => NOW })).rejects.toThrow(/minotaur auth login again/);
    const status = await authStatusText(env, { now: () => NOW });
    expect(status).toContain('This login has expired');
    expect(status).not.toContain(TOKEN);
  });

  it('runs ant auth login, including when there is no browser, and says when a key still wins', async () => {
    const run = vi.fn(async () => 0);
    const warnings: string[] = [];
    const warn = (message: string) => warnings.push(message);
    expect(await consoleLogin({ env: {}, run, warn })).toBe(0);
    expect(run).toHaveBeenCalledWith('ant', ['auth', 'login']);

    expect(await consoleLogin({ noBrowser: true, env: { ANTHROPIC_API_KEY: 'sk' }, run, warn })).toBe(0);
    expect(run).toHaveBeenCalledWith('ant', ['auth', 'login', '--no-browser']);
    expect(warnings).toEqual(['ANTHROPIC_API_KEY is set, so Minotaur keeps using it until you unset it.']);
  });

  it('explains how to install ant when there is no terminal to ask', async () => {
    const stdin = process.stdin.isTTY;
    const stderr = process.stderr.isTTY;
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: false });
    Object.defineProperty(process.stderr, 'isTTY', { configurable: true, value: false });
    spawnMock.mockImplementation(() => {
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('error', Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' })));
      return child;
    });
    try {
      await expect(consoleLogin({ env: {} })).rejects.toThrow(/ant is not installed[\s\S]*brew install anthropics\/tap\/ant/);
      expect(spawnMock).toHaveBeenCalledWith('ant', ['auth', 'login'], { stdio: 'inherit' });
    } finally {
      Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: stdin });
      Object.defineProperty(process.stderr, 'isTTY', { configurable: true, value: stderr });
    }
  });

  it('installs ant when you agree, then logs in', async () => {
    let attempts = 0;
    const run = vi.fn(async () => {
      attempts += 1;
      if (attempts === 1) throw new AntMissingError();
      return 0;
    });
    const install = vi.fn(async () => 0);
    const ask = vi.fn(async () => true);
    expect(await consoleLogin({ env: {}, run, install, ask, hasBrew: async () => true })).toBe(0);
    expect(ask).toHaveBeenCalledWith('ant is not installed. Install it with Homebrew? [y/N] ');
    expect(install).toHaveBeenCalledOnce();
    expect(run).toHaveBeenCalledTimes(2);
  });

  it('leaves ant uninstalled when you decline', async () => {
    const install = vi.fn(async () => 0);
    await expect(
      consoleLogin({ env: {}, run: async () => { throw new AntMissingError(); }, install, ask: async () => false, hasBrew: async () => true }),
    ).rejects.toThrow(/brew install anthropics\/tap\/ant/);
    expect(install).not.toHaveBeenCalled();
  });

  it('does not offer an install when Homebrew is missing', async () => {
    const ask = vi.fn(async () => true);
    await expect(
      consoleLogin({ env: {}, run: async () => { throw new AntMissingError(); }, ask, hasBrew: async () => false }),
    ).rejects.toThrow(/Homebrew is not available/);
    expect(ask).not.toHaveBeenCalled();
  });

  it('logs ant out as well, because both tools share the file', async () => {
    const run = vi.fn(async () => 0);
    const warnings: string[] = [];
    expect(await consoleLogout({ run, warn: (message) => warnings.push(message) })).toBe(0);
    expect(run).toHaveBeenCalledWith('ant', ['auth', 'logout']);
    expect(warnings[0]).toMatch(/logs the ant command out/);
  });
});

async function writeLogin(
  dir: string,
  profile: string,
  options: { credentials: Record<string, unknown>; config?: Record<string, unknown>; mode?: number },
): Promise<void> {
  const credentialsDir = join(dir, 'credentials');
  await mkdir(credentialsDir, { recursive: true });
  const file = join(credentialsDir, `${profile}.json`);
  await writeFile(file, JSON.stringify(options.credentials));
  await chmod(file, options.mode ?? 0o600);
  if (options.config) {
    const configs = join(dir, 'configs');
    await mkdir(configs, { recursive: true });
    await writeFile(join(configs, `${profile}.json`), JSON.stringify(options.config));
  }
}
