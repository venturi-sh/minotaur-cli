import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { isSensitiveFile, Workspace, WorkspaceAccessError } from './workspace.js';

let root: string;
let outside: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'minotaur-ws-'));
  outside = await mkdtemp(join(tmpdir(), 'minotaur-outside-'));
  await mkdir(join(root, 'src'));
  await mkdir(join(root, 'node_modules/lodash'), { recursive: true });
  await writeFile(join(root, 'src/app.js'), "const _ = require('lodash');\n_.template(input);\nconsole.log('ok');\n");
  await writeFile(join(root, 'node_modules/lodash/index.js'), 'module.exports.template = () => {};\n');
  await writeFile(join(root, '.env'), 'API_KEY=sk-live-123\n');
  await writeFile(join(root, '.env.example'), 'API_KEY=\n');
  await writeFile(join(root, 'config.yml'), 'token: abc\n');
  await writeFile(join(outside, 'secret.txt'), 'outside the repo\n');
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
  await rm(outside, { recursive: true, force: true });
});

describe('isSensitiveFile', () => {
  it.each(['.env', '.env.local', 'config/.env.production', 'server.pem', 'tls.key', 'id_rsa', '.npmrc', 'aws/credentials'])(
    'refuses %s',
    (path) => expect(isSensitiveFile(path)).toBe(true),
  );

  it.each(['.env.example', '.env.sample', '.env.template', 'src/env.ts', 'keys.ts', 'README.md'])('allows %s', (path) =>
    expect(isSensitiveFile(path)).toBe(false),
  );
});

describe('Workspace.readFile', () => {
  it('returns numbered lines and records the file as an input', async () => {
    const ws = await Workspace.open(root);
    const result = await ws.readFile('src/app.js', { startLine: 2, endLine: 2 });
    expect(result.content).toBe('2: _.template(input);\n');
    expect(result.totalLines).toBe(4);
    expect(ws.inputs()).toEqual([{ path: 'src/app.js', sha256: expect.stringMatching(/^[0-9a-f]{64}$/) }]);
  });

  it('refuses absolute paths and paths that climb out', async () => {
    const ws = await Workspace.open(root);
    await expect(ws.readFile(join(outside, 'secret.txt'))).rejects.toBeInstanceOf(WorkspaceAccessError);
    await expect(ws.readFile('../' + join('..', outside, 'secret.txt'))).rejects.toThrow(/outside|no such/);
  });

  it('refuses a symlink that points outside the repository', async () => {
    await symlink(join(outside, 'secret.txt'), join(root, 'src/link.txt'));
    const ws = await Workspace.open(root);
    await expect(ws.readFile('src/link.txt')).rejects.toThrow(/outside the repository/);
  });

  it('refuses a symlinked directory that points outside', async () => {
    await symlink(outside, join(root, 'escape'));
    const ws = await Workspace.open(root);
    await expect(ws.readFile('escape/secret.txt')).rejects.toThrow(/outside the repository/);
    await expect(ws.listDir('escape')).rejects.toThrow(/outside the repository/);
  });

  it('refuses credential files, including through a symlink', async () => {
    await symlink(join(root, '.env'), join(root, 'src/settings.txt'));
    const ws = await Workspace.open(root);
    await expect(ws.readFile('.env')).rejects.toThrow(/may contain credentials/);
    await expect(ws.readFile('src/settings.txt')).rejects.toThrow(/may contain credentials/);
    await expect(ws.readFile('.env.example')).resolves.toMatchObject({ path: '.env.example' });
  });

  it('refuses paths a secret finding points at', async () => {
    const ws = await Workspace.open(root, { denied: ['config.yml'] });
    await expect(ws.readFile('config.yml')).rejects.toThrow(/may contain credentials/);
  });

  it('refuses directories and oversized files', async () => {
    const ws = await Workspace.open(root, { limits: { maxFileBytes: 10 } });
    await expect(ws.readFile('src')).rejects.toThrow(/directory/);
    await expect(ws.readFile('src/app.js')).rejects.toThrow(/too large/);
  });

  it('truncates long reads', async () => {
    const ws = await Workspace.open(root, { limits: { maxReadChars: 35 } });
    const result = await ws.readFile('src/app.js');
    expect(result.truncated).toBe(true);
    expect(result.endLine).toBe(1);
  });
});

describe('Workspace.grep', () => {
  it('skips dependencies and credential files', async () => {
    const ws = await Workspace.open(root);
    const { matches } = await ws.grep('template|API_KEY');
    expect(matches).toEqual([
      { path: '.env.example', line: 1, text: 'API_KEY=' },
      { path: 'src/app.js', line: 2, text: '_.template(input);' },
    ]);
  });

  it('searches a dependency when the path filter names its directory', async () => {
    await mkdir(join(root, '.venv/lib/python3.11/site-packages/aiohttp'), { recursive: true });
    await writeFile(join(root, '.venv/lib/python3.11/site-packages/aiohttp/web.py'), 'def template(): pass\n');
    await writeFile(join(root, '.venv/lib/python3.11/site-packages/aiohttp/.env'), 'TOKEN=x\n');
    const ws = await Workspace.open(root);

    expect((await ws.grep('template', { pathContains: 'node_modules/lodash/' })).matches).toEqual([
      { path: 'node_modules/lodash/index.js', line: 1, text: 'module.exports.template = () => {};' },
    ]);
    expect((await ws.grep('template', { pathContains: 'site-packages/aiohttp/' })).matches).toEqual([
      { path: '.venv/lib/python3.11/site-packages/aiohttp/web.py', line: 1, text: 'def template(): pass' },
    ]);
    expect((await ws.grep('TOKEN', { pathContains: '.venv/' })).matches).toEqual([]);
    expect((await ws.grep('template', { pathContains: 'lodash' })).matches).toEqual([]);
  });

  it('never searches version control internals, even when named', async () => {
    await mkdir(join(root, '.git'));
    await writeFile(join(root, '.git/config'), 'template = yes\n');
    const ws = await Workspace.open(root);
    expect((await ws.grep('template', { pathContains: '.git/' })).matches).toEqual([]);
  });

  it('does not follow symlinks out of the repository', async () => {
    await symlink(outside, join(root, 'escape'));
    const ws = await Workspace.open(root);
    expect((await ws.grep('outside')).matches).toEqual([]);
  });

  it('filters by path and case', async () => {
    const ws = await Workspace.open(root);
    expect((await ws.grep('CONSOLE', { ignoreCase: true, pathContains: 'src/' })).matches).toHaveLength(1);
    expect((await ws.grep('CONSOLE')).matches).toHaveLength(0);
  });

  it('reports an invalid pattern as an access error', async () => {
    const ws = await Workspace.open(root);
    await expect(ws.grep('(')).rejects.toBeInstanceOf(WorkspaceAccessError);
  });

  it('stops at the match limit', async () => {
    const ws = await Workspace.open(root, { limits: { maxGrepMatches: 1 } });
    const result = await ws.grep('.');
    expect(result.matches).toHaveLength(1);
    expect(result.truncated).toBe(true);
  });
});

describe('Workspace.listDir', () => {
  it('hides credential files', async () => {
    const ws = await Workspace.open(root);
    const { entries } = await ws.listDir('.');
    expect(entries).toContain('.env.example');
    expect(entries).toContain('src/');
    expect(entries).not.toContain('.env');
  });
});

describe('Workspace.unchanged', () => {
  it('holds while every read, search and listing would look the same', async () => {
    const first = await Workspace.open(root);
    await first.readFile('src/app.js');
    await first.grep('template', { pathContains: 'src' });
    await first.listDir('src');
    const inputs = first.inputs();

    expect(await (await Workspace.open(root)).unchanged(inputs)).toBe(true);
  });

  it('breaks when a file that was read changes', async () => {
    const first = await Workspace.open(root);
    await first.readFile('src/app.js');
    const inputs = first.inputs();
    await writeFile(join(root, 'src/app.js'), '// changed\n');
    expect(await (await Workspace.open(root)).unchanged(inputs)).toBe(false);
  });

  it('breaks when a new file would change a search result', async () => {
    const first = await Workspace.open(root);
    await first.grep('template');
    const inputs = first.inputs();
    await writeFile(join(root, 'src/other.js'), '_.template(more);\n');
    expect(await (await Workspace.open(root)).unchanged(inputs)).toBe(false);
  });

  it('breaks when a file that was read disappears, or nothing was observed', async () => {
    const first = await Workspace.open(root);
    await first.readFile('config.yml');
    const inputs = first.inputs();
    await rm(join(root, 'config.yml'));
    const ws = await Workspace.open(root);
    expect(await ws.unchanged(inputs)).toBe(false);
    expect(await ws.unchanged([])).toBe(false);
  });
});
