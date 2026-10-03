import { execFileSync } from 'node:child_process';
import { mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { resolveTarget } from './commit.js';

let dir: string;

beforeEach(async () => {
  dir = await realpath(await mkdtemp(join(tmpdir(), 'minotaur-commit-')));
  vi.stubEnv('GIT_AUTHOR_NAME', 't');
  vi.stubEnv('GIT_AUTHOR_EMAIL', 't@t');
  vi.stubEnv('GIT_COMMITTER_NAME', 't');
  vi.stubEnv('GIT_COMMITTER_EMAIL', 't@t');
});

afterEach(async () => {
  vi.unstubAllEnvs();
  await rm(dir, { recursive: true, force: true });
});

describe('resolveTarget', () => {
  it('makes a repository and a snapshot commit when you agree', async () => {
    await writeFile(join(dir, 'note.txt'), 'hello\n');
    const ask = vi.fn(async () => true);
    const target = await resolveTarget(dir, undefined, { ask });
    expect(ask).toHaveBeenCalledWith('This folder is not a git repository. Make one here and commit a snapshot? [y/N] ');
    expect(target.commit.subject).toBe('snapshot');
    expect(target.head).toBe(true);
    expect(target.copy).toBe(true);
    expect(target.uncommitted).toBe(false);
    expect(execFileSync('git', ['show', 'HEAD:note.txt'], { cwd: dir, encoding: 'utf8' })).toBe('hello\n');
  });

  it('leaves a folder without git when you decline', async () => {
    const ask = vi.fn(async () => false);
    await expect(resolveTarget(dir, undefined, { ask })).rejects.toThrow(/not in a git repository[\s\S]*git init && git add -A && git commit/);
    expect(ask).toHaveBeenCalledOnce();
  });

  it('does not offer when a commit was named', async () => {
    const ask = vi.fn(async () => true);
    await expect(resolveTarget(dir, 'HEAD', { ask })).rejects.toThrow(/not in a git repository/);
    expect(ask).not.toHaveBeenCalled();
  });

  it('commits a snapshot when the repository has no commits yet', async () => {
    execFileSync('git', ['init', '-q'], { cwd: dir });
    await writeFile(join(dir, 'note.txt'), 'hello\n');
    const ask = vi.fn(async () => true);
    const target = await resolveTarget(dir, undefined, { ask });
    expect(ask).toHaveBeenCalledWith('This repository has no commits yet. Commit a snapshot? [y/N] ');
    expect(target.commit.subject).toBe('snapshot');
    expect(target.head).toBe(true);
  });

  it('always uses a clean copy of the commit, even with a dirty working tree', async () => {
    execFileSync('git', ['init', '-q'], { cwd: dir });
    await writeFile(join(dir, 'note.txt'), 'hello\n');
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', 'add', '-A'], { cwd: dir });
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'first'], { cwd: dir });
    const clean = await resolveTarget(dir, undefined);
    expect(clean.copy).toBe(true);
    expect(clean.uncommitted).toBe(false);

    await writeFile(join(dir, 'note.txt'), 'dirty\n');
    await writeFile(join(dir, 'extra.txt'), 'x\n');
    const dirty = await resolveTarget(dir, undefined);
    expect(dirty.copy).toBe(true);
    expect(dirty.uncommitted).toBe(true);
    expect(dirty.commit.sha).toBe(clean.commit.sha);
  });
});
