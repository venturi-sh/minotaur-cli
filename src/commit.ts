/**
 * Which commit a run looks at, and the directory that holds it.
 *
 * On HEAD with nothing uncommitted, the working tree is that commit, and it
 * keeps the installed dependencies the agent may want to read. Anything else
 * gets a clean copy of the commit from `git archive`, kept in the cache, so
 * the scan and the checks describe exactly what was committed.
 */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readdir, rename, rm, stat, utimes } from 'node:fs/promises';
import { join } from 'node:path';

import { DECISIONS_FILE } from './decisions.js';

/** Clean copies kept per repository, the most recently used first. */
const KEPT_COPIES = 3;

export interface Commit {
  sha: string;
  short: string;
  subject: string;
}

export interface Target {
  /** The directory the person named. Caches are kept per this directory. */
  repo: string;
  /** Null outside a git repository, or in one without commits. */
  commit: Commit | null;
  /** True when the commit is HEAD. */
  head: boolean;
  /** True when the working tree has changes, including untracked files, that the commit does not have. */
  uncommitted: boolean;
  /** True when the working tree is not the commit, so a clean copy is scanned instead. */
  copy: boolean;
  /** The repository's top directory, and where `repo` sits in it. */
  top: string | null;
  prefix: string;
}

export class CommitError extends Error {}

/** Works out which commit to look at. Quick: only `git` metadata is read. */
export async function resolveTarget(repo: string, ref: string | undefined): Promise<Target> {
  const top = (await git(repo, ['rev-parse', '--show-toplevel']))?.trim();
  if (!top) {
    if (ref) throw new CommitError(`${repo} is not in a git repository, so --commit does not apply`);
    return { repo, commit: null, head: false, uncommitted: false, copy: false, top: null, prefix: '' };
  }
  const prefix = (await git(repo, ['rev-parse', '--show-prefix']))?.trim() ?? '';
  const head = (await git(top, ['rev-parse', '-q', '--verify', 'HEAD^{commit}']))?.trim() || null;
  const sha = (await git(top, ['rev-parse', '-q', '--verify', `${ref ?? 'HEAD'}^{commit}`]))?.trim() || null;
  if (!sha) {
    if (ref) throw new CommitError(`"${ref}" is not a commit in ${top}`);
    return { repo, commit: null, head: false, uncommitted: false, copy: false, top, prefix };
  }
  const [short = sha.slice(0, 7), subject = ''] = ((await git(top, ['log', '-1', '--format=%h%x00%s', sha])) ?? '').trim().split('\0');
  const status = await git(top, statusArgs(prefix));
  const uncommitted = status === null || status.length > 0;
  const isHead = sha === head;
  return { repo, commit: { sha, short, subject }, head: isHead, uncommitted, copy: !isHead || uncommitted, top, prefix };
}

/** The directory to scan and read: the working tree, or a clean copy of the commit made on first use. */
export async function treeFor(target: Target, cache: string): Promise<string> {
  if (!target.copy || !target.commit || !target.top) return target.repo;
  const copies = join(cache, 'trees', createHash('sha256').update(target.top).digest('hex').slice(0, 16));
  const dir = join(copies, target.commit.sha);
  if (await isDirectory(dir)) {
    const now = new Date();
    await utimes(dir, now, now).catch(() => {});
  } else {
    // Committed files can hold secrets, so the copies are readable by this user only.
    await mkdir(copies, { recursive: true, mode: 0o700 });
    const staging = `${dir}.${process.pid}.tmp`;
    await rm(staging, { recursive: true, force: true });
    await mkdir(staging, { mode: 0o700 });
    try {
      await archive(target.top, target.commit.sha, staging);
      await rename(staging, dir);
    } catch (error) {
      await rm(staging, { recursive: true, force: true });
      throw error;
    }
    await prune(copies);
  }
  const tree = join(dir, target.prefix);
  if (!(await isDirectory(tree))) throw new CommitError(`${target.prefix} is not in commit ${target.commit.short}`);
  return tree;
}

/** True while the working tree still matches the commit, so a check that read it describes the commit. */
export async function stillCommitted(target: Target): Promise<boolean> {
  if (target.copy) return true;
  if (!target.top) return false;
  return (await git(target.top, statusArgs(target.prefix))) === '';
}

/**
 * Changes that make the working tree differ from the commit. Marking a finding
 * writes the decisions file, and that alone should not switch every later run
 * to a clean copy; decisions are read from the working tree either way.
 */
function statusArgs(prefix: string): string[] {
  return ['status', '--porcelain', '-z', '--untracked-files=all', '--', ':/', `:(top,exclude)${prefix}${DECISIONS_FILE}`];
}

/** "commit 3f9a1c2 (Fix the login redirect)". */
export function describeCommit(commit: Commit): string {
  return `commit ${commit.short}${commit.subject ? ` (${commit.subject})` : ''}`;
}

/** What a person should know about where the findings come from, or nothing when it is the working tree as it is. */
export function targetNotes(target: Target): string[] {
  if (!target.commit) return target.top ? ['This repository has no commits yet, so the files are scanned as they are.'] : [];
  if (!target.copy) return [];
  const why = target.head
    ? `Uncommitted changes are left out: this is ${target.commit.short} as committed.`
    : `This is ${target.commit.short} as committed, not your working tree.`;
  return [`${why} Installed dependencies are not in a commit, so checks cannot read them.`];
}

function archive(top: string, sha: string, into: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const source = spawn('git', ['archive', '--format=tar', sha], { cwd: top, stdio: ['ignore', 'pipe', 'pipe'] });
    const sink = spawn('tar', ['-x', '-f', '-', '-C', into], { stdio: ['pipe', 'ignore', 'pipe'] });
    const errors: string[] = [];
    source.stderr.on('data', (chunk: Buffer) => errors.push(chunk.toString('utf8')));
    sink.stderr.on('data', (chunk: Buffer) => errors.push(chunk.toString('utf8')));
    source.stdout.pipe(sink.stdin);
    let pending = 2;
    let failed = false;
    const finish = (code: number | null) => {
      if (code !== 0) failed = true;
      if (--pending > 0) return;
      if (failed) reject(new Error(`could not copy commit ${sha.slice(0, 7)}: ${errors.join(' ').trim() || 'git archive failed'}`));
      else resolve();
    };
    source.on('error', reject);
    sink.on('error', reject);
    source.on('close', finish);
    sink.on('close', finish);
  });
}

async function prune(copies: string): Promise<void> {
  const names = (await readdir(copies).catch(() => [] as string[])).filter((name) => /^[0-9a-f]{40,64}$/.test(name));
  const dated = await Promise.all(names.map(async (name) => ({ name, at: (await stat(join(copies, name)).catch(() => null))?.mtimeMs ?? 0 })));
  const old = dated.sort((a, b) => b.at - a.at).slice(KEPT_COPIES);
  await Promise.all(old.map(({ name }) => rm(join(copies, name), { recursive: true, force: true })));
}

async function isDirectory(path: string): Promise<boolean> {
  return (await stat(path).catch(() => null))?.isDirectory() ?? false;
}

function git(cwd: string, args: readonly string[]): Promise<string | null> {
  return new Promise((done) => {
    const child = spawn('git', args, { cwd, stdio: ['ignore', 'pipe', 'ignore'] });
    const chunks: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    child.on('error', () => done(null));
    child.on('close', (code) => done(code === 0 ? Buffer.concat(chunks).toString('utf8') : null));
  });
}
