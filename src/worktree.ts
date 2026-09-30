/**
 * The branch a fix is committed to, and the worktree it is made in.
 *
 * The worktree starts at the commit the findings came from and lives in the
 * cache, so the person's working tree, and whatever they have not committed,
 * is never touched. The branch outlives the worktree: it is what the person
 * reviews and merges.
 */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';

import type { Target } from './commit.js';

export class WorktreeError extends Error {}

export interface FixBranch {
  /** Such as `minotaur/fix-3f9a1c2e`. */
  name: string;
  /** The commit the branch started from. */
  base: string;
  /** The worktree's top directory. */
  worktree: string;
  /** The directory the findings are relative to: the worktree, or the same subdirectory of it as the scanned one. */
  tree: string;
  /** The repository the branch belongs to. */
  top: string;
}

/** `minotaur/fix-<id>` for one finding, `minotaur/fixes-<commit>` for several. */
export function branchName(ids: readonly string[], commitShort: string): string {
  return ids.length === 1 ? `minotaur/fix-${ids[0]}` : `minotaur/fixes-${commitShort}`;
}

export async function branchExists(top: string, name: string): Promise<boolean> {
  return (await git(top, ['rev-parse', '-q', '--verify', `refs/heads/${name}`])).code === 0;
}

/**
 * Makes the branch at the target commit and checks it out in a new worktree.
 * An existing branch is an error unless `force`, which moves it.
 */
export async function openFixBranch(target: Target, name: string, cache: string, options: { force?: boolean } = {}): Promise<FixBranch> {
  const top = target.top;
  if ((await git(top, ['check-ref-format', '--branch', name])).code !== 0) throw new WorktreeError(`"${name}" is not a valid branch name`);
  if (!options.force && (await branchExists(top, name))) {
    throw new WorktreeError(`branch ${name} already exists; delete it, or pass --force to replace it`);
  }
  const worktrees = join(cache, 'worktrees', createHash('sha256').update(top).digest('hex').slice(0, 16));
  const worktree = join(worktrees, name.replace(/[^A-Za-z0-9._-]/g, '_'));
  // Left over from a run that was killed: git still lists it, and a branch checked out there cannot be moved.
  await git(top, ['worktree', 'remove', '--force', worktree]);
  await rm(worktree, { recursive: true, force: true });
  await git(top, ['worktree', 'prune']);
  await mkdir(worktrees, { recursive: true, mode: 0o700 });
  await must(top, ['worktree', 'add', '-q', options.force ? '-B' : '-b', name, worktree, target.commit.sha], `could not make branch ${name}`);
  return { name, base: target.commit.sha, worktree, tree: join(worktree, target.prefix), top };
}

/** Commits exactly these files, as the person's git identity, with their hooks. Returns the new commit. */
export async function commitFix(branch: FixBranch, files: readonly string[], message: string): Promise<string> {
  const paths = files.map((file) => join(branch.tree, file));
  await must(branch.worktree, ['add', '--', ...paths], 'could not stage the fix');
  if ((await git(branch.worktree, ['diff', '--cached', '--quiet'])).code === 0) throw new WorktreeError('the edits leave the files as they were');
  await must(branch.worktree, ['commit', '-q', '-F', '-'], 'could not commit the fix', message);
  return (await must(branch.worktree, ['rev-parse', 'HEAD'], 'could not read the new commit')).trim();
}

/** What the edits add and remove since the last commit on the branch, as a unified diff. New files included. */
export async function uncommittedDiff(branch: FixBranch, files: readonly string[]): Promise<string> {
  const paths = files.map((file) => join(branch.tree, file));
  // Intent-to-add makes new files show in the diff without staging their content.
  await git(branch.worktree, ['add', '-N', '--', ...paths]);
  return must(branch.worktree, ['diff', '--no-color', '--no-ext-diff', 'HEAD', '--', ...paths], 'could not diff the fix');
}

/** Drops every uncommitted edit, so the next fix starts from the last commit. */
export async function discardChanges(branch: FixBranch): Promise<void> {
  await must(branch.worktree, ['reset', '-q', '--hard', 'HEAD'], 'could not undo the edits');
  await must(branch.worktree, ['clean', '-q', '-f', '-d'], 'could not remove new files');
}

/** How many commits the branch has on top of where it started. */
export async function commitsOnBranch(branch: FixBranch): Promise<number> {
  return Number((await must(branch.worktree, ['rev-list', '--count', `${branch.base}..HEAD`], 'could not count commits')).trim());
}

/** Removes the worktree. The branch is kept only when it has commits: an empty one is noise. */
export async function closeFixBranch(branch: FixBranch): Promise<{ kept: boolean }> {
  const kept = (await commitsOnBranch(branch).catch(() => 0)) > 0;
  await git(branch.top, ['worktree', 'remove', '--force', branch.worktree]);
  await rm(branch.worktree, { recursive: true, force: true });
  await git(branch.top, ['worktree', 'prune']);
  if (!kept) await git(branch.top, ['branch', '-q', '-D', branch.name]);
  return { kept };
}

async function must(cwd: string, args: readonly string[], what: string, input?: string): Promise<string> {
  const result = await git(cwd, args, input);
  if (result.code !== 0) throw new WorktreeError(`${what}: ${result.stderr.trim() || `git ${args[0]} failed`}`);
  return result.stdout;
}

function git(cwd: string, args: readonly string[], input?: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done) => {
    const child = spawn('git', args, { cwd, stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout!.on('data', (chunk: Buffer) => out.push(chunk));
    child.stderr!.on('data', (chunk: Buffer) => err.push(chunk));
    child.on('error', (error) => done({ code: 1, stdout: '', stderr: error.message }));
    child.on('close', (code) =>
      done({ code: code ?? 1, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }),
    );
    if (input !== undefined) child.stdin!.end(input);
  });
}
