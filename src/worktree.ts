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
import { mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

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

/** Every fix goes on this branch unless another is named: one branch to review, one commit per fix. */
export const DEFAULT_BRANCH = 'minotaur/fixes';

export async function branchExists(top: string, name: string): Promise<boolean> {
  return (await git(top, ['rev-parse', '-q', '--verify', `refs/heads/${name}`])).code === 0;
}

/**
 * Checks out the fix branch in its worktree, making the branch at the target
 * commit when it does not exist, or when `force` starts it again.
 *
 * An existing branch is continued. When the target commit is newer than the
 * branch, it is merged in first, so each fix is made and verified on the code
 * the findings came from; a branch that was already merged just moves forward.
 * A merge that conflicts is left for the person.
 *
 * The worktree is shared by every fix of the branch, and an agent's fix waits
 * in it between commands. Uncommitted edits there are never thrown away.
 */
export async function openFixBranch(target: Target, name: string, cache: string, options: { force?: boolean } = {}): Promise<FixBranch> {
  const top = target.top;
  if ((await git(top, ['check-ref-format', '--branch', name])).code !== 0) throw new WorktreeError(`"${name}" is not a valid branch name`);
  const worktree = worktreeDir(top, name, cache);
  if ((await isWorktree(top, worktree)) && (await hasEdits(worktree))) {
    const claim = await readClaim(worktree);
    const who = claim ? ` for finding ${claim.id}` : '';
    const next = claim ? `run "minotaur fix ${claim.id} --verify" to commit them, or "minotaur fix ${claim.id} --discard"` : 'commit or remove them';
    throw new WorktreeError(`branch ${name} has uncommitted edits${who} in ${join(worktree, target.prefix)}; ${next} first`);
  }
  // Left over from a run that was killed, or from an agent's fix that was committed or abandoned.
  await removeWorktree(top, worktree);
  await mkdir(dirname(worktree), { recursive: true, mode: 0o700 });
  const exists = await branchExists(top, name);
  if (!exists || options.force) {
    await must(top, ['worktree', 'add', '-q', options.force ? '-B' : '-b', name, worktree, target.commit.sha], `could not make branch ${name}`);
  } else {
    await must(top, ['worktree', 'add', '-q', worktree, name], `could not check out branch ${name}`);
    await catchUp(top, worktree, name, target);
  }
  return { name, base: target.commit.sha, worktree, tree: join(worktree, target.prefix), top };
}

/** Brings the branch up to the target commit: a fast-forward when it has no fixes of its own, a merge when it does. */
async function catchUp(top: string, worktree: string, name: string, target: Target): Promise<void> {
  if ((await git(worktree, ['merge-base', '--is-ancestor', target.commit.sha, 'HEAD'])).code === 0) return;
  const merged = await git(worktree, ['merge', '--no-edit', '-q', '-m', `Merge ${target.commit.short} into ${name}`, target.commit.sha]);
  if (merged.code === 0) return;
  await git(worktree, ['merge', '--abort']);
  await removeWorktree(top, worktree);
  const why = merged.stderr.trim().split('\n').slice(-2).join(' ') || 'the merge failed';
  throw new WorktreeError(
    `branch ${name} cannot take the changes of ${target.commit.short} (${why}); merge ${target.commit.short} into it yourself, or pass --force to start it again from ${target.commit.short}`,
  );
}

async function isWorktree(top: string, worktree: string): Promise<boolean> {
  const real = await realpath(worktree).catch(() => null);
  if (!real) return false;
  const listed = (await git(top, ['worktree', 'list', '--porcelain'])).stdout.split('\n');
  const paths = await Promise.all(listed.filter((line) => line.startsWith('worktree ')).map((line) => realpath(line.slice(9)).catch(() => '')));
  return paths.includes(real);
}

async function hasEdits(worktree: string): Promise<boolean> {
  const status = await git(worktree, ['status', '--porcelain', '--untracked-files=all']);
  return status.code === 0 && status.stdout.trim().length > 0;
}

async function removeWorktree(top: string, worktree: string): Promise<void> {
  await git(top, ['worktree', 'remove', '--force', worktree]);
  await rm(worktree, { recursive: true, force: true });
  await git(top, ['worktree', 'prune']);
}

/** Where a branch's worktree is kept in the cache. */
export function worktreeDir(top: string, name: string, cache: string): string {
  return join(cache, 'worktrees', createHash('sha256').update(top).digest('hex').slice(0, 16), name.replace(/[^A-Za-z0-9._-]/g, '_'));
}

/** Which finding an agent is fixing in the worktree, kept beside it between `brief --fix` and `fix --verify`. */
export interface Claim {
  id: string;
  fingerprint: string;
}

function claimPath(worktree: string): string {
  return `${worktree}.claim.json`;
}

export async function readClaim(worktree: string): Promise<Claim | null> {
  try {
    return JSON.parse(await readFile(claimPath(worktree), 'utf8')) as Claim;
  } catch {
    return null;
  }
}

export async function writeClaim(branch: FixBranch, claim: Claim): Promise<void> {
  await writeFile(claimPath(branch.worktree), JSON.stringify(claim), { mode: 0o600 });
}

/**
 * The worktree an agent is editing, left open between commands. Null when
 * there is none, such as before `brief --fix` or after the fix was committed.
 */
export async function existingFixBranch(target: Target, name: string, cache: string): Promise<FixBranch | null> {
  const worktree = worktreeDir(target.top, name, cache);
  if (!(await isWorktree(target.top, worktree))) return null;
  if ((await git(worktree, ['merge-base', '--is-ancestor', target.commit.sha, 'HEAD'])).code !== 0) {
    throw new WorktreeError(`the worktree of ${name} was made from an older commit than ${target.commit.short}; pass the commit its brief named with --commit`);
  }
  return { name, base: target.commit.sha, worktree, tree: join(worktree, target.prefix), top: target.top };
}

/** A commit's patch, for showing a fix. */
export async function commitDiff(top: string, commit: string): Promise<string> {
  return must(top, ['show', '--no-color', '--no-ext-diff', '--format=', commit], 'could not show the fix');
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

/**
 * Files that differ from the last commit, new ones included, relative to the
 * tree. What a package manager changed is only known this way.
 */
export async function changedPaths(branch: FixBranch): Promise<string[]> {
  const tracked = await must(branch.tree, ['diff', '--name-only', '--relative', '-z', 'HEAD'], 'could not list changed files');
  const untracked = await must(branch.tree, ['ls-files', '--others', '--exclude-standard', '-z'], 'could not list new files');
  return [...new Set([...tracked.split('\0'), ...untracked.split('\0')].filter(Boolean))].sort();
}

/** The findings the branch already has a commit for, from their `Minotaur-Finding` trailers. */
export async function fixedOnBranch(branch: FixBranch): Promise<Set<string>> {
  const log = await must(
    branch.worktree,
    ['log', '--format=%(trailers:key=Minotaur-Finding,valueonly,separator=%x00)', `${branch.base}..HEAD`],
    'could not read the branch',
  );
  return new Set(log.split(/[\0\n]/).map((line) => line.trim()).filter(Boolean));
}

/** A fix committed on a `minotaur/` branch that the scanned commit does not have yet. */
export interface PendingFix {
  branch: string;
  commit: string;
  /** The model, package manager or agent that made it, from `Minotaur-Fixed-By`. */
  by: string | null;
  /** False when the commit says no scanner could check it. */
  verified: boolean;
}

/**
 * Fixes waiting to be merged, by the fingerprint of each finding they remove.
 * Read from the `Minotaur-Finding` trailers of the commits on every
 * `minotaur/` branch that `base` does not contain, so a fix disappears from
 * here once it is merged. The newest fix of a finding wins.
 */
export async function pendingFixes(top: string, base: string): Promise<Map<string, PendingFix>> {
  const fixes = new Map<string, PendingFix>();
  const refs = await git(top, ['for-each-ref', '--sort=-committerdate', '--format=%(refname:short)', 'refs/heads/minotaur/']);
  if (refs.code !== 0) return fixes;
  for (const branch of refs.stdout.split('\n').filter(Boolean)) {
    const format = '%H%x1f%(trailers:key=Minotaur-Finding,valueonly,separator=%x1d)%x1f%(trailers:key=Minotaur-Fixed-By,valueonly)%x1f%b%x1e';
    const log = await git(top, ['log', `--format=${format}`, `${base}..${branch}`, '--']);
    if (log.code !== 0) continue;
    for (const entry of log.stdout.split('\x1e')) {
      const [commit, findings = '', by = '', body = ''] = entry.trim().split('\x1f');
      if (!commit) continue;
      const fix: PendingFix = { branch, commit, by: by.trim() || null, verified: !body.includes('Not verified:') };
      for (const fingerprint of findings.split(/[\x1d\n]/).map((item) => item.trim()).filter(Boolean)) {
        if (!fixes.has(fingerprint)) fixes.set(fingerprint, fix);
      }
    }
  }
  return fixes;
}

/** Drops every uncommitted edit, so the next fix starts from the last commit. */
export async function discardChanges(branch: FixBranch): Promise<void> {
  await must(branch.worktree, ['reset', '-q', '--hard', 'HEAD'], 'could not undo the edits');
  await must(branch.worktree, ['clean', '-q', '-f', '-d'], 'could not remove new files');
}

/** How many commits the branch has that the target commit does not. */
export async function commitsOnBranch(branch: FixBranch): Promise<number> {
  return Number((await must(branch.top, ['rev-list', '--count', `${branch.base}..refs/heads/${branch.name}`], 'could not count commits')).trim());
}

/**
 * Removes the worktree. The branch is deleted only when it has no commit the
 * target lacks, so nothing is lost; when that cannot be counted, it is kept.
 */
export async function closeFixBranch(branch: FixBranch): Promise<{ kept: boolean }> {
  const kept = (await commitsOnBranch(branch).catch(() => 1)) > 0;
  await removeWorktree(branch.top, branch.worktree);
  await rm(claimPath(branch.worktree), { force: true });
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
