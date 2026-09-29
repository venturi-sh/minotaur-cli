/**
 * Finished checks, kept per repository, commit and finding.
 *
 * On the commit it was made on, a check applies as it is: the code it read
 * cannot have changed. From another commit it is carried over on the same rule
 * as the platform (same prompt version and model, and every file the agent
 * read and every search it ran would come out the same today), and then kept
 * for this commit too, so that rule runs once per commit rather than per load.
 */

import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import { EXPLOIT_PROMPT_VERSION, Workspace, isReusable } from './agent/index.js';
import { assessmentInputSchema, type AssessmentInput } from './core/index.js';
import { z } from 'zod';

import type { LocalFinding } from './sources.js';
import { triageResultSchema, type TriageResult } from './triage.js';

const FORMAT = 2;
/** Where checks made without a commit are kept. They are always verified before reuse. */
const NO_COMMIT = 'no-commit';

/** Which model setup a check came from. A different model or effort may answer differently. */
export interface CheckIdentity {
  model: string;
  effort: string | null;
}

export interface CachedCheck {
  result: TriageResult;
  createdAt: number;
  /** Where the check was made, such as "commit 3f9a1c2", when that was not this commit. */
  carriedFrom?: string;
}

/** Where checks are looked up: the repository as the person named it, and the commit, if any. */
export interface CheckScope {
  repo: string;
  commit: string | null;
  /** True when the tree is a clean copy of the commit, which has fewer files than the working tree. */
  copy?: boolean;
}

// Built on first use: triage.ts imports this module, so its schema is not ready while this one loads.
const entrySchema = () =>
  z.object({
    format: z.literal(FORMAT),
    repo: z.string(),
    commit: z.string().nullable(),
    effort: z.string().nullable(),
    inputs: z.array(assessmentInputSchema),
    createdAt: z.number(),
    result: triageResultSchema,
  });

/** Checks from before they were kept per commit, which can still be carried over. */
const legacySchema = () =>
  z.object({
    format: z.literal(1),
    root: z.string(),
    effort: z.string().nullable(),
    inputs: z.array(assessmentInputSchema),
    createdAt: z.number(),
    result: triageResultSchema,
  });

type Entry = z.infer<ReturnType<typeof entrySchema>>;

export function checkCacheDir(cache: string): string {
  return join(cache, 'checks');
}

/** Keeps a succeeded check. Anything else is not worth reusing, and a check that read nothing cannot be verified later. */
export async function saveCheck(
  dir: string,
  scope: CheckScope,
  result: TriageResult,
  inputs: readonly AssessmentInput[],
  identity: CheckIdentity,
  now = Date.now(),
): Promise<boolean> {
  if (result.status !== 'succeeded' || inputs.length === 0) return false;
  await writeEntry(dir, { format: FORMAT, repo: scope.repo, commit: scope.commit, effort: identity.effort, inputs: [...inputs], createdAt: now, result });
  return true;
}

/**
 * The earlier checks of these findings that still apply. `tree` is the
 * directory that holds the commit, and `protectedPaths` must still be
 * unreadable for a check to count.
 */
export async function loadChecks(
  dir: string,
  scope: CheckScope,
  tree: string,
  findings: readonly LocalFinding[],
  identity: CheckIdentity,
  protectedPaths: ReadonlySet<string>,
): Promise<Map<string, CachedCheck>> {
  const folder = repositoryDir(dir, scope.repo);
  const here = scope.commit ?? NO_COMMIT;
  const found = new Map<string, CachedCheck>();
  const suits = (entry: Entry | null, fingerprint: string): entry is Entry =>
    entry !== null &&
    entry.result.finding.fingerprint === fingerprint &&
    entry.result.model === identity.model &&
    entry.effort === identity.effort &&
    entry.result.promptVersion === EXPLOIT_PROMPT_VERSION &&
    !touchesProtected(entry, protectedPaths);

  const others = new Map<string, Array<{ path: string; label: string }>>();
  if (scope.commit) {
    for (const finding of findings) {
      const entry = await readEntry(join(folder, here, `${finding.fingerprint}.json`), scope.repo);
      if (suits(entry, finding.fingerprint)) found.set(finding.fingerprint, { result: entry.result, createdAt: entry.createdAt });
    }
  }
  const wanted = new Set(findings.map((finding) => finding.fingerprint).filter((fingerprint) => !found.has(fingerprint)));
  if (wanted.size === 0) return found;

  // A check that did not carry over to this commit will not next time either, so it is only tried once.
  const missesPath = join(folder, here, `misses-${scope.copy ? 'copy' : 'tree'}.json`);
  const misses = new Set(scope.commit ? await readMisses(missesPath) : []);
  const missed = misses.size;
  for (const name of await readdir(folder).catch(() => [] as string[])) {
    if (name === here && scope.commit) continue;
    const files = name.endsWith('.json') ? [name] : await readdir(join(folder, name)).catch(() => [] as string[]);
    for (const file of files) {
      const fingerprint = file.slice(0, -'.json'.length);
      if (!file.endsWith('.json') || !wanted.has(fingerprint)) continue;
      const path = name.endsWith('.json') ? join(folder, name) : join(folder, name, file);
      others.set(fingerprint, [...(others.get(fingerprint) ?? []), { path, label: name.endsWith('.json') ? file : `${name}/${file}` }]);
    }
  }

  let workspace: Workspace | null = null;
  for (const [fingerprint, candidates] of others) {
    const entries = (
      await Promise.all(
        candidates.map(async ({ path, label }) => {
          const entry = await readEntry(path, scope.repo);
          return entry && suits(entry, fingerprint) ? { entry, miss: `${label}@${entry.createdAt}` } : null;
        }),
      )
    ).filter((candidate) => candidate !== null && !misses.has(candidate.miss)) as Array<{ entry: Entry; miss: string }>;
    // The newest check first: it is the most likely to still apply, and the best answer when it does.
    for (const { entry, miss } of entries.sort((a, b) => b.entry.createdAt - a.entry.createdAt)) {
      workspace ??= await Workspace.open(tree, { denied: [...protectedPaths] });
      const current = { promptVersion: EXPLOIT_PROMPT_VERSION, modelId: identity.model };
      const previous = { status: entry.result.status, promptVersion: entry.result.promptVersion, model: entry.result.model, inputs: entry.inputs };
      if (!(await isReusable(previous, current, workspace))) {
        misses.add(miss);
        continue;
      }
      const carriedFrom = entry.commit ? `commit ${entry.commit.slice(0, 7)}` : 'an earlier run';
      found.set(fingerprint, { result: entry.result, createdAt: entry.createdAt, carriedFrom });
      if (scope.commit) {
        await writeEntry(dir, { ...entry, format: FORMAT, repo: scope.repo, commit: scope.commit }).catch(() => {});
      }
      break;
    }
  }
  if (scope.commit && misses.size > missed) await writeMisses(missesPath, misses).catch(() => {});
  return found;
}

async function readMisses(path: string): Promise<string[]> {
  try {
    const parsed = z.array(z.string()).safeParse(JSON.parse(await readFile(path, 'utf8')));
    return parsed.success ? parsed.data : [];
  } catch {
    return [];
  }
}

async function writeMisses(path: string, misses: ReadonlySet<string>): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const staging = `${path}.${process.pid}.tmp`;
  await writeFile(staging, JSON.stringify([...misses]), { mode: 0o600 });
  await rename(staging, path);
}

/** A check that read a file now known to hold a secret, or cites one, is not shown again. */
function touchesProtected(entry: Entry, protectedPaths: ReadonlySet<string>): boolean {
  if (protectedPaths.size === 0) return false;
  return (
    entry.inputs.some((input) => protectedPaths.has(input.path)) ||
    entry.result.evidence.some((item) => protectedPaths.has(item.path))
  );
}

async function writeEntry(dir: string, entry: Entry): Promise<void> {
  // Checks quote code, so they are readable by this user only.
  const folder = join(repositoryDir(dir, entry.repo), entry.commit ?? NO_COMMIT);
  await mkdir(folder, { recursive: true, mode: 0o700 });
  const path = join(folder, `${entry.result.finding.fingerprint}.json`);
  const staging = `${path}.${process.pid}.tmp`;
  await writeFile(staging, JSON.stringify(entry), { mode: 0o600 });
  await rename(staging, path);
}

async function readEntry(path: string, repo: string): Promise<Entry | null> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return null;
  }
  const parsed = entrySchema().safeParse(raw);
  if (parsed.success) return parsed.data.repo === repo ? parsed.data : null;
  const legacy = legacySchema().safeParse(raw);
  if (!legacy.success || legacy.data.root !== repo) return null;
  const { root: _root, ...rest } = legacy.data;
  return { ...rest, format: FORMAT, repo, commit: null };
}

function repositoryDir(dir: string, repo: string): string {
  return join(dir, createHash('sha256').update(repo).digest('hex').slice(0, 16));
}
