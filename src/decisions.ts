/**
 * Decisions a person made about findings, in `.minotaur/decisions.yml`. The
 * file is meant to be committed, so the team shares them and reviews them in
 * pull requests. Each decision is keyed by the finding's full fingerprint,
 * which stays the same between runs and scanners.
 *
 * A false positive on a secret also lifts the protection on its file, as on
 * the platform, so checks may read it and send it to the model. Anyone who can
 * change the file can do that, which is why it belongs in review.
 */

import { spawn } from 'node:child_process';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { dirname, join } from 'node:path';

import { focusRank, type FindingState } from './core/index.js';
import { parse, stringify } from 'yaml';
import { z } from 'zod';

import type { LocalFinding } from './sources.js';

export const DECISIONS_FILE = '.minotaur/decisions.yml';

export const DECISION_STATES = ['confirmed', 'false_positive', 'accepted_risk', 'fixed'] as const satisfies readonly FindingState[];
export type DecisionState = (typeof DECISION_STATES)[number];

/** States that take a finding off the list: someone looked and it needs nothing more. */
export const CLOSED_STATES: ReadonlySet<DecisionState> = new Set(['false_positive', 'accepted_risk', 'fixed']);

export const DECISION_LABEL: Record<DecisionState, string> = {
  confirmed: 'confirmed',
  false_positive: 'false positive',
  accepted_risk: 'accepted risk',
  fixed: 'fixed',
};

export const decisionSchema = z.strictObject({
  fingerprint: z.string().regex(/^[0-9a-f]{64}$/, 'must be a full 64-character fingerprint'),
  state: z.enum(DECISION_STATES),
  reason: z.string().max(2000).optional(),
  /** For people reading the file; the fingerprint is what matches. */
  title: z.string().optional(),
  path: z.string().optional(),
  by: z.string().optional(),
  at: z.string().optional(),
});
export type Decision = z.infer<typeof decisionSchema>;

const fileSchema = z.strictObject({ decisions: z.array(decisionSchema).default([]) });

const HEADER = `# Decisions about minotaur findings. Commit this file to share them.
# A false positive on a secret lets checks read that file and send it to the model.
`;

/** The decisions for the repository at `root`, by fingerprint. */
export async function loadDecisions(root: string): Promise<Map<string, Decision>> {
  const path = join(root, DECISIONS_FILE);
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new Map();
    throw error;
  }
  let raw: unknown;
  try {
    raw = parse(text) ?? {};
  } catch (error) {
    throw new Error(`${DECISIONS_FILE} is not valid YAML: ${(error as Error).message}`);
  }
  const parsed = fileSchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`${DECISIONS_FILE}: ${issue?.path.join('.') || 'top level'} ${issue?.message ?? 'is not valid'}`);
  }
  return new Map(parsed.data.decisions.map((decision) => [decision.fingerprint, decision]));
}

/** Records a decision, or with `open`, removes it. Returns the decisions as they are now. */
export async function saveDecision(
  root: string,
  finding: Pick<LocalFinding, 'fingerprint' | 'title' | 'location'>,
  state: DecisionState | 'open',
  options: { reason?: string | undefined; by?: string | undefined; now?: Date } = {},
): Promise<Map<string, Decision>> {
  const decisions = await loadDecisions(root);
  if (state === 'open') {
    decisions.delete(finding.fingerprint);
  } else {
    const reason = options.reason?.trim();
    decisions.set(finding.fingerprint, {
      fingerprint: finding.fingerprint,
      state,
      ...(reason ? { reason } : {}),
      title: finding.title,
      ...(finding.location?.path ? { path: finding.location.path } : {}),
      ...(options.by ? { by: options.by } : {}),
      at: (options.now ?? new Date()).toISOString().slice(0, 10),
    });
  }
  // Sorted by path so a new decision lands next to the others for that file, and diffs stay small.
  const sorted = [...decisions.values()].sort(
    (a, b) => (a.path ?? '').localeCompare(b.path ?? '') || a.fingerprint.localeCompare(b.fingerprint),
  );
  const path = join(root, DECISIONS_FILE);
  await mkdir(dirname(path), { recursive: true });
  const staging = `${path}.${process.pid}.tmp`;
  await writeFile(staging, HEADER + stringify({ decisions: sorted }, { lineWidth: 0 }));
  await rename(staging, path);
  return decisions;
}

/**
 * Attaches each finding's decision. A confirmed finding becomes likely and
 * moves up with the other likely ones; the order is otherwise kept.
 */
export function applyDecisions(findings: readonly LocalFinding[], decisions: ReadonlyMap<string, Decision>): LocalFinding[] {
  const decided = findings.map((finding, index) => {
    const decision = decisions.get(finding.fingerprint);
    if (!decision) return { finding, index };
    const confirmed = decision.state === 'confirmed';
    const reason = `${DECISION_LABEL[decision.state]} by ${decision.by ?? 'a person'}${decision.reason ? `: ${decision.reason}` : ''}`;
    return {
      finding: {
        ...finding,
        decision,
        ...(confirmed ? { focus: 'likely' as const, focusReasons: [reason, ...(finding.focusReasons ?? [])] } : {}),
      },
      index,
    };
  });
  decided.sort(
    (a, b) =>
      focusRank(b.finding.focus ?? 'maybe') - focusRank(a.finding.focus ?? 'maybe') ||
      Number(b.finding.decision?.state === 'confirmed') - Number(a.finding.decision?.state === 'confirmed') ||
      a.index - b.index,
  );
  return decided.map(({ finding }) => finding);
}

export function isClosed(finding: LocalFinding): boolean {
  return finding.decision !== undefined && CLOSED_STATES.has(finding.decision.state);
}

/**
 * The protected files once false positives are taken into account: a file
 * stays protected while any secret found in it is not marked a false positive.
 */
export function liftProtected(protectedPaths: Iterable<string>, findings: readonly LocalFinding[]): Set<string> {
  const secrets = findings.filter((finding) => finding.kind === 'secret' && finding.location?.path);
  const stillSecret = new Set(secrets.filter((finding) => finding.decision?.state !== 'false_positive').map((finding) => finding.location!.path));
  const cleared = new Set(secrets.filter((finding) => finding.decision?.state === 'false_positive').map((finding) => finding.location!.path));
  return new Set([...protectedPaths, ...stillSecret].filter((path) => !cleared.has(path) || stillSecret.has(path)));
}

/** "false-positive" or "false_positive" on the command line; `open` removes a decision. */
export function parseDecisionState(value: string): DecisionState | 'open' | null {
  const normalized = value.trim().toLowerCase().replace(/[- ]/g, '_');
  if (normalized === 'open') return 'open';
  return (DECISION_STATES as readonly string[]).includes(normalized) ? (normalized as DecisionState) : null;
}

/** Who made the decision: the git user name, or the login name. */
export async function decider(root: string): Promise<string | undefined> {
  const name = await new Promise<string>((done) => {
    const child = spawn('git', ['config', 'user.name'], { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '';
    child.stdout.on('data', (chunk: Buffer) => (out += chunk.toString('utf8')));
    child.on('error', () => done(''));
    child.on('close', () => done(out.trim()));
  });
  if (name) return name;
  try {
    return userInfo().username;
  } catch {
    return undefined;
  }
}
