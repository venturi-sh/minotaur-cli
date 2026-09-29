/**
 * Exploitation evidence for the CVEs a scan found: whether CISA lists one as
 * exploited, and its EPSS score. Both change daily, so they are fetched fresh
 * once a day and kept in the cache between runs. Only the scan's own CVEs are
 * asked about, never the whole EPSS file.
 *
 * Neither is needed for a scan to be useful. Offline, an older copy is used
 * if there is one, and otherwise dependency findings are ranked on severity
 * and CVSS alone, with a note saying so.
 */

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { focusOf, focusRank, type AdvisoryRisk, type FocusOverrides } from './core/index.js';
import { fetchKev, lookupEpss, type EpssRow } from './feeds/index.js';
import { z } from 'zod';

import type { LocalFinding } from './sources.js';

export const ADVISORY_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const TIMEOUT_MS = 10_000;

export interface AdvisoryFetchers {
  kev: () => Promise<Array<{ id: string; ransomware: boolean }>>;
  epss: (ids: readonly string[]) => Promise<EpssRow[]>;
}

const NETWORK: AdvisoryFetchers = {
  kev: async () => (await fetchKev({ timeoutMs: TIMEOUT_MS })).entries,
  epss: (ids) => lookupEpss(ids, { timeoutMs: TIMEOUT_MS }),
};

const kevFileSchema = z.object({
  fetchedAt: z.number(),
  entries: z.array(z.object({ id: z.string(), ransomware: z.boolean() })),
});

const epssFileSchema = z.object({
  scores: z.record(z.string(), z.object({ score: z.number(), percentile: z.number(), fetchedAt: z.number() })),
  /** CVEs EPSS had no score for, so they are not asked about again until the entry is old. */
  unscored: z.record(z.string(), z.number()).default({}),
});

export interface AdvisoryLookup {
  risks: Map<string, AdvisoryRisk>;
  /** Set when some of the evidence could not be fetched. */
  note?: string;
}

export function advisoryCacheDir(cache: string): string {
  return join(cache, 'advisories');
}

/** KEV and EPSS for these ids. CVEs only: EPSS scores nothing else, and KEV lists CVEs. */
export async function lookupAdvisories(
  dir: string,
  ids: readonly string[],
  options: { now?: number; fetchers?: AdvisoryFetchers } = {},
): Promise<AdvisoryLookup> {
  const cves = [...new Set(ids.map((id) => id.trim().toUpperCase()).filter((id) => /^CVE-\d{4}-\d+$/.test(id)))];
  const risks = new Map<string, AdvisoryRisk>();
  if (cves.length === 0) return { risks };
  const now = options.now ?? Date.now();
  const fetchers = options.fetchers ?? NETWORK;
  const problems: string[] = [];

  const kev = await kevList(dir, now, fetchers, problems);
  const epss = await epssScores(dir, cves, now, fetchers, problems);
  for (const id of cves) {
    const listed = kev?.get(id);
    const score = epss.get(id);
    risks.set(id, {
      kev: listed !== undefined,
      kevRansomware: listed === true,
      ...(score ? { epss: score.score, epssPercentile: score.percentile } : {}),
    });
  }
  return problems.length > 0 ? { risks, note: problems.join(' ') } : { risks };
}

/** The most serious evidence among a finding's advisory ids. */
export function worstRisk(ids: readonly string[], risks: ReadonlyMap<string, AdvisoryRisk>): AdvisoryRisk | undefined {
  let worst: AdvisoryRisk | undefined;
  for (const id of ids) {
    const risk = risks.get(id.trim().toUpperCase());
    if (!risk) continue;
    worst = {
      kev: (worst?.kev ?? false) || risk.kev,
      kevRansomware: (worst?.kevRansomware ?? false) || risk.kevRansomware,
      ...maxEpss(worst, risk),
    };
  }
  return worst;
}

/**
 * Rates every finding, and orders them: likely issues first, then by risk
 * score and severity, as the list already was within a level.
 */
export function rankFindings(
  findings: readonly LocalFinding[],
  risks: ReadonlyMap<string, AdvisoryRisk>,
  overrides?: FocusOverrides,
): LocalFinding[] {
  const rated = findings.map((finding, index) => {
    const advisory = finding.kind === 'sca' ? worstRisk(finding.vulnerabilityIds, risks) : undefined;
    const assessment = focusOf(finding, { advisory, overrides });
    const ranked: LocalFinding = {
      ...finding,
      focus: assessment.focus,
      focusReasons: assessment.reasons,
      riskScore: assessment.riskScore,
      ...(advisory?.epss !== undefined ? { epss: advisory.epss } : {}),
      ...(advisory ? { kev: advisory.kev } : {}),
    };
    return { ranked, index };
  });
  rated.sort(
    (a, b) =>
      focusRank(b.ranked.focus!) - focusRank(a.ranked.focus!) ||
      (b.ranked.riskScore ?? 0) - (a.ranked.riskScore ?? 0) ||
      a.index - b.index,
  );
  return rated.map(({ ranked }) => ranked);
}

async function kevList(dir: string, now: number, fetchers: AdvisoryFetchers, problems: string[]): Promise<Map<string, boolean> | null> {
  const path = join(dir, 'kev.json');
  const cached = kevFileSchema.safeParse(await readJson(path));
  if (cached.success && now - cached.data.fetchedAt < ADVISORY_MAX_AGE_MS) return toKevMap(cached.data.entries);
  try {
    const entries = (await fetchers.kev()).map(({ id, ransomware }) => ({ id: id.toUpperCase(), ransomware }));
    await writeJson(path, { fetchedAt: now, entries }).catch(() => {});
    return toKevMap(entries);
  } catch (error) {
    if (cached.success) {
      problems.push(`Could not refresh the CISA exploited list (${reason(error)}), so the copy from ${daysAgo(now, cached.data.fetchedAt)} is used.`);
      return toKevMap(cached.data.entries);
    }
    problems.push(`Could not fetch the CISA exploited list (${reason(error)}), so no dependency is marked as exploited.`);
    return null;
  }
}

async function epssScores(
  dir: string,
  cves: readonly string[],
  now: number,
  fetchers: AdvisoryFetchers,
  problems: string[],
): Promise<Map<string, { score: number; percentile: number }>> {
  const path = join(dir, 'epss.json');
  const parsed = epssFileSchema.safeParse(await readJson(path));
  const file = parsed.success ? parsed.data : { scores: {}, unscored: {} };
  const fresh = (at: number | undefined) => at !== undefined && now - at < ADVISORY_MAX_AGE_MS;
  const missing = cves.filter((id) => !fresh(file.scores[id]?.fetchedAt) && !fresh(file.unscored[id]));

  if (missing.length > 0) {
    try {
      const rows = await fetchers.epss(missing);
      for (const row of rows) file.scores[row.id] = { score: row.score, percentile: row.percentile, fetchedAt: now };
      const scored = new Set(rows.map((row) => row.id));
      for (const id of missing) if (!scored.has(id)) file.unscored[id] = now;
      await writeJson(path, file).catch(() => {});
    } catch (error) {
      const stale = missing.filter((id) => file.scores[id]).length;
      problems.push(
        `Could not fetch EPSS scores (${reason(error)})${stale > 0 ? `, so older scores are used for ${stale} of them` : ''}; dependency findings without one are ranked on severity and CVSS.`,
      );
    }
  }
  return new Map(cves.flatMap((id) => (file.scores[id] ? [[id, file.scores[id]!] as const] : [])));
}

function toKevMap(entries: ReadonlyArray<{ id: string; ransomware: boolean }>): Map<string, boolean> {
  return new Map(entries.map((entry) => [entry.id, entry.ransomware]));
}

function maxEpss(a: AdvisoryRisk | undefined, b: AdvisoryRisk): Pick<AdvisoryRisk, 'epss' | 'epssPercentile'> {
  const best = (a?.epss ?? -1) >= (b.epss ?? -1) ? a : b;
  return best?.epss !== undefined
    ? { epss: best.epss, ...(best.epssPercentile !== undefined ? { epssPercentile: best.epssPercentile } : {}) }
    : {};
}

function reason(error: unknown): string {
  const cause = (error as { cause?: { code?: string } }).cause?.code;
  return cause ?? (error as Error).message ?? String(error);
}

function daysAgo(now: number, then: number): string {
  const days = Math.floor((now - then) / ADVISORY_MAX_AGE_MS);
  return days <= 1 ? 'yesterday' : `${days} days ago`;
}

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return undefined;
  }
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(join(path, '..'), { recursive: true, mode: 0o700 });
  const staging = `${path}.${process.pid}.tmp`;
  await writeFile(staging, JSON.stringify(value), { mode: 0o600 });
  await rename(staging, path);
}
