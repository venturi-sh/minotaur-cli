/**
 * Risk scoring.
 *
 * Severity answers "how bad would this be", which is only half the question.
 * A CVSS 9.8 nobody has ever exploited is less urgent than a CVSS 5.0 being
 * used in ransomware campaigns this week, and a findings list sorted by
 * severity puts them in the wrong order. This module folds exploitation
 * evidence into the ranking.
 *
 * The function is pure and lives in core on purpose: it is called both when a
 * scan persists findings and when a feed refresh rescores stored ones.
 * Expressing it a second time in SQL would be faster and would drift.
 *
 * Isomorphic, like the rest of core — no Node builtins.
 */

import { z } from 'zod';

import type { Cvss, Finding, Severity } from './finding.js';

/**
 * Deliberately three tiers rather than a spectrum. The score exists to order a
 * list; the tier exists to answer "do I need to do something about this", and
 * people do not act differently on a 61 versus a 64.
 */
export const PRIORITIES = ['act', 'attend', 'track'] as const;
export const prioritySchema = z.enum(PRIORITIES);
export type Priority = z.infer<typeof prioritySchema>;

const PRIORITY_RANK: Record<Priority, number> = { act: 3, attend: 2, track: 1 };

export function priorityRank(priority: Priority): number {
  return PRIORITY_RANK[priority];
}

/** The exploitation evidence known for an advisory, as cached from the feeds. */
export const advisoryRiskSchema = z.object({
  /** EPSS probability of exploitation in the next 30 days, 0 to 1. */
  epss: z.number().min(0).max(1).optional(),
  /** Where that probability sits against every other scored CVE, 0 to 1. */
  epssPercentile: z.number().min(0).max(1).optional(),
  /** Listed in the CISA Known Exploited Vulnerabilities catalog. */
  kev: z.boolean().default(false),
  kevRansomware: z.boolean().default(false),
  /** ISO date CISA added the entry, used only to explain the score. */
  kevAddedAt: z.string().optional(),
});
export type AdvisoryRisk = z.infer<typeof advisoryRiskSchema>;

export const riskAssessmentSchema = z.object({
  score: z.number().int().min(0).max(100),
  priority: prioritySchema,
  /** Why this score, in one sentence. Shown in the UI so the number is arguable. */
  rationale: z.string(),
  /** Denormalized onto the finding so the list can filter without a join. */
  epss: z.number().min(0).max(1).optional(),
  kev: z.boolean(),
});
export type RiskAssessment = z.infer<typeof riskAssessmentSchema>;

/** A finding with its risk attached. Scanners never produce these; enrichment does. */
export interface EnrichedFinding extends Finding {
  risk: RiskAssessment;
}

/**
 * How much of the impact scale each severity is worth when no CVSS score is
 * available. Nothing reaches 1.0: a severity label is a coarser signal than a
 * vector, and should not outrank one.
 */
const SEVERITY_IMPACT: Record<Severity, number> = {
  critical: 0.9,
  high: 0.7,
  medium: 0.45,
  low: 0.2,
  info: 0.05,
  unknown: 0.35,
};

/**
 * EPSS probabilities are crushed against zero — the median CVE sits near
 * 0.0004 — so a linear term would rank almost identically to CVSS and defeat
 * the purpose. Log scaling below this floor stops being informative.
 */
const EPSS_FLOOR = 1e-5;
const EPSS_DECADES = -Math.log10(EPSS_FLOOR);

/**
 * Applied when there is no advisory to look up at all. Secrets, SAST and IaC
 * findings have no CVE and never will, so they are ranked on impact with a
 * mild discount rather than pushed to the bottom for missing data they cannot
 * have.
 */
const NO_ADVISORY_MODIFIER = 0.85;

/**
 * Exploitation observed in the wild is fact rather than prediction, so a KEV
 * listing sets a floor no amount of low severity can pull below.
 */
const KEV_FLOOR = 85;
const KEV_RANSOMWARE_FLOOR = 95;

const ACT_AT = 70;
const ATTEND_AT = 40;

export interface RiskInput {
  severity: Severity;
  cvss?: Cvss | undefined;
  /** Absent when the finding has no advisory, or none of its ids are known. */
  advisory?: AdvisoryRisk | undefined;
}

export function scoreFinding(input: RiskInput): RiskAssessment {
  const impact = impactOf(input);
  const advisory = input.advisory;

  const kev = advisory?.kev === true;
  const epss = advisory?.epss;

  const modifier = kev ? 1 : epss !== undefined ? epssModifier(epss) : NO_ADVISORY_MODIFIER;

  let score = Math.round(100 * impact * modifier);
  if (kev) {
    score = Math.max(score, advisory?.kevRansomware === true ? KEV_RANSOMWARE_FLOOR : KEV_FLOOR);
  }
  score = clamp(score, 0, 100);

  return {
    score,
    priority: priorityFor(score),
    rationale: explain(input, { kev, epss }),
    ...(epss !== undefined ? { epss } : {}),
    kev,
  };
}

export function priorityFor(score: number): Priority {
  if (score >= ACT_AT) return 'act';
  if (score >= ATTEND_AT) return 'attend';
  return 'track';
}

/** Descending by risk, so the most urgent findings sort first. */
export function byRiskDesc(a: RiskAssessment, b: RiskAssessment): number {
  return b.score - a.score;
}

/**
 * A CVSS vector is a measured impact and a severity label is a guess at one, so
 * the vector wins wherever a scanner supplied it.
 */
function impactOf(input: RiskInput): number {
  const score = input.cvss?.score;
  if (score !== undefined && Number.isFinite(score)) return clamp(score / 10, 0, 1);
  return SEVERITY_IMPACT[input.severity];
}

/** Maps an EPSS probability onto 0.5 to 1.0 across five orders of magnitude. */
function epssModifier(epss: number): number {
  const bounded = clamp(epss, EPSS_FLOOR, 1);
  const decades = (Math.log10(bounded) + EPSS_DECADES) / EPSS_DECADES;
  return 0.5 + 0.5 * clamp(decades, 0, 1);
}

function explain(input: RiskInput, evidence: { kev: boolean; epss: number | undefined }): string {
  const basis =
    input.cvss?.score !== undefined
      ? `CVSS ${input.cvss.score.toFixed(1)}`
      : `${input.severity} severity`;

  if (evidence.kev) {
    const added = input.advisory?.kevAddedAt;
    const ransomware = input.advisory?.kevRansomware === true;
    return (
      `Actively exploited${added !== undefined ? `, listed by CISA on ${added}` : ' and listed by CISA'}` +
      `${ransomware ? ', including in ransomware campaigns' : ''}. Impact ${basis}.`
    );
  }

  if (evidence.epss !== undefined) {
    const chance = formatProbability(evidence.epss);
    const percentile = input.advisory?.epssPercentile;
    const context =
      percentile !== undefined
        ? ` — higher than ${Math.round(percentile * 100)}% of scored CVEs`
        : '';
    return `No confirmed exploitation. ${chance} predicted chance of exploitation in the next 30 days${context}. Impact ${basis}.`;
  }

  return `No exploitation data available, ranked on ${basis} alone.`;
}

function formatProbability(epss: number): string {
  const percent = epss * 100;
  if (percent >= 10) return `${percent.toFixed(0)}%`;
  if (percent >= 1) return `${percent.toFixed(1)}%`;
  return `${percent.toFixed(2)}%`;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
