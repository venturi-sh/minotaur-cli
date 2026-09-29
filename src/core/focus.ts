/**
 * Which findings deserve a look first, decided without a model.
 *
 * A code scanner's default rules mix security checks with style, correctness
 * and translation rules, and in a typical repository the second group is most
 * of the list. Their own metadata says which is which, so that noise can be set
 * aside for free before any time or spend goes on it. Every decision carries
 * its reasons, because a finding hidden for no stated reason is a finding
 * nobody trusts the tool with.
 *
 * Only code findings are ever called noise by the rules here. A dependency
 * with a known CVE, a secret, or a misconfiguration is at least worth a look;
 * a person can still set one aside explicitly with an override.
 *
 * Isomorphic, like the rest of core — no Node builtins.
 */

import { z } from 'zod';

import type { Finding } from './finding.js';
import { scoreFinding, type AdvisoryRisk } from './risk.js';

export const FOCUS_LEVELS = ['likely', 'maybe', 'noise'] as const;
export const focusSchema = z.enum(FOCUS_LEVELS);
export type Focus = z.infer<typeof focusSchema>;

const FOCUS_RANK: Record<Focus, number> = { likely: 3, maybe: 2, noise: 1 };

export function focusRank(focus: Focus): number {
  return FOCUS_RANK[focus];
}

/** Rule ids and paths, as globs, that a person has decided about. */
export const focusOverridesSchema = z.object({
  /** Always set aside as noise. */
  noise: z.object({ rules: z.array(z.string()).default([]), paths: z.array(z.string()).default([]) }).partial().default({}),
  /** Always rated likely, whatever the rules say. Wins over `noise`. */
  keep: z.object({ rules: z.array(z.string()).default([]), paths: z.array(z.string()).default([]) }).partial().default({}),
});
export type FocusOverrides = z.input<typeof focusOverridesSchema>;

export interface FocusAssessment {
  focus: Focus;
  reasons: string[];
  /** 0 to 100, for ordering within a level. See `scoreFinding`. */
  riskScore: number;
}

/**
 * Code that only runs while developing: tests, fixtures, examples, docs and
 * evaluation sets. A finding there is rarely reachable by an attacker.
 */
export const NON_PRODUCTION_PATHS: readonly string[] = [
  '**/*.test.*',
  '**/*.spec.*',
  '**/*_test.*',
  '**/test_*.py',
  '**/__tests__/**',
  '**/__mocks__/**',
  '**/test/**',
  '**/tests/**',
  '**/testdata/**',
  '**/e2e/**',
  '**/fixture.*',
  '**/fixtures.*',
  '**/fixtures/**',
  '**/example/**',
  '**/examples/**',
  '**/docs/**',
  '**/evals/**',
];

export type FocusSubject = Pick<Finding, 'kind' | 'severity' | 'ruleId' | 'rule' | 'location' | 'cvss'>;

export interface FocusOptions {
  /** The worst known exploitation evidence among the finding's advisories. */
  advisory?: AdvisoryRisk | undefined;
  overrides?: FocusOverrides | undefined;
}

export function focusOf(finding: FocusSubject, options: FocusOptions = {}): FocusAssessment {
  const risk = scoreFinding({ severity: finding.severity, cvss: finding.cvss, advisory: options.advisory });
  const assessed = (focus: Focus, reasons: string[]): FocusAssessment => ({ focus, reasons, riskScore: risk.score });
  const path = finding.location?.path;
  const overrides = focusOverridesSchema.parse(options.overrides ?? {});

  const kept = matchesAny(finding.ruleId, overrides.keep.rules) ?? matchesAny(path, overrides.keep.paths);
  if (kept) return assessed('likely', [`kept by the focus settings (${kept})`]);
  const dropped = matchesAny(finding.ruleId, overrides.noise.rules) ?? matchesAny(path, overrides.noise.paths);
  if (dropped) return assessed('noise', [`set aside by the focus settings (${dropped})`]);

  const nonProduction = path !== undefined && matchesAny(path, NON_PRODUCTION_PATHS) !== null;
  const where = nonProduction ? ['in test, example or docs code'] : [];

  switch (finding.kind) {
    case 'sca': {
      const reasons = risk.kev ? ['on the CISA list of exploited vulnerabilities'] : [];
      if (risk.epss !== undefined) {
        const percent = risk.epss * 100;
        reasons.push(`EPSS ${percent < 0.1 ? 'under 0.1' : percent.toFixed(1)}% chance of exploitation in 30 days`);
      }
      if (risk.kev || risk.priority === 'act') return assessed('likely', [...reasons, `risk score ${risk.score}`]);
      return assessed('maybe', [...reasons, `risk score ${risk.score}`]);
    }
    case 'secret':
      return nonProduction ? assessed('maybe', ['secret', ...where]) : assessed('likely', ['secret in code that ships']);
    case 'iac':
    case 'license': {
      const serious = finding.severity === 'critical' || finding.severity === 'high';
      return assessed(serious && !nonProduction ? 'likely' : 'maybe', [`${finding.severity} ${finding.kind} finding`, ...where]);
    }
    case 'sast': {
      const { focus, reasons } = codeFocus(finding);
      if (!nonProduction || focus === 'noise') return assessed(focus, reasons);
      return assessed(focus === 'likely' ? 'maybe' : 'noise', [...reasons, ...where]);
    }
  }
}

function codeFocus(finding: FocusSubject): { focus: Focus; reasons: string[] } {
  const rule = finding.rule;
  const category = rule?.category;
  if (!category) return { focus: 'maybe', reasons: ['the rule does not say whether it is a security rule'] };
  if (category !== 'security') return { focus: 'noise', reasons: [`${category} rule, not a security rule`] };
  const audit = rule.subcategory.includes('audit');
  const weak = rule.confidence === 'low' || rule.likelihood === 'low';
  if (audit && weak) return { focus: 'maybe', reasons: ['security audit rule with low confidence'] };
  if (audit) return { focus: 'maybe', reasons: ['security audit rule: flags code worth a look, not a known flaw'] };
  return { focus: 'likely', reasons: [`security rule${rule.confidence ? `, ${rule.confidence} confidence` : ''}`] };
}

/** The first pattern that matches, or null. */
function matchesAny(value: string | undefined, patterns: readonly string[] | undefined): string | null {
  if (value === undefined || !patterns) return null;
  return patterns.find((pattern) => globToRegExp(pattern).test(value)) ?? null;
}

const compiled = new Map<string, RegExp>();

/** `**` spans directories, `*` and `?` stay within one. Rule ids have no slashes, so `*` covers any part of one. */
export function globToRegExp(pattern: string): RegExp {
  const cached = compiled.get(pattern);
  if (cached) return cached;
  let source = '';
  for (let index = 0; index < pattern.length; index++) {
    const char = pattern[index]!;
    if (char === '*' && pattern[index + 1] === '*') {
      const slash = pattern[index + 2] === '/';
      source += slash ? '(?:.*/)?' : '.*';
      index += slash ? 2 : 1;
    } else if (char === '*') {
      source += '[^/]*';
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  const regex = new RegExp(`^${source}$`);
  compiled.set(pattern, regex);
  return regex;
}
