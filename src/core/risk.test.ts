/**
 * The risk model is the one place where a quiet arithmetic change would go
 * unnoticed for a long time. Nothing crashes when a score drifts by ten points;
 * the list just silently reorders and everyone works on the wrong thing first.
 * So the properties that carry meaning are pinned here rather than the
 * implementation details around them.
 */

import { describe, expect, it } from 'vitest';

import {
  PRIORITIES,
  priorityFor,
  priorityRank,
  scoreFinding,
  type AdvisoryRisk,
  type RiskInput,
} from './risk.js';

const kev = (extra: Partial<AdvisoryRisk> = {}): AdvisoryRisk => ({
  kev: true,
  kevRansomware: false,
  ...extra,
});

const predicted = (epss: number, percentile?: number): AdvisoryRisk => ({
  kev: false,
  kevRansomware: false,
  epss,
  ...(percentile === undefined ? {} : { epssPercentile: percentile }),
});

describe('scoreFinding', () => {
  /**
   * The worked examples from the Phase 3 plan, which it calls the acceptance
   * criteria. Two of the numbers there — 49 and 41 — were arithmetic slips in
   * the prose: they were computed with the modifier floor rather than the
   * modifier the stated formula produces for those EPSS values. The tiers the
   * plan claims are the part that carries meaning, and those hold exactly.
   */
  const acceptance: { name: string; input: RiskInput; score: number; priority: string }[] = [
    {
      name: 'KEV with ransomware use and a critical CVSS',
      input: { severity: 'critical', cvss: { score: 9.8 }, advisory: kev({ kevRansomware: true }) },
      score: 98,
      priority: 'act',
    },
    {
      name: 'KEV with a merely medium CVSS still reaches the floor',
      input: { severity: 'medium', cvss: { score: 5 }, advisory: kev() },
      score: 85,
      priority: 'act',
    },
    {
      name: 'critical CVSS that nobody is predicted to exploit',
      input: { severity: 'critical', cvss: { score: 9.8 }, advisory: predicted(0.0001) },
      score: 59,
      priority: 'attend',
    },
    {
      name: 'high CVSS with a low prediction',
      input: { severity: 'high', cvss: { score: 7.5 }, advisory: predicted(0.001) },
      score: 53,
      priority: 'attend',
    },
    {
      name: 'critical secret, which can never have a CVE',
      input: { severity: 'critical' },
      score: 77,
      priority: 'act',
    },
    {
      name: 'medium infrastructure finding, likewise',
      input: { severity: 'medium' },
      score: 38,
      priority: 'track',
    },
  ];

  it.each(acceptance)('$name scores $score and lands in $priority', ({ input, score, priority }) => {
    const risk = scoreFinding(input);
    expect(risk.score).toBe(score);
    expect(risk.priority).toBe(priority);
  });

  /**
   * The entire reason the phase exists. If this ever fails, the product has
   * quietly gone back to ranking by severity.
   */
  it('ranks a confirmed-exploited medium above an unexploited critical', () => {
    const exploitedMedium = scoreFinding({
      severity: 'medium',
      cvss: { score: 5 },
      advisory: kev(),
    });
    const quietCritical = scoreFinding({
      severity: 'critical',
      cvss: { score: 9.8 },
      advisory: predicted(0.0001),
    });

    expect(exploitedMedium.score).toBeGreaterThan(quietCritical.score);
    expect(exploitedMedium.priority).toBe('act');
    expect(quietCritical.priority).toBe('attend');
  });

  describe('confirmed exploitation', () => {
    it('floors a KEV finding at 85 however low its impact', () => {
      expect(scoreFinding({ severity: 'info', cvss: { score: 0.1 }, advisory: kev() }).score).toBe(
        85,
      );
      expect(scoreFinding({ severity: 'unknown', advisory: kev() }).score).toBe(85);
    });

    it('floors ransomware use higher still', () => {
      const risk = scoreFinding({
        severity: 'low',
        cvss: { score: 2 },
        advisory: kev({ kevRansomware: true }),
      });
      expect(risk.score).toBe(95);
    });

    // A floor that also acted as a ceiling would flatten every serious KEV
    // finding onto the same number and destroy the ordering among them.
    it('does not cap a KEV finding whose impact scores above the floor', () => {
      const risk = scoreFinding({ severity: 'critical', cvss: { score: 10 }, advisory: kev() });
      expect(risk.score).toBe(100);
    });

    it('ignores EPSS once exploitation is confirmed', () => {
      const withLowPrediction = scoreFinding({
        severity: 'high',
        cvss: { score: 8 },
        advisory: { ...kev(), epss: 0.00001 },
      });
      const withoutPrediction = scoreFinding({
        severity: 'high',
        cvss: { score: 8 },
        advisory: kev(),
      });
      expect(withLowPrediction.score).toBe(withoutPrediction.score);
    });
  });

  describe('EPSS scaling', () => {
    it('increases monotonically with the probability', () => {
      const scores = [0.00001, 0.0001, 0.001, 0.01, 0.1, 1].map(
        (epss) => scoreFinding({ severity: 'high', cvss: { score: 8 }, advisory: predicted(epss) }).score,
      );

      for (let i = 1; i < scores.length; i += 1) {
        expect(scores[i]).toBeGreaterThan(scores[i - 1] as number);
      }
    });

    /**
     * The point of the log scale. On a linear term the gap between a 0.01%
     * chance and a 10% chance would be invisible next to the CVSS term, and
     * folding EPSS in at all would have been pointless.
     */
    it('separates the bottom and top of the range by a wide margin', () => {
      const negligible = scoreFinding({
        severity: 'critical',
        cvss: { score: 9.8 },
        advisory: predicted(0.00001),
      }).score;
      const likely = scoreFinding({
        severity: 'critical',
        cvss: { score: 9.8 },
        advisory: predicted(0.9),
      }).score;

      expect(likely - negligible).toBeGreaterThan(40);
    });

    it('clamps probabilities below the floor rather than running off to negative infinity', () => {
      const atFloor = scoreFinding({ severity: 'high', advisory: predicted(0.00001) }).score;
      const belowFloor = scoreFinding({ severity: 'high', advisory: predicted(0) }).score;
      expect(belowFloor).toBe(atFloor);
      expect(belowFloor).toBeGreaterThan(0);
    });
  });

  describe('findings with no advisory', () => {
    /**
     * Secrets, SAST and IaC findings have no CVE and never will. Scoring them
     * on absent exploit data would bury a leaked production credential under a
     * dependency nobody can reach.
     */
    it('discounts mildly rather than pushing them to the bottom', () => {
      expect(scoreFinding({ severity: 'critical' }).priority).toBe('act');
      expect(scoreFinding({ severity: 'high' }).priority).toBe('attend');
    });

    it('outranks an equally severe finding whose EPSS is negligible', () => {
      const noAdvisory = scoreFinding({ severity: 'critical', cvss: { score: 9 } });
      const negligibleEpss = scoreFinding({
        severity: 'critical',
        cvss: { score: 9 },
        advisory: predicted(0.00001),
      });
      expect(noAdvisory.score).toBeGreaterThan(negligibleEpss.score);
    });

    it('reports no EPSS on the assessment', () => {
      const risk = scoreFinding({ severity: 'high' });
      expect(risk.epss).toBeUndefined();
      expect(risk.kev).toBe(false);
    });
  });

  describe('impact', () => {
    it('prefers a measured CVSS vector over a severity label', () => {
      const labelled = scoreFinding({ severity: 'low' });
      const measured = scoreFinding({ severity: 'low', cvss: { score: 9.8 } });
      expect(measured.score).toBeGreaterThan(labelled.score);
    });

    it('falls back to severity when no CVSS was reported', () => {
      const ordered = (['critical', 'high', 'medium', 'low', 'info'] as const).map(
        (severity) => scoreFinding({ severity }).score,
      );
      for (let i = 1; i < ordered.length; i += 1) {
        expect(ordered[i]).toBeLessThan(ordered[i - 1] as number);
      }
    });

    // Scanners do emit nonsense occasionally, and a NaN reaching the database
    // would poison the ordering for the whole project.
    it('ignores a non-finite CVSS score', () => {
      const risk = scoreFinding({ severity: 'medium', cvss: { score: Number.NaN } });
      expect(risk.score).toBe(scoreFinding({ severity: 'medium' }).score);
    });

    it('keeps the score within 0 and 100', () => {
      for (const input of [
        { severity: 'critical' as const, cvss: { score: 10 }, advisory: kev({ kevRansomware: true }) },
        { severity: 'info' as const, cvss: { score: 0 } },
      ]) {
        const { score } = scoreFinding(input);
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
      }
    });
  });

  describe('rationale', () => {
    it('names CISA and the listing date when exploitation is confirmed', () => {
      const risk = scoreFinding({
        severity: 'critical',
        cvss: { score: 9.8 },
        advisory: kev({ kevAddedAt: '2021-12-10', kevRansomware: true }),
      });
      expect(risk.rationale).toContain('CISA');
      expect(risk.rationale).toContain('2021-12-10');
      expect(risk.rationale).toContain('ransomware');
    });

    it('gives the percentile context when there is only a prediction', () => {
      const risk = scoreFinding({
        severity: 'high',
        cvss: { score: 7.5 },
        advisory: predicted(0.05, 0.92),
      });
      expect(risk.rationale).toContain('5.0%');
      expect(risk.rationale).toContain('92%');
    });

    it('says so plainly when there is nothing to go on', () => {
      expect(scoreFinding({ severity: 'medium' }).rationale).toMatch(/no exploitation data/i);
    });
  });

  it('carries the evidence through for the denormalized columns', () => {
    const risk = scoreFinding({
      severity: 'high',
      advisory: { kev: true, kevRansomware: false, epss: 0.42 },
    });
    expect(risk.epss).toBe(0.42);
    expect(risk.kev).toBe(true);
  });
});

describe('priorityFor', () => {
  it.each([
    [100, 'act'],
    [70, 'act'],
    [69, 'attend'],
    [40, 'attend'],
    [39, 'track'],
    [0, 'track'],
  ])('maps %i to %s', (score, priority) => {
    expect(priorityFor(score)).toBe(priority);
  });
});

describe('priorityRank', () => {
  it('orders the tiers by urgency', () => {
    expect(priorityRank('act')).toBeGreaterThan(priorityRank('attend'));
    expect(priorityRank('attend')).toBeGreaterThan(priorityRank('track'));
  });

  it('ranks every tier in the vocabulary', () => {
    for (const priority of PRIORITIES) expect(priorityRank(priority)).toBeGreaterThan(0);
  });
});
