/**
 * Citations are checked, not trusted.
 *
 * A model will cite a line that says what it needs it to say. So every quote
 * is compared with the file it names, and a citation that does not match is
 * dropped. A false-positive verdict is the one that hides a finding, so it has
 * to stand on at least one citation that holds up; without one it becomes
 * `needs_review` rather than a dismissal nobody can verify.
 */

import type { Evidence, ExploitVerdict, TriageVerdict } from '../core/index.js';

export interface LineSource {
  lines(path: string, startLine: number, endLine: number): Promise<string[] | undefined>;
}

export interface Checked<V> {
  verdict: V;
  /** Citations removed because the file did not say what the quote claimed. */
  rejected: Evidence[];
  downgraded: boolean;
}

export type CheckedVerdict = Checked<TriageVerdict>;

/** Quotes may span lines and be reindented, so only the words have to match. */
function normalize(text: string): string {
  return text.replace(/^\s*\d+:\s?/gm, '').replace(/\s+/g, ' ').trim();
}

async function verifyCitations(
  evidence: readonly Evidence[],
  source: LineSource,
): Promise<{ kept: Evidence[]; rejected: Evidence[] }> {
  const kept: Evidence[] = [];
  const rejected: Evidence[] = [];

  for (const item of evidence) {
    const lines = await source.lines(item.path, item.startLine, item.endLine);
    const quote = normalize(item.quote);
    if (lines !== undefined && quote.length > 0 && normalize(lines.join('\n')).includes(quote)) {
      kept.push(item);
    } else {
      rejected.push(item);
    }
  }
  return { kept, rejected };
}

export async function checkEvidence(verdict: TriageVerdict, source: LineSource): Promise<CheckedVerdict> {
  const { kept, rejected } = await verifyCitations(verdict.evidence, source);
  const downgraded = verdict.verdict === 'false_positive' && kept.length === 0;

  return {
    verdict: {
      ...verdict,
      evidence: kept,
      ...(downgraded
        ? {
            verdict: 'needs_review' as const,
            confidence: Math.min(verdict.confidence, 0.5),
            rationale: `${verdict.rationale}\n\n(Downgraded from false_positive: no cited evidence could be verified against the code.)`,
          }
        : {}),
    },
    rejected,
    downgraded,
  };
}

/**
 * Stricter than triage: both definite answers need proof. "Exploitable" with
 * no path that checks out is as unsupported as "not exploitable" with no
 * blocking code, and someone is about to act on either.
 */
export async function checkExploitEvidence(verdict: ExploitVerdict, source: LineSource): Promise<Checked<ExploitVerdict>> {
  const { kept, rejected } = await verifyCitations(verdict.evidence, source);
  const downgraded = verdict.exploitability !== 'undetermined' && kept.length === 0;

  return {
    verdict: {
      ...verdict,
      evidence: kept,
      ...(downgraded
        ? {
            exploitability: 'undetermined' as const,
            confidence: Math.min(verdict.confidence, 0.5),
            rationale: `${verdict.rationale}\n\n(Downgraded from ${verdict.exploitability}: no cited evidence could be verified against the code.)`,
          }
        : {}),
    },
    rejected,
    downgraded,
  };
}
