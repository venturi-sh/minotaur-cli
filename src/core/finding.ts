/**
 * The canonical findings model.
 *
 * Every scanner adapter normalizes into these types, and the rest of the CLI
 * speaks only this vocabulary. It is the same model as the Minotaur platform's,
 * and like there it does not depend on Node builtins; fingerprinting lives in
 * `fingerprint.ts`.
 */

import { z } from 'zod';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const;
export const severitySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof severitySchema>;

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity];
}

/** Descending by severity, so the worst findings sort first. */
export function bySeverityDesc(a: Severity, b: Severity): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a];
}

export function normalizeSeverity(raw: string | null | undefined): Severity {
  if (!raw) return 'unknown';
  const value = raw.trim().toLowerCase();
  switch (value) {
    case 'critical':
      return 'critical';
    case 'high':
    case 'error':
      return 'high';
    case 'medium':
    case 'moderate':
    case 'warning':
      return 'medium';
    case 'low':
      return 'low';
    case 'info':
    case 'informational':
    case 'note':
    case 'none':
      return 'info';
    default:
      return 'unknown';
  }
}

export const findingKindSchema = z.enum(['sca', 'sast', 'secret', 'iac', 'license']);
export type FindingKind = z.infer<typeof findingKindSchema>;

export const codeLocationSchema = z.object({
  path: z.string(),
  startLine: z.number().int().positive().optional(),
  endLine: z.number().int().positive().optional(),
  snippet: z.string().optional(),
});

export const packageRefSchema = z.object({
  name: z.string(),
  version: z.string().optional(),
  ecosystem: z.string().optional(),
  /** Package URL, the cross-ecosystem identifier that makes cross-tool correlation possible. */
  purl: z.string().optional(),
  fixedVersion: z.string().optional(),
});

export const cvssSchema = z.object({
  score: z.number().min(0).max(10),
  vector: z.string().optional(),
  version: z.string().optional(),
  source: z.string().optional(),
});

/**
 * What a rule says about itself, as Semgrep-style rules do in their metadata.
 * Lower-cased. Tells a security rule from a style one without a model.
 */
export const ruleMetaSchema = z.object({
  /** Such as `security`, `correctness`, `best-practice`, `portability`. */
  category: z.string().optional(),
  /** Such as `vuln` or `audit`. An audit rule flags code worth a look, not a known flaw. */
  subcategory: z.array(z.string()).default([]),
  confidence: z.string().optional(),
  likelihood: z.string().optional(),
  impact: z.string().optional(),
});

export const toolRefSchema = z.object({
  name: z.string(),
  version: z.string(),
});

export const findingSchema = z.object({
  /** Stable across scans. See `fingerprint.ts`. */
  fingerprint: z.string().length(64),
  kind: findingKindSchema,
  severity: severitySchema,
  title: z.string(),
  description: z.string().optional(),
  ruleId: z.string().optional(),
  rule: ruleMetaSchema.optional(),
  /** CVE, GHSA, or other advisory identifiers. Plural because they alias each other. */
  vulnerabilityIds: z.array(z.string()).default([]),
  cvss: cvssSchema.optional(),
  location: codeLocationSchema.optional(),
  package: packageRefSchema.optional(),
  references: z.array(z.string()).default([]),
  tool: toolRefSchema,
  /**
   * Every scanner that reported this finding. Overlapping coverage is the point
   * of running a fleet, and agreement between independent tools is a signal the
   * triage layer should get to see.
   */
  tools: z.array(toolRefSchema).default([]),
  /** Original scanner payload, retained so we can re-normalize without re-scanning. */
  raw: z.unknown().optional(),
});

export type Finding = z.infer<typeof findingSchema>;
export type CodeLocation = z.infer<typeof codeLocationSchema>;
export type PackageRef = z.infer<typeof packageRefSchema>;
export type Cvss = z.infer<typeof cvssSchema>;
export type ToolRef = z.infer<typeof toolRefSchema>;
export type RuleMeta = z.infer<typeof ruleMetaSchema>;

/**
 * Strips the version from a package URL so that a finding keeps its identity
 * when the package is bumped to another still-vulnerable version.
 *
 * Scoped npm packages make this fiddly: in `pkg:npm/@scope/name` the only `@`
 * belongs to the scope, not a version, so we only treat a trailing `@` as a
 * version separator when nothing after it looks like a path segment.
 */
export function purlWithoutVersion(purl: string): string {
  const withoutSubpath = purl.split('#')[0] ?? purl;
  const base = withoutSubpath.split('?')[0] ?? withoutSubpath;
  const at = base.lastIndexOf('@');
  if (at <= 0) return base;
  const candidate = base.slice(at + 1);
  if (candidate.includes('/')) return base;
  return base.slice(0, at);
}

/** Collapses whitespace so reindentation does not change a finding's identity. */
export function normalizeSnippet(snippet: string): string {
  return snippet.replace(/\s+/g, ' ').trim();
}

/**
 * Assigns a stable ordinal to entries that would otherwise share an identity,
 * so that N identical matches in one file produce N distinct findings rather
 * than collapsing into one.
 */
export function assignOrdinals<T>(items: readonly T[], key: (item: T) => string): Map<T, number> {
  const seen = new Map<string, number>();
  const ordinals = new Map<T, number>();
  for (const item of items) {
    const k = key(item);
    const next = seen.get(k) ?? 0;
    ordinals.set(item, next);
    seen.set(k, next + 1);
  }
  return ordinals;
}

/**
 * Merges findings that share a fingerprint, which happens when several scanners
 * report the same vulnerability. Overlapping coverage is deliberate, so this is
 * a normal path rather than an error case.
 */
export function dedupeFindings(findings: readonly Finding[]): Finding[] {
  const merged = new Map<string, Finding>();
  for (const finding of findings) {
    const existing = merged.get(finding.fingerprint);
    if (!existing) {
      merged.set(finding.fingerprint, { ...finding, tools: toolList(finding) });
      continue;
    }
    merged.set(finding.fingerprint, {
      ...existing,
      // Scanners disagree about severity constantly. Taking the highest is the
      // safe direction to be wrong in, and the disagreement stays visible
      // because every contributing tool is recorded.
      severity:
        bySeverityDesc(finding.severity, existing.severity) < 0
          ? finding.severity
          : existing.severity,
      vulnerabilityIds: [...new Set([...existing.vulnerabilityIds, ...finding.vulnerabilityIds])],
      references: [...new Set([...existing.references, ...finding.references])],
      tools: mergeTools(existing.tools, toolList(finding)),
      cvss: existing.cvss ?? finding.cvss,
      description: existing.description ?? finding.description,
      location: existing.location ?? finding.location,
      package: mergePackage(existing.package, finding.package),
    });
  }
  return [...merged.values()];
}

function toolList(finding: Finding): ToolRef[] {
  return finding.tools.length > 0 ? finding.tools : [finding.tool];
}

function mergeTools(a: readonly ToolRef[], b: readonly ToolRef[]): ToolRef[] {
  const byKey = new Map<string, ToolRef>();
  for (const tool of [...a, ...b]) byKey.set(`${tool.name}@${tool.version}`, tool);
  return [...byKey.values()].sort((x, y) => x.name.localeCompare(y.name));
}

/** Prefers the more complete record: a fixed version from one tool is worth keeping. */
function mergePackage(a: PackageRef | undefined, b: PackageRef | undefined): PackageRef | undefined {
  if (!a) return b;
  if (!b) return a;
  return {
    ...a,
    purl: a.purl ?? b.purl,
    ecosystem: a.ecosystem ?? b.ecosystem,
    version: a.version ?? b.version,
    fixedVersion: a.fixedVersion ?? b.fixedVersion,
  };
}
