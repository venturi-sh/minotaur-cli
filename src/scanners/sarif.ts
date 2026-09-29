/**
 * SARIF 2.1.0, the format nearly every scanner can write.
 *
 * It is the fallback for tools without a native adapter, so it has to work out
 * from conventions what kind of finding each result is: advisory-style rule
 * ids mean a dependency, secret and misconfiguration tags mean what they say,
 * and everything else is treated as a code finding. Dependency details only
 * survive as prose in the message, so they are read back out of it where the
 * common tools' wording allows.
 */

import { assignOrdinals, normalizeSeverity, type Finding, type FindingKind, type RuleMeta, type Severity } from '../core/index.js';
import { fingerprintIac, fingerprintSast, fingerprintSca, fingerprintSecret } from '../core/fingerprint.js';
import { z } from 'zod';

import { WORKSPACE_MOUNT, type ScanContext } from './adapter.js';
import { ruleMeta } from './semgrep.js';

const textSchema = z.object({ text: z.string().optional() }).loose();

const ruleSchema = z
  .object({
    id: z.string(),
    name: z.string().optional(),
    shortDescription: textSchema.optional(),
    fullDescription: textSchema.optional(),
    help: textSchema.optional(),
    helpUri: z.string().optional(),
    defaultConfiguration: z.object({ level: z.string().optional() }).loose().optional(),
    properties: z.record(z.string(), z.unknown()).optional(),
  })
  .loose();

const regionSchema = z
  .object({
    startLine: z.number().int().positive().optional(),
    endLine: z.number().int().positive().optional(),
    snippet: textSchema.optional(),
  })
  .loose();

const resultSchema = z
  .object({
    ruleId: z.string().optional(),
    ruleIndex: z.number().int().nonnegative().optional(),
    rule: z.object({ id: z.string().optional(), index: z.number().optional() }).loose().optional(),
    level: z.string().optional(),
    message: textSchema.optional(),
    locations: z
      .array(
        z
          .object({
            physicalLocation: z
              .object({
                artifactLocation: z.object({ uri: z.string().optional() }).loose().optional(),
                region: regionSchema.optional(),
              })
              .loose()
              .optional(),
          })
          .loose(),
      )
      .optional(),
    properties: z.record(z.string(), z.unknown()).optional(),
  })
  .loose();

const runSchema = z
  .object({
    tool: z
      .object({
        driver: z
          .object({
            name: z.string(),
            version: z.string().optional(),
            semanticVersion: z.string().optional(),
            rules: z.array(ruleSchema).optional(),
          })
          .loose(),
      })
      .loose(),
    results: z.array(resultSchema).nullish(),
  })
  .loose();

export const sarifSchema = z.object({ version: z.string().optional(), runs: z.array(runSchema) }).loose();

type Rule = z.infer<typeof ruleSchema>;
type Result = z.infer<typeof resultSchema>;

export function isSarif(value: unknown): boolean {
  if (typeof value !== 'object' || value === null || !Array.isArray((value as { runs?: unknown }).runs)) return false;
  const { version, $schema } = value as { version?: unknown; $schema?: unknown };
  return version === '2.1.0' || (typeof $schema === 'string' && $schema.toLowerCase().includes('sarif'));
}

const SECRET_TOOLS = new Set(['gitleaks', 'trufflehog', 'detect-secrets', 'ggshield', 'semgrep secrets']);
const IAC_TOOLS = new Set(['checkov', 'tfsec', 'kics', 'terrascan', 'hadolint', 'kube-linter', 'kubesec']);
const ADVISORY_ID = /^(CVE|GHSA|PYSEC|RUSTSEC|GO|OSV|SNYK|GMS|MAL|DSA|RHSA|ALAS|USN)-/i;
const CWE = /cwe[-/](\d+)/i;

export function parseSarif(text: string, context: Pick<ScanContext, 'projectId' | 'readSnippet'>): Finding[] {
  const parsed = sarifSchema.safeParse(JSON.parse(text));
  if (!parsed.success) throw new Error(`not a SARIF report: ${parsed.error.issues[0]?.message ?? 'invalid'}`);

  const findings: Finding[] = [];
  for (const run of parsed.data.runs) {
    const driver = run.tool.driver;
    const tool = { name: toolName(driver.name), version: driver.semanticVersion ?? driver.version ?? 'unknown' };
    const rules = driver.rules ?? [];
    const byId = new Map(rules.map((rule) => [rule.id, rule]));
    const results = (run.results ?? []).map((result) => ({ result, rule: ruleFor(result, rules, byId) }));
    const ordinals = assignOrdinals(results, ({ result, rule }) => `${ruleIdOf(result, rule)}\u0000${pathOf(result) ?? ''}`);

    for (const entry of results) {
      findings.push(toFinding(entry.result, entry.rule, tool, ordinals.get(entry) ?? 0, context));
    }
  }
  return findings;
}

function toFinding(
  result: Result,
  rule: Rule | undefined,
  tool: { name: string; version: string },
  ordinal: number,
  context: Pick<ScanContext, 'projectId' | 'readSnippet'>,
): Finding {
  const ruleId = ruleIdOf(result, rule);
  const tags = tagsOf(rule, result);
  const kind = kindOf(tool.name, ruleId, tags);
  const region = result.locations?.[0]?.physicalLocation?.region;
  const path = pathOf(result);
  const startLine = region?.startLine;
  const endLine = region?.endLine ?? startLine;
  const message = result.message?.text ?? rule?.fullDescription?.text ?? rule?.shortDescription?.text;
  const title = titleOf(rule, ruleId);
  // A secret scanner's snippet is the credential itself. Otherwise the file
  // wins over the report, as in the native adapters, so a finding keeps its
  // identity whichever format it arrived in.
  const snippet =
    kind === 'secret'
      ? undefined
      : ((path && startLine ? context.readSnippet?.(path, startLine, endLine ?? startLine) : undefined) ??
        usable(region?.snippet?.text));
  const location = path
    ? {
        path,
        ...(startLine ? { startLine } : {}),
        ...(endLine ? { endLine } : {}),
        ...(snippet ? { snippet } : {}),
      }
    : undefined;
  const pkg = kind === 'sca' ? packageFrom(message ?? '') : undefined;
  const cwes = [...new Set(tags.flatMap((tag) => (CWE.test(tag) ? [`CWE-${Number(CWE.exec(tag)![1])}`] : [])))];

  const fingerprint =
    kind === 'sca'
      ? fingerprintSca({ projectId: context.projectId, vulnerabilityId: ruleId, packageName: pkg?.name ?? path })
      : kind === 'secret'
        ? fingerprintSecret({ projectId: context.projectId, ruleId, path: path ?? '', match: `${ruleId}:${startLine ?? 0}` })
        : kind === 'iac'
          ? fingerprintIac({ projectId: context.projectId, ruleId, path: path ?? '', ordinal })
          : fingerprintSast({
              projectId: context.projectId,
              ruleId,
              path: path ?? '',
              ...(snippet ? { snippet } : {}),
              ...(startLine ? { startLine } : {}),
              ordinal,
            });

  return {
    fingerprint,
    kind,
    severity: severityOf(result, rule),
    title: kind === 'sca' && pkg ? `${ruleId} in ${pkg.name}` : title,
    ...(message ? { description: message } : {}),
    ruleId,
    ...(kind === 'sast' ? { rule: sarifRuleMeta(ruleId, tags, cwes.length > 0) } : {}),
    vulnerabilityIds: kind === 'sca' && ADVISORY_ID.test(ruleId) ? [ruleId] : cwes,
    ...(location ? { location } : {}),
    ...(pkg ? { package: pkg } : {}),
    references: rule?.helpUri ? [rule.helpUri] : [],
    tool,
    tools: [tool],
    ...(kind === 'secret' ? {} : { raw: result }),
  };
}

/** SARIF has no rule category, but a `security` tag or a CWE says as much. */
function sarifRuleMeta(ruleId: string, tags: readonly string[], hasCwe: boolean): RuleMeta {
  const fromId = ruleMeta(ruleId, {});
  const security = hasCwe || tags.some((tag) => tag.toLowerCase() === 'security');
  return security ? { ...fromId, category: 'security' } : fromId;
}

function ruleFor(result: Result, rules: readonly Rule[], byId: Map<string, Rule>): Rule | undefined {
  const index = result.ruleIndex ?? result.rule?.index;
  if (index !== undefined && rules[index]) return rules[index];
  const id = result.ruleId ?? result.rule?.id;
  return id ? byId.get(id) : undefined;
}

/**
 * Semgrep names rules after the path they were loaded from, so the same rule
 * is `cache.semgrep-rules.python...` in one run and `python...` in another.
 * The Semgrep adapter strips that prefix, and so does this, so both formats
 * give a finding the same identity.
 */
function ruleIdOf(result: Result, rule: Rule | undefined): string {
  const id = result.ruleId ?? result.rule?.id ?? rule?.id ?? 'unknown';
  const marker = 'semgrep-rules.';
  const index = id.indexOf(marker);
  return index === -1 ? id : id.slice(index + marker.length);
}

/** "Semgrep OSS" and "Semgrep Pro" are both Semgrep, as the native adapter calls it. */
function toolName(name: string): string {
  return name
    .toLowerCase()
    .replace(/\s+(oss|pro|ce|community edition)$/, '')
    .trim();
}

/** Some tools put a generic label in the short description; the rule's own name says more. */
function titleOf(rule: Rule | undefined, ruleId: string): string {
  const short = rule?.shortDescription?.text?.trim();
  if (short && !/^semgrep finding:/i.test(short)) return short;
  return ruleId.split('.').pop() ?? ruleId;
}

function pathOf(result: Result): string | undefined {
  const uri = result.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
  return uri ? normalizeReportedPath(uri) : undefined;
}

/** Strips the forms a scanner may wrap a repository path in: a file URI, the sandbox mount, `./`. */
export function normalizeReportedPath(path: string): string {
  let value = path;
  if (value.startsWith('file://')) value = value.slice('file://'.length);
  if (value.includes('%')) {
    try {
      value = decodeURIComponent(value);
    } catch {
      // Left as reported.
    }
  }
  if (value.startsWith(`${WORKSPACE_MOUNT}/`)) value = value.slice(WORKSPACE_MOUNT.length + 1);
  while (value.startsWith('./')) value = value.slice(2);
  return value;
}

function tagsOf(rule: Rule | undefined, result: Result): string[] {
  const raw = [rule?.properties?.['tags'], result.properties?.['tags']].flatMap((tags) =>
    Array.isArray(tags) ? tags.filter((tag): tag is string => typeof tag === 'string') : [],
  );
  return raw.map((tag) => tag.toLowerCase());
}

function kindOf(toolName: string, ruleId: string, tags: readonly string[]): FindingKind {
  if (SECRET_TOOLS.has(toolName) || tags.includes('secret') || tags.includes('secrets')) return 'secret';
  if (ADVISORY_ID.test(ruleId) || tags.includes('vulnerability') || tags.includes('dependency')) return 'sca';
  if (IAC_TOOLS.has(toolName) || tags.includes('misconfiguration') || /^(CKV|AVD|DS|KSV)[_-]/i.test(ruleId)) return 'iac';
  return 'sast';
}

/** GitHub's convention: a CVSS-style score in `security-severity`, which beats the coarse SARIF level. */
function severityOf(result: Result, rule: Rule | undefined): Severity {
  const raw = result.properties?.['security-severity'] ?? rule?.properties?.['security-severity'];
  const score = typeof raw === 'number' ? raw : typeof raw === 'string' ? Number.parseFloat(raw) : Number.NaN;
  if (Number.isFinite(score)) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    if (score > 0) return 'low';
    return 'info';
  }
  return normalizeSeverity(result.level ?? rule?.defaultConfiguration?.level ?? 'warning');
}

/** Trivy writes "Package: x / Installed Version: y / Fixed Version: z"; Grype writes "package: x, version y". */
function packageFrom(message: string): Finding['package'] {
  const trivy = /Package:\s*(\S+)[\s\S]*?Installed Version:\s*(\S+)/i.exec(message);
  if (trivy) {
    const fixed = /Fixed Version:\s*([^\s,]+)/i.exec(message);
    return { name: trivy[1]!, version: trivy[2]!, ...(fixed?.[1] ? { fixedVersion: fixed[1] } : {}) };
  }
  const grype = /package:\s*([^\s,]+),\s*version\s+([^\s,]+)/i.exec(message);
  if (grype) return { name: grype[1]!, version: grype[2]! };
  return undefined;
}

function usable(snippet: string | undefined): string | undefined {
  const trimmed = snippet?.trim();
  if (!trimmed || trimmed === 'requires login') return undefined;
  return trimmed;
}
