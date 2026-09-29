/**
 * Trivy adapter.
 *
 * Uses Trivy's native JSON rather than SARIF. SARIF is the better lingua franca
 * for pure code scanners, but it flattens dependency findings into prose: the
 * package URL, the fixed version and the CVSS vectors all end up as text inside
 * a message string. Since package URLs are what make cross-tool correlation
 * possible, losing them is not an option.
 */

import { z } from 'zod';
import { assignOrdinals, normalizeSeverity, type Finding } from '../core/index.js';
import { fingerprintIac, fingerprintSca, fingerprintSecret } from '../core/fingerprint.js';
import {
  CACHE_MOUNT,
  WORKSPACE_MOUNT,
  standardMounts,
  type DatabaseSyncOptions,
  type ScanContext,
  type ScannerAdapter,
} from './adapter.js';
import type { DetectedTarget } from './detect.js';
import type { SandboxSpec } from './runtime.js';

export const TRIVY_VERSION = '0.73.0';
export const TRIVY_IMAGE =
  'aquasec/trivy@sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c';

const TOOL = { name: 'trivy', version: TRIVY_VERSION } as const;

const WORKSPACE = WORKSPACE_MOUNT;
/** The cache volume is shared with the rest of the fleet, so Trivy gets a subdirectory. */
const CACHE = `${CACHE_MOUNT}/trivy`;

export interface TrivyScanOptions {
  /** Host path to the checked-out source. Mounted read-only. */
  workspace: string;
  /** Docker volume holding the pre-warmed vulnerability database. */
  cacheVolume: string;
  /** Defaults to true. Trivy opens a pre-warmed database read-only quite happily. */
  cacheReadOnly?: boolean;
  timeoutMs?: number;
}

export function trivyFilesystemScan(options: TrivyScanOptions): SandboxSpec {
  return {
    image: TRIVY_IMAGE,
    // The database is pre-warmed into the cache volume by `trivyDatabaseSync`,
    // which is what lets the scan itself run with no network at all.
    network: 'none',
    args: [
      '--cache-dir',
      CACHE,
      'fs',
      '--format',
      'json',
      '--scanners',
      'vuln,misconfig,secret',
      '--skip-db-update',
      '--skip-java-db-update',
      '--offline-scan',
      '--quiet',
      WORKSPACE,
    ],
    mounts: [
      { type: 'bind', source: options.workspace, target: WORKSPACE, readOnly: true },
      {
        type: 'volume',
        source: options.cacheVolume,
        target: CACHE,
        readOnly: options.cacheReadOnly ?? true,
      },
    ],
    // The read-only rootfs leaves no writable home directory, and Trivy wants one.
    env: { HOME: '/tmp', TMPDIR: '/tmp' },
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
  };
}

/**
 * The only step permitted to touch the network. Run on a schedule, never as
 * part of a scan.
 */
export function trivyDatabaseSync(cacheVolume: string): SandboxSpec[] {
  const base = {
    image: TRIVY_IMAGE,
    network: 'bridge' as const,
    mounts: [{ type: 'volume' as const, source: cacheVolume, target: CACHE_MOUNT, readOnly: false }],
    env: { HOME: '/tmp', TMPDIR: '/tmp' },
    timeoutMs: 10 * 60 * 1000,
  };

  return [
    { ...base, args: ['--cache-dir', CACHE, 'image', '--download-db-only'] },
    // The Java index is a separate download and is not fetched by the call
    // above, so a Maven project would otherwise fail its first offline scan.
    { ...base, args: ['--cache-dir', CACHE, 'image', '--download-java-db-only'] },
  ];
}

export const trivyAdapter: ScannerAdapter = {
  name: TOOL.name,
  version: TOOL.version,

  // Trivy covers dependencies, infrastructure and secrets, so it earns its
  // place against almost any target.
  appliesTo: (target: DetectedTarget) =>
    target.ecosystems.length > 0 || target.hasIac || target.hasContainerfile || target.fileCount > 0,

  spec: (context: ScanContext): SandboxSpec => ({
    ...trivyFilesystemScan({ workspace: context.workspace, cacheVolume: context.cacheVolume }),
    mounts: standardMounts(context),
  }),

  databaseSync: ({ cacheVolume }: DatabaseSyncOptions): SandboxSpec[] =>
    trivyDatabaseSync(cacheVolume),

  cachePaths: ['trivy/db'],

  native: {
    binary: 'trivy',
    args: (root, extra) => ['fs', '--format', 'json', '--scanners', 'vuln,misconfig,secret', '--quiet', ...extra, root],
  },

  parse: (stdout: string, context: ScanContext): Finding[] =>
    parseTrivyReport(stdout, { projectId: context.projectId }),
};

// ---------------------------------------------------------------------------
// Output schemas
// ---------------------------------------------------------------------------

// Deliberately lenient: scanner output shapes drift between releases, and a
// new field upstream should never fail a scan. `.loose()` keeps unrecognized
// keys so they survive into the stored raw payload.

const cvssEntrySchema = z
  .object({
    V2Score: z.number().optional(),
    V3Score: z.number().optional(),
    V40Score: z.number().optional(),
    V2Vector: z.string().optional(),
    V3Vector: z.string().optional(),
    V40Vector: z.string().optional(),
  })
  .loose();

const vulnerabilitySchema = z
  .object({
    VulnerabilityID: z.string(),
    PkgName: z.string().optional(),
    PkgIdentifier: z.object({ PURL: z.string().optional() }).loose().optional(),
    InstalledVersion: z.string().optional(),
    FixedVersion: z.string().optional(),
    Severity: z.string().optional(),
    Title: z.string().optional(),
    Description: z.string().optional(),
    PrimaryURL: z.string().optional(),
    References: z.array(z.string()).optional(),
    CVSS: z.record(z.string(), cvssEntrySchema).optional(),
  })
  .loose();

const codeLinesSchema = z
  .object({
    Lines: z
      .array(z.object({ Number: z.number().optional(), Content: z.string().optional() }).loose())
      .optional(),
  })
  .loose();

const misconfigurationSchema = z
  .object({
    ID: z.string(),
    AVDID: z.string().optional(),
    Title: z.string().optional(),
    Description: z.string().optional(),
    Message: z.string().optional(),
    Resolution: z.string().optional(),
    Severity: z.string().optional(),
    PrimaryURL: z.string().optional(),
    References: z.array(z.string()).optional(),
    Status: z.string().optional(),
    CauseMetadata: z
      .object({
        Resource: z.string().optional(),
        StartLine: z.number().optional(),
        EndLine: z.number().optional(),
        Code: codeLinesSchema.optional(),
      })
      .loose()
      .optional(),
  })
  .loose();

const secretSchema = z
  .object({
    RuleID: z.string(),
    Category: z.string().optional(),
    Severity: z.string().optional(),
    Title: z.string().optional(),
    StartLine: z.number().optional(),
    EndLine: z.number().optional(),
    Match: z.string().optional(),
  })
  .loose();

const resultSchema = z
  .object({
    Target: z.string(),
    Class: z.string().optional(),
    Type: z.string().optional(),
    Vulnerabilities: z.array(vulnerabilitySchema).nullish(),
    Misconfigurations: z.array(misconfigurationSchema).nullish(),
    Secrets: z.array(secretSchema).nullish(),
  })
  .loose();

export const trivyReportSchema = z
  .object({
    SchemaVersion: z.number().optional(),
    ArtifactName: z.string().optional(),
    Results: z.array(resultSchema).nullish(),
  })
  .loose();

export type TrivyReport = z.infer<typeof trivyReportSchema>;

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

export function parseTrivyReport(stdout: string, context: { projectId: string }): Finding[] {
  const report = trivyReportSchema.parse(JSON.parse(stdout));
  const findings: Finding[] = [];

  for (const result of report.Results ?? []) {
    findings.push(...vulnerabilityFindings(result, context.projectId));
    findings.push(...misconfigurationFindings(result, context.projectId));
    findings.push(...secretFindings(result, context.projectId));
  }

  return findings;
}

function vulnerabilityFindings(
  result: z.infer<typeof resultSchema>,
  projectId: string,
): Finding[] {
  return (result.Vulnerabilities ?? []).map((vulnerability) => {
    const purl = vulnerability.PkgIdentifier?.PURL;
    const cvss = bestCvss(vulnerability.CVSS);
    const references = [
      ...(vulnerability.PrimaryURL ? [vulnerability.PrimaryURL] : []),
      ...(vulnerability.References ?? []),
    ];

    return {
      fingerprint: fingerprintSca({
        projectId,
        vulnerabilityId: vulnerability.VulnerabilityID,
        purl,
        ecosystem: result.Type,
        packageName: vulnerability.PkgName,
      }),
      kind: 'sca',
      severity: normalizeSeverity(vulnerability.Severity),
      title:
        vulnerability.Title ??
        `${vulnerability.PkgName ?? 'dependency'}: ${vulnerability.VulnerabilityID}`,
      ...(vulnerability.Description ? { description: vulnerability.Description } : {}),
      ruleId: vulnerability.VulnerabilityID,
      vulnerabilityIds: [vulnerability.VulnerabilityID],
      ...(cvss ? { cvss } : {}),
      location: { path: result.Target },
      package: {
        name: vulnerability.PkgName ?? 'unknown',
        ...(vulnerability.InstalledVersion ? { version: vulnerability.InstalledVersion } : {}),
        ...(result.Type ? { ecosystem: result.Type } : {}),
        ...(purl ? { purl } : {}),
        ...(vulnerability.FixedVersion ? { fixedVersion: vulnerability.FixedVersion } : {}),
      },
      references: [...new Set(references)],
      tool: TOOL,
      tools: [TOOL],
      raw: vulnerability,
    } satisfies Finding;
  });
}

function misconfigurationFindings(
  result: z.infer<typeof resultSchema>,
  projectId: string,
): Finding[] {
  const entries = (result.Misconfigurations ?? []).filter((entry) => entry.Status !== 'PASS');
  const ordinals = assignOrdinals(
    entries,
    (entry) => `${entry.ID}:${entry.CauseMetadata?.Resource ?? ''}`,
  );

  return entries.map((entry) => {
    const cause = entry.CauseMetadata;
    const snippet = cause?.Code?.Lines?.map((line) => line.Content ?? '').join('\n');

    return {
      fingerprint: fingerprintIac({
        projectId,
        ruleId: entry.ID,
        path: result.Target,
        resource: cause?.Resource,
        ordinal: ordinals.get(entry) ?? 0,
      }),
      kind: 'iac',
      severity: normalizeSeverity(entry.Severity),
      title: entry.Title ?? entry.ID,
      ...(entry.Message || entry.Description
        ? { description: [entry.Message, entry.Description, entry.Resolution].filter(Boolean).join('\n\n') }
        : {}),
      ruleId: entry.AVDID ?? entry.ID,
      vulnerabilityIds: [],
      location: {
        path: result.Target,
        ...(cause?.StartLine ? { startLine: cause.StartLine } : {}),
        ...(cause?.EndLine ? { endLine: cause.EndLine } : {}),
        ...(snippet ? { snippet } : {}),
      },
      references: entry.PrimaryURL ? [entry.PrimaryURL, ...(entry.References ?? [])] : entry.References ?? [],
      tool: TOOL,
      tools: [TOOL],
      raw: entry,
    } satisfies Finding;
  });
}

function secretFindings(result: z.infer<typeof resultSchema>, projectId: string): Finding[] {
  return (result.Secrets ?? []).map((secret) => ({
    fingerprint: fingerprintSecret({
      projectId,
      ruleId: secret.RuleID,
      path: result.Target,
      match: secret.Match ?? `${secret.RuleID}:${secret.StartLine ?? 0}`,
    }),
    kind: 'secret' as const,
    severity: normalizeSeverity(secret.Severity),
    title: secret.Title ?? secret.RuleID,
    ruleId: secret.RuleID,
    vulnerabilityIds: [],
    location: {
      path: result.Target,
      ...(secret.StartLine ? { startLine: secret.StartLine } : {}),
      ...(secret.EndLine ? { endLine: secret.EndLine } : {}),
      // The matched text is intentionally not carried: it contains the secret.
    },
    references: [],
    tool: TOOL,
    tools: [TOOL],
    raw: { ...secret, Match: '[redacted]' },
  }));
}

/**
 * Trivy reports CVSS from several sources at once. Prefer the newest scoring
 * system available, and prefer NVD when multiple sources agree on a version.
 */
function bestCvss(
  cvss: Record<string, z.infer<typeof cvssEntrySchema>> | undefined,
): Finding['cvss'] {
  if (!cvss) return undefined;
  const sources = Object.entries(cvss);
  const ordered = [...sources].sort(([a], [b]) => (a === 'nvd' ? -1 : b === 'nvd' ? 1 : 0));

  for (const [version, score, vector] of [
    ['4.0', 'V40Score', 'V40Vector'],
    ['3.1', 'V3Score', 'V3Vector'],
    ['2.0', 'V2Score', 'V2Vector'],
  ] as const) {
    for (const [source, entry] of ordered) {
      const value = entry[score];
      if (typeof value === 'number') {
        return {
          score: value,
          version,
          source,
          ...(entry[vector] ? { vector: entry[vector] } : {}),
        };
      }
    }
  }
  return undefined;
}
