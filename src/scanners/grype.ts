/**
 * Grype adapter, with Syft doing the cataloguing.
 *
 * Grype embeds Syft, so pointing it at a directory produces the software
 * inventory and the vulnerability match in one pass rather than shuttling an
 * SBOM between two containers. The third opinion on dependencies is worth
 * having because Grype's matching is CPE-aware, which catches vendored and
 * renamed packages that purl-only matchers miss.
 */

import { normalizeSeverity, type Finding } from '../core/index.js';
import { fingerprintSca } from '../core/fingerprint.js';
import { z } from 'zod';

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

export const GRYPE_VERSION = '0.117.0';
export const GRYPE_IMAGE =
  'anchore/grype@sha256:ddf9e9f204049f3a4a0955ef70873cabab6a31432125ad4f20a490b54950a253';

const TOOL = { name: 'grype', version: GRYPE_VERSION } as const;

const GRYPE_ENV = {
  HOME: '/tmp',
  TMPDIR: '/tmp',
  GRYPE_DB_CACHE_DIR: `${CACHE_MOUNT}/grype`,
  // Left to itself Grype will try to reach the internet mid-scan and, worse,
  // refuse to run against a database it considers stale. Neither is acceptable
  // in a sandbox with no network.
  GRYPE_DB_AUTO_UPDATE: 'false',
  GRYPE_DB_VALIDATE_AGE: 'false',
  GRYPE_CHECK_FOR_APP_UPDATE: 'false',
} as const;

const matchSchema = z
  .object({
    vulnerability: z
      .object({
        id: z.string(),
        severity: z.string().optional(),
        description: z.string().optional(),
        dataSource: z.string().optional(),
        urls: z.array(z.string()).optional(),
        cvss: z
          .array(
            z
              .object({
                version: z.string().optional(),
                vector: z.string().optional(),
                metrics: z.object({ baseScore: z.number().optional() }).loose().optional(),
              })
              .loose(),
          )
          .optional(),
        fix: z.object({ versions: z.array(z.string()).optional(), state: z.string().optional() }).loose().optional(),
      })
      .loose(),
    relatedVulnerabilities: z.array(z.object({ id: z.string() }).loose()).optional(),
    artifact: z
      .object({
        name: z.string(),
        version: z.string().optional(),
        type: z.string().optional(),
        purl: z.string().optional(),
        locations: z.array(z.object({ path: z.string() }).loose()).optional(),
      })
      .loose(),
  })
  .loose();

const reportSchema = z.object({ matches: z.array(matchSchema).optional() }).loose();

export const grypeAdapter: ScannerAdapter = {
  name: TOOL.name,
  version: TOOL.version,

  appliesTo: (target: DetectedTarget) => target.ecosystems.length > 0,

  spec: (context: ScanContext): SandboxSpec => ({
    image: GRYPE_IMAGE,
    network: 'none',
    args: [`dir:${WORKSPACE_MOUNT}`, '-o', 'json', '-q'],
    mounts: standardMounts(context),
    env: GRYPE_ENV,
    timeoutMs: 15 * 60 * 1000,
    memory: '4g',
  }),

  databaseSync: ({ cacheVolume }: DatabaseSyncOptions): SandboxSpec[] => [
    {
      image: GRYPE_IMAGE,
      network: 'bridge',
      args: ['db', 'update'],
      mounts: [{ type: 'volume', source: cacheVolume, target: CACHE_MOUNT, readOnly: false }],
      env: { ...GRYPE_ENV, GRYPE_DB_AUTO_UPDATE: 'true' },
      timeoutMs: 30 * 60 * 1000,
    },
  ],

  cachePaths: ['grype'],

  native: {
    binary: 'grype',
    args: (root, extra) => [`dir:${root}`, '-o', 'json', '-q', ...extra],
  },

  parse(stdout: string, context: ScanContext): Finding[] {
    const report = reportSchema.safeParse(safeJson(stdout));
    if (!report.success) return [];

    return (report.data.matches ?? []).map((match) => {
      const { vulnerability, artifact } = match;
      const ids = [vulnerability.id, ...(match.relatedVulnerabilities ?? []).map((r) => r.id)];
      const path = relative(artifact.locations?.[0]?.path);
      const score = bestScore(vulnerability.cvss ?? []);
      const fixedVersion = vulnerability.fix?.versions?.[0];

      return {
        fingerprint: fingerprintSca({
          projectId: context.projectId,
          vulnerabilityId: vulnerability.id,
          ...(artifact.purl !== undefined ? { purl: artifact.purl } : {}),
          ...(artifact.type !== undefined ? { ecosystem: artifact.type } : {}),
          packageName: artifact.name,
        }),
        kind: 'sca',
        severity: normalizeSeverity(vulnerability.severity),
        title: `${vulnerability.id} in ${artifact.name}`,
        ...(vulnerability.description !== undefined
          ? { description: vulnerability.description }
          : {}),
        ruleId: vulnerability.id,
        vulnerabilityIds: [...new Set(ids)].sort(),
        ...(score !== undefined ? { cvss: score } : {}),
        ...(path !== undefined ? { location: { path } } : {}),
        package: {
          name: artifact.name,
          ...(artifact.version !== undefined ? { version: artifact.version } : {}),
          ...(artifact.type !== undefined ? { ecosystem: artifact.type } : {}),
          ...(artifact.purl !== undefined ? { purl: artifact.purl } : {}),
          ...(fixedVersion !== undefined ? { fixedVersion } : {}),
        },
        references: (vulnerability.urls ?? []).slice(0, 10),
        tool: TOOL,
        tools: [TOOL],
        raw: match,
      };
    });
  },
};

type CvssEntry = NonNullable<z.infer<typeof matchSchema>['vulnerability']['cvss']>[number];

function bestScore(entries: readonly CvssEntry[]) {
  for (const version of ['3.1', '3.0', '2.0']) {
    const entry = entries.find((item) => item?.version?.startsWith(version));
    const score = entry?.metrics?.baseScore;
    if (entry !== undefined && score !== undefined) {
      return {
        score,
        ...(entry.vector !== undefined ? { vector: entry.vector } : {}),
        ...(entry.version !== undefined ? { version: entry.version } : {}),
        source: 'grype',
      };
    }
  }
  return undefined;
}

function relative(path: string | undefined): string | undefined {
  if (path === undefined) return undefined;
  const prefix = `${WORKSPACE_MOUNT}/`;
  if (path.startsWith(prefix)) return path.slice(prefix.length);
  // Grype reports paths relative to the scanned directory with a leading slash.
  return path.startsWith('/') ? path.slice(1) : path;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
