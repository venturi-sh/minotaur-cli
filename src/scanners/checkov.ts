/**
 * Checkov adapter.
 *
 * Trivy already checks infrastructure code, so this is overlap by design:
 * Checkov ships roughly a thousand policies against Trivy's few hundred and is
 * consistently earlier on new cloud services. Where both fire, correlation
 * collapses them; where only one does, the coverage was worth the container.
 */

import { assignOrdinals, type Finding } from '../core/index.js';
import { fingerprintIac } from '../core/fingerprint.js';
import { z } from 'zod';

import { WORKSPACE_MOUNT, standardMounts, type ScanContext, type ScannerAdapter } from './adapter.js';
import type { DetectedTarget } from './detect.js';
import type { SandboxSpec } from './runtime.js';

export const CHECKOV_VERSION = '3.3.11';
export const CHECKOV_IMAGE =
  'bridgecrew/checkov@sha256:e5e308e713725e73f517e4cb85b39d467f1e047204c174fb15eb444c27ffb745';

const TOOL = { name: 'checkov', version: CHECKOV_VERSION } as const;

const failedCheckSchema = z
  .object({
    check_id: z.string(),
    check_name: z.string(),
    file_path: z.string(),
    file_abs_path: z.string().optional(),
    file_line_range: z.array(z.number()).optional(),
    resource: z.string().optional(),
    severity: z.string().nullable().optional(),
    guideline: z.string().nullable().optional(),
    check_class: z.string().optional(),
  })
  .loose();

const frameworkResultSchema = z
  .object({
    check_type: z.string(),
    results: z.object({ failed_checks: z.array(failedCheckSchema).optional() }).loose().optional(),
  })
  .loose();

// Checkov emits a bare object rather than an array when only one framework
// matched, which is the kind of shape drift that should not fail a scan.
const reportSchema = z.union([z.array(frameworkResultSchema), frameworkResultSchema]);

export const checkovAdapter: ScannerAdapter = {
  name: TOOL.name,
  version: TOOL.version,

  appliesTo: (target: DetectedTarget) =>
    target.hasIac || target.hasContainerfile || target.hasKubernetes,

  spec: (context: ScanContext): SandboxSpec => ({
    image: CHECKOV_IMAGE,
    network: 'none',
    args: [
      '-d',
      WORKSPACE_MOUNT,
      '-o',
      'json',
      '--compact',
      '--quiet',
      // Without this Checkov spends the first seconds of every scan trying to
      // reach Prisma Cloud for policy guidelines it will not get.
      '--skip-download',
    ],
    mounts: standardMounts(context),
    env: { HOME: '/tmp', TMPDIR: '/tmp', LOG_LEVEL: 'ERROR' },
    timeoutMs: 15 * 60 * 1000,
    memory: '4g',
  }),

  /** Exit 1 means policies failed, which is the whole point of running it. */
  isSuccess: (exitCode: number) => exitCode === 0 || exitCode === 1,

  native: {
    binary: 'checkov',
    args: (root, extra) => ['-d', root, '-o', 'json', '--compact', '--quiet', '--skip-download', ...extra],
  },

  parse(stdout: string, context: ScanContext): Finding[] {
    const report = reportSchema.safeParse(safeJson(stdout));
    if (!report.success) return [];

    const frameworks = Array.isArray(report.data) ? report.data : [report.data];
    const checks = frameworks.flatMap((framework) =>
      (framework.results?.failed_checks ?? []).map((check) => ({ framework, check })),
    );

    const ordinals = assignOrdinals(
      checks,
      ({ check }) => `${check.check_id}\u0000${relative(check.file_path)}\u0000${check.resource ?? ''}`,
    );

    return checks.map((entry) => {
      const { check, framework } = entry;
      const path = relative(check.file_path);
      const startLine = check.file_line_range?.[0];
      const endLine = check.file_line_range?.[1];
      const snippet =
        startLine !== undefined ? context.readSnippet?.(path, startLine, endLine ?? startLine) : undefined;

      return {
        fingerprint: fingerprintIac({
          projectId: context.projectId,
          ruleId: check.check_id,
          path,
          ...(check.resource !== undefined ? { resource: check.resource } : {}),
          ordinal: ordinals.get(entry) ?? 0,
        }),
        kind: 'iac',
        // Checkov's open-source policies carry no severity at all; the field is
        // populated only by the commercial platform. Rather than invent a
        // ranking, everything lands at medium and the triage layer sorts it out.
        severity: check.severity ? normalize(check.severity) : 'medium',
        title: check.check_name,
        description: `${framework.check_type} policy ${check.check_id} failed${
          check.resource !== undefined ? ` on ${check.resource}` : ''
        }`,
        ruleId: check.check_id,
        vulnerabilityIds: [],
        location: {
          path,
          ...(startLine !== undefined && startLine > 0 ? { startLine } : {}),
          ...(endLine !== undefined && endLine > 0 ? { endLine } : {}),
          ...(snippet !== undefined ? { snippet } : {}),
        },
        references: check.guideline ? [check.guideline] : [],
        tool: TOOL,
        tools: [TOOL],
        raw: check,
      };
    });
  },
};

function normalize(severity: string) {
  const value = severity.trim().toLowerCase();
  if (value === 'critical' || value === 'high' || value === 'medium' || value === 'low') {
    return value;
  }
  return 'medium' as const;
}

function relative(path: string): string {
  const prefix = `${WORKSPACE_MOUNT}/`;
  if (path.startsWith(prefix)) return path.slice(prefix.length);
  // Checkov reports paths relative to the scanned directory, with a leading slash.
  return path.startsWith('/') ? path.slice(1) : path;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
