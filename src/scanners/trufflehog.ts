/**
 * TruffleHog adapter.
 *
 * Trivy's secret scanning is rule-driven and conservative; the Phase 0 spike
 * watched it walk past credentials because the variable name did not match its
 * expectations. TruffleHog carries around 800 detectors and is the better net.
 *
 * Verification is deliberately off. TruffleHog can confirm a credential is live
 * by authenticating against the provider, which is genuinely useful triage
 * data, but it means sending a customer's secret to a third party from inside a
 * sandbox that is otherwise network-isolated. That is a product decision with
 * consent attached, not a default.
 */

import type { Finding } from '../core/index.js';
import { fingerprintSecret } from '../core/fingerprint.js';
import { z } from 'zod';

import { WORKSPACE_MOUNT, standardMounts, type ScanContext, type ScannerAdapter } from './adapter.js';
import type { DetectedTarget } from './detect.js';
import type { SandboxSpec } from './runtime.js';

export const TRUFFLEHOG_VERSION = '3.97.0';
export const TRUFFLEHOG_IMAGE =
  'trufflesecurity/trufflehog@sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33';

const TOOL = { name: 'trufflehog', version: TRUFFLEHOG_VERSION } as const;

const resultSchema = z
  .object({
    DetectorName: z.string(),
    DecoderName: z.string().optional(),
    Verified: z.boolean().optional(),
    Raw: z.string().optional(),
    RawV2: z.string().optional(),
    Redacted: z.string().optional(),
    DetectorDescription: z.string().optional(),
    SourceMetadata: z
      .object({
        Data: z
          .object({
            Filesystem: z.object({ file: z.string(), line: z.number().optional() }).loose().optional(),
          })
          .loose(),
      })
      .loose(),
  })
  .loose();

export const trufflehogAdapter: ScannerAdapter = {
  name: TOOL.name,
  version: TOOL.version,

  // Any file can hold a credential, including the ones no other scanner cares
  // about, so this runs whenever there is anything at all to look at.
  appliesTo: (target: DetectedTarget) => target.fileCount > 0,

  spec: (context: ScanContext): SandboxSpec => ({
    image: TRUFFLEHOG_IMAGE,
    network: 'none',
    args: [
      'filesystem',
      WORKSPACE_MOUNT,
      '--json',
      '--no-verification',
      '--no-update',
      '--concurrency',
      '4',
    ],
    mounts: standardMounts(context),
    env: { HOME: '/tmp', TMPDIR: '/tmp' },
    timeoutMs: 15 * 60 * 1000,
  }),

  native: {
    binary: 'trufflehog',
    args: (root, extra) => ['filesystem', root, '--json', '--no-verification', '--no-update', ...extra],
  },

  parse(stdout: string, context: ScanContext): Finding[] {
    const records = stdout
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.startsWith('{'))
      .map((line) => resultSchema.safeParse(safeJson(line)))
      .flatMap((parsed) => (parsed.success ? [parsed.data] : []))
      .filter((record) => !isGitObject(filePath(record)));

    return records.map((record) => {
      const path = relative(filePath(record));
      const match = record.RawV2 ?? record.Raw ?? '';
      const line = record.SourceMetadata.Data.Filesystem?.line;

      return {
        fingerprint: fingerprintSecret({
          projectId: context.projectId,
          ruleId: record.DetectorName,
          path,
          match,
        }),
        kind: 'secret',
        // A live credential in a repository is an incident, not a finding to
        // schedule. Nothing here is verified, but nothing here is speculative
        // either: these detectors match on credential structure.
        severity: record.Verified === true ? 'critical' : 'high',
        title: `${record.DetectorName} credential in ${path}`,
        ...(record.DetectorDescription !== undefined
          ? { description: record.DetectorDescription }
          : {}),
        ruleId: record.DetectorName,
        vulnerabilityIds: [],
        location: {
          path,
          ...(line !== undefined && line > 0 ? { startLine: line } : {}),
          // The secret itself is never carried into the finding. It is hashed
          // into the fingerprint and shown only as the tool's own redaction.
          ...(record.Redacted !== undefined && record.Redacted.length > 0
            ? { snippet: record.Redacted }
            : {}),
        },
        references: [],
        tool: TOOL,
        tools: [TOOL],
        raw: redact(record),
      };
    });
  },
};

/**
 * TruffleHog reads `.git/objects` as ordinary files, so every secret in the
 * working tree is reported a second time against a content-addressed blob path
 * that means nothing to the person fixing it.
 *
 * Dropping those loses secrets that exist only in history, which is a real gap:
 * a credential deleted in the last commit is still a leaked credential. That
 * wants a dedicated history scan reporting commits rather than blob paths, not
 * a pile of unactionable duplicates in the working-tree scan.
 */
function isGitObject(path: string): boolean {
  return path.includes('/.git/') || path.endsWith('/.git');
}

/** The raw payload is stored on the finding, so the credential is stripped from it. */
function redact(record: z.infer<typeof resultSchema>): unknown {
  const { Raw, RawV2, ...rest } = record;
  void Raw;
  void RawV2;
  return rest;
}

function filePath(record: z.infer<typeof resultSchema>): string {
  return record.SourceMetadata.Data.Filesystem?.file ?? '';
}

function relative(path: string): string {
  const prefix = `${WORKSPACE_MOUNT}/`;
  return path.startsWith(prefix) ? path.slice(prefix.length) : path;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
