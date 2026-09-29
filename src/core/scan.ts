/**
 * Shared vocabulary for projects, scans and the queue contract between the API
 * and the workers.
 */

import { z } from 'zod';

/**
 * `skipped` applies to scan tasks rather than scans: a scanner with nothing to
 * do is not a scanner that found nothing, and conflating the two would let a
 * misconfigured pipeline look like a clean repository.
 */
export const SCAN_STATUSES = ['queued', 'running', 'succeeded', 'failed', 'skipped'] as const;
export const scanStatusSchema = z.enum(SCAN_STATUSES);
export type ScanStatus = z.infer<typeof scanStatusSchema>;

/**
 * How a finding relates to the scan before it. Stored per observation rather
 * than on the finding, because "new" is only ever true relative to one scan.
 */
export const OBSERVATION_STATUSES = ['new', 'existing', 'reintroduced'] as const;
export const observationStatusSchema = z.enum(OBSERVATION_STATUSES);
export type ObservationStatus = z.infer<typeof observationStatusSchema>;

export const SOURCE_TYPES = ['git', 'local'] as const;
export const sourceTypeSchema = z.enum(SOURCE_TYPES);
export type SourceType = z.infer<typeof sourceTypeSchema>;

export const FINDING_STATES = [
  'open',
  'confirmed',
  'false_positive',
  'accepted_risk',
  'fixed',
] as const;
export const findingStateSchema = z.enum(FINDING_STATES);
export type FindingState = z.infer<typeof findingStateSchema>;

export const scanSourceSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('git'),
    url: z.string().min(1),
    ref: z.string().min(1).optional(),
  }),
  z.object({
    type: z.literal('local'),
    path: z.string().min(1),
  }),
]);
export type ScanSource = z.infer<typeof scanSourceSchema>;

export const SCAN_QUEUE = 'minotaur.scan';

/**
 * The queue contract.
 *
 * Workers are reached only through this payload, never through in-process
 * calls, and it is versioned deliberately: it is the seam that lets a worker be
 * rewritten in another language, or run on different infrastructure, without
 * the control plane knowing. Bump the version rather than changing a field's
 * meaning in place.
 */
export const SCAN_JOB_CONTRACT_VERSION = 1;

export const scanJobSchema = z.object({
  contractVersion: z.literal(SCAN_JOB_CONTRACT_VERSION),
  scanId: z.uuid(),
  projectId: z.uuid(),
  source: scanSourceSchema,
});
export type ScanJob = z.infer<typeof scanJobSchema>;

/** Per-scan counts, denormalized so a scan list does not aggregate on every request. */
export const scanStatsSchema = z.object({
  total: z.number().int().nonnegative(),
  new: z.number().int().nonnegative(),
  reintroduced: z.number().int().nonnegative(),
  fixed: z.number().int().nonnegative(),
});
export type ScanStats = z.infer<typeof scanStatsSchema>;
