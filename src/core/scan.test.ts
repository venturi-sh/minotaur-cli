/**
 * The queue payload is the seam between the control plane and the workers, and
 * the only thing they share. Both sides are deployed separately, so a field
 * that quietly changes meaning is not caught by a compiler anywhere — it is
 * caught by jobs failing in production, or worse, by jobs succeeding against
 * the wrong interpretation.
 *
 * The vocabularies below are also persisted as Postgres enum types, which makes
 * renaming or reordering a member a migration rather than an edit.
 */

import { describe, expect, it } from 'vitest';

import {
  FINDING_STATES,
  OBSERVATION_STATUSES,
  SCAN_JOB_CONTRACT_VERSION,
  SCAN_QUEUE,
  SCAN_STATUSES,
  scanJobSchema,
  scanSourceSchema,
  scanStatsSchema,
  SOURCE_TYPES,
} from './scan.js';

const SCAN_ID = '11111111-1111-4111-8111-111111111111';
const PROJECT_ID = '22222222-2222-4222-8222-222222222222';

const gitJob = {
  contractVersion: SCAN_JOB_CONTRACT_VERSION,
  scanId: SCAN_ID,
  projectId: PROJECT_ID,
  source: { type: 'git', url: 'https://github.com/juice-shop/juice-shop.git', ref: 'master' },
};

describe('persisted vocabularies', () => {
  /**
   * These back Postgres enum types. Changing a member in place would need a
   * migration, so the lists are pinned rather than merely type-checked.
   */
  it('pins the scan statuses', () => {
    expect(SCAN_STATUSES).toEqual(['queued', 'running', 'succeeded', 'failed', 'skipped']);
  });

  it('distinguishes a scanner with nothing to do from one that found nothing', () => {
    expect(SCAN_STATUSES).toContain('skipped');
    expect(SCAN_STATUSES).toContain('succeeded');
  });

  it('pins the observation statuses', () => {
    expect(OBSERVATION_STATUSES).toEqual(['new', 'existing', 'reintroduced']);
  });

  it('pins the triage states', () => {
    expect(FINDING_STATES).toEqual([
      'open',
      'confirmed',
      'false_positive',
      'accepted_risk',
      'fixed',
    ]);
  });

  it('pins the source types', () => {
    expect(SOURCE_TYPES).toEqual(['git', 'local']);
  });
});

describe('scanSourceSchema', () => {
  it('accepts a git source with a ref', () => {
    expect(scanSourceSchema.safeParse({ type: 'git', url: 'https://x/y.git', ref: 'main' }).success)
      .toBe(true);
  });

  it('accepts a git source without a ref, meaning the default branch', () => {
    expect(scanSourceSchema.safeParse({ type: 'git', url: 'https://x/y.git' }).success).toBe(true);
  });

  it('accepts a local source', () => {
    expect(scanSourceSchema.safeParse({ type: 'local', path: '/repos/x' }).success).toBe(true);
  });

  it('rejects a git source with no url, which would clone nothing', () => {
    expect(scanSourceSchema.safeParse({ type: 'git' }).success).toBe(false);
    expect(scanSourceSchema.safeParse({ type: 'git', url: '' }).success).toBe(false);
  });

  it('rejects a local source with no path', () => {
    expect(scanSourceSchema.safeParse({ type: 'local', path: '' }).success).toBe(false);
  });

  it('does not let the fields of one source type satisfy the other', () => {
    expect(scanSourceSchema.safeParse({ type: 'git', path: '/repos/x' }).success).toBe(false);
    expect(scanSourceSchema.safeParse({ type: 'local', url: 'https://x/y.git' }).success).toBe(
      false,
    );
  });

  it('rejects an unknown source type rather than defaulting to one', () => {
    expect(scanSourceSchema.safeParse({ type: 's3', url: 'https://x/y' }).success).toBe(false);
  });
});

describe('scanJobSchema', () => {
  it('accepts a well-formed job', () => {
    expect(scanJobSchema.parse(gitJob)).toEqual(gitJob);
  });

  /**
   * The version exists so an old worker refuses a payload it would otherwise
   * misread. Accepting a mismatched version would defeat the entire mechanism.
   */
  it('refuses a payload from a different contract version', () => {
    expect(scanJobSchema.safeParse({ ...gitJob, contractVersion: 2 }).success).toBe(false);
    expect(scanJobSchema.safeParse({ ...gitJob, contractVersion: 0 }).success).toBe(false);
  });

  it('refuses a payload with no version at all', () => {
    const { contractVersion: _omitted, ...unversioned } = gitJob;
    expect(scanJobSchema.safeParse(unversioned).success).toBe(false);
  });

  it('refuses identifiers that are not uuids', () => {
    expect(scanJobSchema.safeParse({ ...gitJob, scanId: 'scan-1' }).success).toBe(false);
    expect(scanJobSchema.safeParse({ ...gitJob, projectId: '' }).success).toBe(false);
  });

  it('refuses a job with no source', () => {
    const { source: _omitted, ...sourceless } = gitJob;
    expect(scanJobSchema.safeParse(sourceless).success).toBe(false);
  });

  it('survives the round trip through the queue as JSON', () => {
    expect(scanJobSchema.parse(JSON.parse(JSON.stringify(gitJob)))).toEqual(gitJob);
  });

  it('agrees with both sides on the queue name', () => {
    expect(SCAN_QUEUE).toBe('minotaur.scan');
  });
});

describe('scanStatsSchema', () => {
  it('accepts a plausible set of counts', () => {
    const stats = { total: 42, new: 7, reintroduced: 1, fixed: 3 };
    expect(scanStatsSchema.parse(stats)).toEqual(stats);
  });

  it('accepts an all-zero scan', () => {
    expect(scanStatsSchema.safeParse({ total: 0, new: 0, reintroduced: 0, fixed: 0 }).success).toBe(
      true,
    );
  });

  it('rejects negative counts, which would mean an arithmetic bug upstream', () => {
    expect(
      scanStatsSchema.safeParse({ total: -1, new: 0, reintroduced: 0, fixed: 0 }).success,
    ).toBe(false);
  });

  it('rejects fractional counts', () => {
    expect(
      scanStatsSchema.safeParse({ total: 1.5, new: 0, reintroduced: 0, fixed: 0 }).success,
    ).toBe(false);
  });

  it('requires every count, so a missing one cannot read as zero', () => {
    expect(scanStatsSchema.safeParse({ total: 1, new: 0, reintroduced: 0 }).success).toBe(false);
  });
});
