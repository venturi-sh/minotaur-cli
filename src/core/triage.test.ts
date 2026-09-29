/**
 * The triage contract crosses three boundaries: the model's structured output,
 * the queue between API and worker, and a Postgres enum. Each is a place where
 * a quiet change is only noticed in production.
 */

import { describe, expect, it } from 'vitest';

import {
  ASSESSMENT_STATUSES,
  EXPLOITABILITY,
  exploitVerdictSchema,
  isTriageable,
  protectedReason,
  REACHABILITY,
  secretProtectsFile,
  TRIAGE_JOB_CONTRACT_VERSION,
  TRIAGE_QUEUE,
  TRIAGE_STATUS_KEY,
  TRIAGE_VERDICTS,
  triageJobSchema,
  triageVerdictSchema,
  triageWorkerStatusSchema,
} from './triage.js';

const SCAN_ID = '11111111-1111-4111-8111-111111111111';
const PROJECT_ID = '22222222-2222-4222-8222-222222222222';
const FINDING_ID = '33333333-3333-4333-8333-333333333333';

const verdict = {
  verdict: 'false_positive',
  reachability: 'unreachable',
  confidence: 0.8,
  rationale: 'The vulnerable parser is never called.',
  evidence: [{ path: 'src/app.py', startLine: 10, endLine: 12, quote: 'import av' }],
};

describe('persisted vocabularies', () => {
  it('pins the verdicts', () => {
    expect(TRIAGE_VERDICTS).toEqual(['true_positive', 'false_positive', 'needs_review']);
  });

  it('pins reachability', () => {
    expect(REACHABILITY).toEqual(['reachable', 'unreachable', 'unknown']);
  });

  it('records a budget skip as its own status, so it never reads as a clean verdict', () => {
    expect(ASSESSMENT_STATUSES).toEqual(['succeeded', 'failed', 'skipped_budget']);
  });
});

describe('isTriageable', () => {
  it('covers dependency and code findings', () => {
    expect(isTriageable('sca')).toBe(true);
    expect(isTriageable('sast')).toBe(true);
  });

  it('never sends a secret to a model provider', () => {
    expect(isTriageable('secret')).toBe(false);
  });

  it('leaves infrastructure and licence findings for later', () => {
    expect(isTriageable('iac')).toBe(false);
    expect(isTriageable('license')).toBe(false);
  });
});

describe('triageVerdictSchema', () => {
  it('accepts a well-formed verdict', () => {
    expect(triageVerdictSchema.parse(verdict)).toEqual(verdict);
  });

  it('defaults evidence to empty rather than rejecting its absence', () => {
    const { evidence: _omitted, ...bare } = verdict;
    expect(triageVerdictSchema.parse(bare).evidence).toEqual([]);
  });

  it('rejects a confidence outside 0 to 1', () => {
    expect(triageVerdictSchema.safeParse({ ...verdict, confidence: 1.2 }).success).toBe(false);
    expect(triageVerdictSchema.safeParse({ ...verdict, confidence: -0.1 }).success).toBe(false);
  });

  it('rejects a verdict outside the vocabulary', () => {
    expect(triageVerdictSchema.safeParse({ ...verdict, verdict: 'safe' }).success).toBe(false);
  });

  it('rejects an empty rationale, since an unexplained verdict cannot be argued with', () => {
    expect(triageVerdictSchema.safeParse({ ...verdict, rationale: '' }).success).toBe(false);
  });

  it('rejects evidence whose range runs backwards', () => {
    const backwards = { ...verdict, evidence: [{ ...verdict.evidence[0], startLine: 12, endLine: 10 }] };
    expect(triageVerdictSchema.safeParse(backwards).success).toBe(false);
  });

  it('rejects evidence with no quote', () => {
    const unquoted = { ...verdict, evidence: [{ ...verdict.evidence[0], quote: '' }] };
    expect(triageVerdictSchema.safeParse(unquoted).success).toBe(false);
  });
});

describe('triageJobSchema', () => {
  const job = { contractVersion: TRIAGE_JOB_CONTRACT_VERSION, scanId: SCAN_ID, projectId: PROJECT_ID };

  it('accepts an automatic job and defaults force to false', () => {
    expect(triageJobSchema.parse(job)).toEqual({ ...job, force: false, mode: 'triage' });
  });

  it('accepts an exploitability check of named findings', () => {
    const check = { ...job, findingIds: [FINDING_ID], force: true, mode: 'exploit' };
    expect(triageJobSchema.parse(check)).toEqual(check);
  });

  it('refuses an exploitability check of a whole scan, which would spend the deep budget on every finding', () => {
    expect(triageJobSchema.safeParse({ ...job, mode: 'exploit' }).success).toBe(false);
  });

  it('lets an exploitability check of one finding continue an earlier one', () => {
    const followUp = { ...job, findingIds: [FINDING_ID], force: true, mode: 'exploit', continueFrom: SCAN_ID };
    expect(triageJobSchema.parse(followUp)).toEqual(followUp);
  });

  it('refuses a continuation of triage, or across several findings', () => {
    const continueFrom = SCAN_ID;
    expect(triageJobSchema.safeParse({ ...job, findingIds: [FINDING_ID], continueFrom }).success).toBe(false);
    expect(
      triageJobSchema.safeParse({ ...job, mode: 'exploit', findingIds: [FINDING_ID, SCAN_ID], continueFrom }).success,
    ).toBe(false);
  });

  it('accepts a manual re-run of specific findings', () => {
    const manual = { ...job, findingIds: [FINDING_ID], force: true };
    expect(triageJobSchema.parse(manual)).toEqual({ ...manual, mode: 'triage' });
  });

  it('rejects an empty finding list, which would silently triage nothing', () => {
    expect(triageJobSchema.safeParse({ ...job, findingIds: [] }).success).toBe(false);
  });

  it('refuses a different contract version', () => {
    expect(triageJobSchema.safeParse({ ...job, contractVersion: 2 }).success).toBe(false);
  });

  it('refuses identifiers that are not uuids', () => {
    expect(triageJobSchema.safeParse({ ...job, scanId: 'scan-1' }).success).toBe(false);
  });

  it('uses its own queue, separate from scans', () => {
    expect(TRIAGE_QUEUE).toBe('minotaur.triage');
  });
});

describe('exploitVerdictSchema', () => {
  const answer = {
    exploitability: 'exploitable',
    confidence: 0.7,
    rationale: 'The upload route passes the file straight to the parser.',
    entryPoint: 'POST /api/upload',
    preconditions: ['authenticated user'],
    evidence: [{ path: 'api/upload.py', startLine: 4, endLine: 4, quote: 'parse(request.files["f"])' }],
    openQuestions: ['Is the upload route behind the admin check in api/auth.py?'],
  };

  it('pins the three answers, with undetermined as the honest third', () => {
    expect(EXPLOITABILITY).toEqual(['exploitable', 'not_exploitable', 'undetermined']);
  });

  it('accepts a full answer', () => {
    expect(exploitVerdictSchema.parse(answer)).toEqual(answer);
  });

  it('defaults preconditions and evidence to empty', () => {
    const { preconditions: _p, evidence: _e, entryPoint: _x, openQuestions: _q, ...bare } = answer;
    expect(exploitVerdictSchema.parse(bare)).toMatchObject({ preconditions: [], evidence: [], openQuestions: [] });
  });

  it('rejects a yes-or-no outside the vocabulary', () => {
    expect(exploitVerdictSchema.safeParse({ ...answer, exploitability: 'probably' }).success).toBe(false);
  });
});

describe('which files the agent may read', () => {
  const secrets = new Set(['agent/uv.lock']);

  it('refuses credential files wherever they sit', () => {
    expect(protectedReason('api/.env', secrets)).toBe('credential_file');
    expect(protectedReason('deploy/keys/server.pem', secrets)).toBe('credential_file');
  });

  it('allows example env files', () => {
    expect(protectedReason('api/.env.example', secrets)).toBeNull();
  });

  it('refuses a file a secret finding points at, and nothing else', () => {
    expect(protectedReason('agent/uv.lock', secrets)).toBe('secret_finding');
    expect(protectedReason('api/uv.lock', secrets)).toBeNull();
  });

  it('lifts the protection only when a person calls the secret a false positive', () => {
    expect(secretProtectsFile('false_positive')).toBe(false);
    for (const state of ['open', 'confirmed', 'accepted_risk', 'fixed'] as const) {
      expect(secretProtectsFile(state)).toBe(true);
    }
  });
});

describe('triageWorkerStatusSchema', () => {
  it('pins the key the worker and the API share', () => {
    expect(TRIAGE_STATUS_KEY).toBe('minotaur:triage:status');
  });

  it('accepts a disabled worker with only a reason', () => {
    const off = { enabled: false, reason: 'ANTHROPIC_API_KEY is not set' };
    expect(triageWorkerStatusSchema.parse(off)).toEqual(off);
  });

  it('strips anything that is not part of the status, so a stray field cannot reach the dashboard', () => {
    const parsed = triageWorkerStatusSchema.parse({ enabled: true, model: 'anthropic:x', apiKey: 'sk-ant-secret' });
    expect(parsed).toEqual({ enabled: true, model: 'anthropic:x' });
  });
});
