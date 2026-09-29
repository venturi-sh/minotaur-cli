/**
 * Fingerprints are what makes triage durable. Every dismissal, every accepted
 * risk, every "we know, it's fine" is attached to one of these strings, so a
 * change to how they are derived does not break a test somewhere else — it
 * silently orphans the entire triage history and refloods the dashboard with
 * findings someone already dealt with.
 *
 * Two kinds of assertion live here. The behavioural ones describe what identity
 * is meant to survive: a version bump, a reindent, a line shift. The golden
 * digests pin the wire format itself, so that a refactor which preserves every
 * behaviour but reorders the hashed parts still fails loudly.
 */

import { describe, expect, it } from 'vitest';

import {
  fingerprintIac,
  fingerprintSast,
  fingerprintSca,
  fingerprintSecret,
} from './fingerprint.js';

const PROJECT = 'proj-1';
const OTHER_PROJECT = 'proj-2';

describe('fingerprint format', () => {
  const all = [
    fingerprintSca({ projectId: PROJECT, vulnerabilityId: 'CVE-1', purl: 'pkg:npm/x@1' }),
    fingerprintSast({ projectId: PROJECT, ruleId: 'r', path: 'a.js', snippet: 'x' }),
    fingerprintSecret({ projectId: PROJECT, ruleId: 'r', path: '.env', match: 's' }),
    fingerprintIac({ projectId: PROJECT, ruleId: 'r', path: 'main.tf' }),
  ];

  it.each(all)('is 64 lowercase hex characters', (fingerprint) => {
    expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it('never collides across kinds, so a rule id shared by two tools stays distinct', () => {
    expect(new Set(all).size).toBe(all.length);
  });

  /**
   * The hashed parts are null-separated precisely so that shifting a character
   * across a field boundary cannot produce the same digest.
   */
  it('does not let a character move across a field boundary produce a collision', () => {
    const a = fingerprintSast({ projectId: PROJECT, ruleId: 'ab', path: 'c', snippet: 's' });
    const b = fingerprintSast({ projectId: PROJECT, ruleId: 'a', path: 'bc', snippet: 's' });
    expect(a).not.toBe(b);
  });

  it.each([
    [
      'sca',
      fingerprintSca({
        projectId: PROJECT,
        vulnerabilityId: 'CVE-2021-23337',
        purl: 'pkg:npm/lodash@4.17.20',
      }),
      '42ebf650fa4f0afd22e03e2426909bd795ba9471bada5afc3916f470f84da83c',
    ],
    [
      'sast',
      fingerprintSast({
        projectId: PROJECT,
        ruleId: 'javascript.express.security.audit',
        path: 'src/app.js',
        snippet: 'eval(userInput)',
        ordinal: 0,
      }),
      '3d51c07b80352e938cc0deecfa3c1075d340a4934d86672c7f6fa9bcc8540776',
    ],
    [
      'secret',
      fingerprintSecret({
        projectId: PROJECT,
        ruleId: 'aws-access-key',
        path: '.env',
        match: 'AKIAIOSFODNN7EXAMPLE',
      }),
      'caf6a554d370353d2f6700ca59940c2500bd8a97adf1e0578cf49c8052d931c1',
    ],
    [
      'iac',
      fingerprintIac({
        projectId: PROJECT,
        ruleId: 'CKV_AWS_18',
        path: 'main.tf',
        resource: 'aws_s3_bucket.logs',
        ordinal: 0,
      }),
      '1995f367383e063beb1e41f95d0999169ea5404b2c92931f0f9b8b691e55e4d7',
    ],
  ])('produces the recorded %s digest, which stored triage depends on', (_kind, actual, golden) => {
    expect(actual).toBe(golden);
  });
});

describe('fingerprintSca', () => {
  const base = { projectId: PROJECT, vulnerabilityId: 'CVE-2021-23337' };

  /**
   * The central promise of dependency identity: upgrading from one vulnerable
   * version to another vulnerable version is the same finding, and the
   * dismissal should follow it.
   */
  it('ignores the installed version', () => {
    expect(fingerprintSca({ ...base, purl: 'pkg:npm/lodash@4.17.20' })).toBe(
      fingerprintSca({ ...base, purl: 'pkg:npm/lodash@4.17.21' }),
    );
  });

  it('ignores purl qualifiers, which describe the build rather than the package', () => {
    expect(fingerprintSca({ ...base, purl: 'pkg:npm/lodash@4.17.20?arch=x64' })).toBe(
      fingerprintSca({ ...base, purl: 'pkg:npm/lodash@4.17.20' }),
    );
  });

  it('separates different packages', () => {
    expect(fingerprintSca({ ...base, purl: 'pkg:npm/lodash@4.17.20' })).not.toBe(
      fingerprintSca({ ...base, purl: 'pkg:npm/underscore@4.17.20' }),
    );
  });

  it('separates different advisories in the same package', () => {
    const purl = 'pkg:npm/lodash@4.17.20';
    expect(fingerprintSca({ ...base, purl })).not.toBe(
      fingerprintSca({ ...base, vulnerabilityId: 'CVE-2020-8203', purl }),
    );
  });

  it('separates the same vulnerability in different projects', () => {
    const purl = 'pkg:npm/lodash@4.17.20';
    expect(fingerprintSca({ ...base, purl })).not.toBe(
      fingerprintSca({ ...base, projectId: OTHER_PROJECT, purl }),
    );
  });

  it('falls back to ecosystem and name when the scanner reported no purl', () => {
    expect(fingerprintSca({ ...base, ecosystem: 'npm', packageName: 'lodash' })).toMatch(
      /^[0-9a-f]{64}$/,
    );
    expect(fingerprintSca({ ...base, ecosystem: 'npm', packageName: 'lodash' })).not.toBe(
      fingerprintSca({ ...base, ecosystem: 'npm', packageName: 'underscore' }),
    );
  });

  it('distinguishes the same package name in two ecosystems', () => {
    expect(fingerprintSca({ ...base, ecosystem: 'npm', packageName: 'requests' })).not.toBe(
      fingerprintSca({ ...base, ecosystem: 'pypi', packageName: 'requests' }),
    );
  });

  it('prefers the purl over the name fields when both are present', () => {
    expect(
      fingerprintSca({ ...base, purl: 'pkg:npm/lodash@4.17.20', packageName: 'ignored' }),
    ).toBe(fingerprintSca({ ...base, purl: 'pkg:npm/lodash@4.17.20' }));
  });

  it('still produces an identity when the package is entirely unidentified', () => {
    expect(fingerprintSca(base)).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('fingerprintSast', () => {
  const base = { projectId: PROJECT, ruleId: 'rule-1', path: 'src/app.js' };

  /**
   * Code findings are content-addressed rather than position-addressed, because
   * editing anything above a finding shifts its line number and position-based
   * identity would discard the triage decision every time that happened.
   */
  it('survives the finding moving to a different line', () => {
    expect(fingerprintSast({ ...base, snippet: 'eval(x)', startLine: 10 })).toBe(
      fingerprintSast({ ...base, snippet: 'eval(x)', startLine: 220 }),
    );
  });

  it('survives a reindent of the same code', () => {
    expect(fingerprintSast({ ...base, snippet: '  eval(x)' })).toBe(
      fingerprintSast({ ...base, snippet: '\teval(x)' }),
    );
  });

  it('changes when the code itself changes', () => {
    expect(fingerprintSast({ ...base, snippet: 'eval(x)' })).not.toBe(
      fingerprintSast({ ...base, snippet: 'eval(y)' }),
    );
  });

  it('separates the same code in different files', () => {
    expect(fingerprintSast({ ...base, snippet: 'eval(x)' })).not.toBe(
      fingerprintSast({ ...base, path: 'src/other.js', snippet: 'eval(x)' }),
    );
  });

  it('separates different rules matching the same code', () => {
    expect(fingerprintSast({ ...base, snippet: 'eval(x)' })).not.toBe(
      fingerprintSast({ ...base, ruleId: 'rule-2', snippet: 'eval(x)' }),
    );
  });

  it('distinguishes repeated identical matches in one file by ordinal', () => {
    expect(fingerprintSast({ ...base, snippet: 'eval(x)', ordinal: 0 })).not.toBe(
      fingerprintSast({ ...base, snippet: 'eval(x)', ordinal: 1 }),
    );
  });

  it('treats a missing ordinal as the first occurrence', () => {
    expect(fingerprintSast({ ...base, snippet: 'eval(x)' })).toBe(
      fingerprintSast({ ...base, snippet: 'eval(x)', ordinal: 0 }),
    );
  });

  /**
   * Anchoring to a line number is knowingly weaker, and used only when a
   * scanner gives no code context at all. It has to still be deterministic.
   */
  it('falls back to the line number when no snippet was reported', () => {
    expect(fingerprintSast({ ...base, startLine: 10 })).toBe(
      fingerprintSast({ ...base, startLine: 10 }),
    );
    expect(fingerprintSast({ ...base, startLine: 10 })).not.toBe(
      fingerprintSast({ ...base, startLine: 11 }),
    );
  });

  it('does not confuse a line-anchored finding with a snippet-anchored one', () => {
    expect(fingerprintSast({ ...base, startLine: 10 })).not.toBe(
      fingerprintSast({ ...base, snippet: '10' }),
    );
  });

  it('treats a missing line and a missing snippet as a stable zero anchor', () => {
    expect(fingerprintSast(base)).toBe(fingerprintSast({ ...base, startLine: 0 }));
  });

  it('ignores an empty snippet rather than anchoring to it', () => {
    expect(fingerprintSast({ ...base, snippet: '', startLine: 10 })).toBe(
      fingerprintSast({ ...base, startLine: 10 }),
    );
  });
});

describe('fingerprintSecret', () => {
  const base = { projectId: PROJECT, ruleId: 'aws-access-key', path: '.env' };
  const secret = 'AKIAIOSFODNN7EXAMPLE';

  /**
   * The point of hashing the match separately: fingerprints are stored, logged
   * and returned over the API, so the credential must not be recoverable from
   * one or even hinted at by it.
   */
  it('does not carry the secret itself', () => {
    const fingerprint = fingerprintSecret({ ...base, match: secret });
    expect(fingerprint).not.toContain(secret);
    expect(fingerprint).not.toContain(Buffer.from(secret).toString('hex'));
  });

  it('is stable for the same credential in the same place', () => {
    expect(fingerprintSecret({ ...base, match: secret })).toBe(
      fingerprintSecret({ ...base, match: secret }),
    );
  });

  it('changes when the credential is rotated, since a new leak is a new finding', () => {
    expect(fingerprintSecret({ ...base, match: secret })).not.toBe(
      fingerprintSecret({ ...base, match: 'AKIAI44QH8DHBEXAMPLE' }),
    );
  });

  it('separates the same credential leaked in two files', () => {
    expect(fingerprintSecret({ ...base, match: secret })).not.toBe(
      fingerprintSecret({ ...base, path: 'config/prod.env', match: secret }),
    );
  });

  it('separates two rules matching the same string', () => {
    expect(fingerprintSecret({ ...base, match: secret })).not.toBe(
      fingerprintSecret({ ...base, ruleId: 'generic-api-key', match: secret }),
    );
  });
});

describe('fingerprintIac', () => {
  const base = { projectId: PROJECT, ruleId: 'CKV_AWS_18', path: 'main.tf' };

  it('separates two resources in one file breaking the same rule', () => {
    expect(fingerprintIac({ ...base, resource: 'aws_s3_bucket.logs' })).not.toBe(
      fingerprintIac({ ...base, resource: 'aws_s3_bucket.assets' }),
    );
  });

  it('is stable across scans for the same resource', () => {
    expect(fingerprintIac({ ...base, resource: 'aws_s3_bucket.logs' })).toBe(
      fingerprintIac({ ...base, resource: 'aws_s3_bucket.logs' }),
    );
  });

  it('separates the same resource name in two files', () => {
    expect(fingerprintIac({ ...base, resource: 'aws_s3_bucket.logs' })).not.toBe(
      fingerprintIac({ ...base, path: 'modules/logging/main.tf', resource: 'aws_s3_bucket.logs' }),
    );
  });

  it('falls back to an ordinal when the tool named no resource', () => {
    expect(fingerprintIac({ ...base, ordinal: 0 })).not.toBe(
      fingerprintIac({ ...base, ordinal: 1 }),
    );
  });

  it('treats a missing resource and ordinal as stable defaults', () => {
    expect(fingerprintIac(base)).toBe(fingerprintIac({ ...base, resource: '', ordinal: 0 }));
  });
});
