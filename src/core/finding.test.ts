/**
 * The findings model is the vocabulary every other stage speaks, so a change
 * here is felt everywhere at once and usually without an error. Severity
 * normalization decides what the dashboard counts as critical; purl and snippet
 * normalization decide whether triage history survives a version bump or a
 * reindent; dedupe decides whether three scanners agreeing looks like three
 * problems. Those consequences are what is pinned here.
 */

import { describe, expect, it } from 'vitest';

import {
  assignOrdinals,
  bySeverityDesc,
  dedupeFindings,
  normalizeSeverity,
  normalizeSnippet,
  purlWithoutVersion,
  severityRank,
  SEVERITIES,
  type Finding,
  type Severity,
  type ToolRef,
} from './finding.js';

const tool = (name: string, version = '1.0.0'): ToolRef => ({ name, version });

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  fingerprint: 'a'.repeat(64),
  kind: 'sca',
  severity: 'medium',
  title: 'Example',
  vulnerabilityIds: [],
  references: [],
  tool: tool('trivy'),
  tools: [],
  ...overrides,
});

describe('normalizeSeverity', () => {
  /**
   * Each scanner names its levels differently, and every one of these spellings
   * was observed in real output during the scanner survey. An unrecognised
   * spelling has to land on `unknown` rather than a guess, because a silent
   * downgrade to `low` is how a critical finding disappears from a filtered list.
   */
  const synonyms: [string, Severity][] = [
    ['critical', 'critical'],
    ['high', 'high'],
    ['error', 'high'],
    ['medium', 'medium'],
    ['moderate', 'medium'],
    ['warning', 'medium'],
    ['low', 'low'],
    ['info', 'info'],
    ['informational', 'info'],
    ['note', 'info'],
    ['none', 'info'],
  ];

  it.each(synonyms)('maps %s to %s', (raw, expected) => {
    expect(normalizeSeverity(raw)).toBe(expected);
  });

  it('is case and whitespace insensitive', () => {
    expect(normalizeSeverity('  CRITICAL  ')).toBe('critical');
    expect(normalizeSeverity('Moderate')).toBe('medium');
  });

  it.each([undefined, null, '', '   ', 'catastrophic', 'sev1'])(
    'falls back to unknown rather than guessing for %o',
    (raw) => {
      expect(normalizeSeverity(raw)).toBe('unknown');
    },
  );
});

describe('severity ordering', () => {
  it('ranks the levels in the documented order', () => {
    const ranked = [...SEVERITIES].sort(bySeverityDesc);
    expect(ranked).toEqual(['critical', 'high', 'medium', 'low', 'info', 'unknown']);
  });

  it('ranks unknown below info, so an unrecognised level never outranks a real one', () => {
    expect(severityRank('unknown')).toBeLessThan(severityRank('info'));
  });

  it('sorts the worst finding first', () => {
    const severities: Severity[] = ['low', 'critical', 'info', 'high'];
    expect([...severities].sort(bySeverityDesc)).toEqual(['critical', 'high', 'low', 'info']);
  });
});

describe('purlWithoutVersion', () => {
  it('strips a version so a bump to another vulnerable version keeps its identity', () => {
    expect(purlWithoutVersion('pkg:npm/lodash@4.17.20')).toBe('pkg:npm/lodash');
    expect(purlWithoutVersion('pkg:npm/lodash@4.17.21')).toBe('pkg:npm/lodash');
  });

  it('keeps the scope of a scoped npm package, whose @ is not a version', () => {
    expect(purlWithoutVersion('pkg:npm/@babel/traverse')).toBe('pkg:npm/@babel/traverse');
  });

  it('strips the version from a scoped package without eating the scope', () => {
    expect(purlWithoutVersion('pkg:npm/@babel/traverse@7.23.2')).toBe('pkg:npm/@babel/traverse');
  });

  it('drops qualifiers and subpaths, which describe the build rather than the package', () => {
    expect(purlWithoutVersion('pkg:golang/github.com/x/y@v1.2.3?type=module')).toBe(
      'pkg:golang/github.com/x/y',
    );
    expect(purlWithoutVersion('pkg:maven/org.apache/commons@1.0#subpath')).toBe(
      'pkg:maven/org.apache/commons',
    );
  });

  it('leaves a purl with no version untouched', () => {
    expect(purlWithoutVersion('pkg:pypi/django')).toBe('pkg:pypi/django');
  });

  it('is idempotent, so re-normalizing a stored purl cannot shift identity', () => {
    const once = purlWithoutVersion('pkg:npm/@babel/traverse@7.23.2');
    expect(purlWithoutVersion(once)).toBe(once);
  });
});

describe('normalizeSnippet', () => {
  it('collapses whitespace so reindenting code does not change identity', () => {
    expect(normalizeSnippet('  if (a)   {\n\t  return b;\n  }  ')).toBe('if (a) { return b; }');
  });

  it('gives the same result for tab- and space-indented copies of one line', () => {
    expect(normalizeSnippet('\tconst x = 1;')).toBe(normalizeSnippet('    const x = 1;'));
  });

  it('does not merge distinct tokens, which would collide unrelated code', () => {
    expect(normalizeSnippet('a b')).not.toBe(normalizeSnippet('ab'));
  });
});

describe('assignOrdinals', () => {
  it('numbers repeated keys from zero in encounter order', () => {
    const items = [{ k: 'a' }, { k: 'b' }, { k: 'a' }, { k: 'a' }];
    const ordinals = assignOrdinals(items, (item) => item.k);
    expect(items.map((item) => ordinals.get(item))).toEqual([0, 0, 1, 2]);
  });

  it('keys every distinct occurrence separately even when the items are equal by value', () => {
    const a = { k: 'same' };
    const b = { k: 'same' };
    const ordinals = assignOrdinals([a, b], (item) => item.k);
    expect(ordinals.get(a)).toBe(0);
    expect(ordinals.get(b)).toBe(1);
  });

  it('returns an empty mapping for no items', () => {
    expect(assignOrdinals([], String).size).toBe(0);
  });
});

describe('dedupeFindings', () => {
  it('merges findings that share a fingerprint', () => {
    const merged = dedupeFindings([
      finding({ tool: tool('trivy') }),
      finding({ tool: tool('grype') }),
    ]);
    expect(merged).toHaveLength(1);
  });

  it('keeps findings with different fingerprints apart', () => {
    const merged = dedupeFindings([finding(), finding({ fingerprint: 'b'.repeat(64) })]);
    expect(merged).toHaveLength(2);
  });

  it('records every contributing tool, sorted so the order does not depend on scan order', () => {
    const merged = dedupeFindings([
      finding({ tool: tool('trivy') }),
      finding({ tool: tool('grype') }),
      finding({ tool: tool('osv-scanner') }),
    ]);
    expect(merged[0]?.tools.map((t) => t.name)).toEqual(['grype', 'osv-scanner', 'trivy']);
  });

  it('treats two versions of one tool as distinct entries rather than collapsing them', () => {
    const merged = dedupeFindings([
      finding({ tool: tool('trivy', '0.58.0') }),
      finding({ tool: tool('trivy', '0.59.0') }),
    ]);
    expect(merged[0]?.tools).toHaveLength(2);
  });

  it('takes the highest severity, the safe direction to be wrong in when scanners disagree', () => {
    const merged = dedupeFindings([finding({ severity: 'low' }), finding({ severity: 'high' })]);
    expect(merged[0]?.severity).toBe('high');
  });

  it('takes the highest severity regardless of which scanner reported first', () => {
    const merged = dedupeFindings([finding({ severity: 'high' }), finding({ severity: 'low' })]);
    expect(merged[0]?.severity).toBe('high');
  });

  it('prefers any real severity over unknown', () => {
    const merged = dedupeFindings([
      finding({ severity: 'unknown' }),
      finding({ severity: 'info' }),
    ]);
    expect(merged[0]?.severity).toBe('info');
  });

  it('unions the advisory identifiers, since each scanner knows a different subset', () => {
    const merged = dedupeFindings([
      finding({ vulnerabilityIds: ['CVE-2021-23337'] }),
      finding({ vulnerabilityIds: ['GHSA-35jh-r3h4-6jhm', 'CVE-2021-23337'] }),
    ]);
    expect(merged[0]?.vulnerabilityIds).toEqual(['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm']);
  });

  it('unions references without duplicating shared ones', () => {
    const merged = dedupeFindings([
      finding({ references: ['https://a', 'https://shared'] }),
      finding({ references: ['https://shared', 'https://b'] }),
    ]);
    expect(merged[0]?.references).toEqual(['https://a', 'https://shared', 'https://b']);
  });

  it('fills in details the first scanner omitted rather than leaving them empty', () => {
    const merged = dedupeFindings([
      finding({}),
      finding({ description: 'why it matters', cvss: { score: 7.5 } }),
    ]);
    expect(merged[0]?.description).toBe('why it matters');
    expect(merged[0]?.cvss?.score).toBe(7.5);
  });

  it('keeps the fixed version when only one scanner reported it', () => {
    const merged = dedupeFindings([
      finding({ package: { name: 'lodash', version: '4.17.20' } }),
      finding({ package: { name: 'lodash', fixedVersion: '4.17.21', ecosystem: 'npm' } }),
    ]);
    expect(merged[0]?.package).toMatchObject({
      name: 'lodash',
      version: '4.17.20',
      fixedVersion: '4.17.21',
      ecosystem: 'npm',
    });
  });

  it('carries the package through when only the later finding has one', () => {
    const merged = dedupeFindings([finding({}), finding({ package: { name: 'lodash' } })]);
    expect(merged[0]?.package?.name).toBe('lodash');
  });

  it('preserves an already-merged tools list instead of resetting it to the single tool', () => {
    const merged = dedupeFindings([
      finding({ tool: tool('trivy'), tools: [tool('trivy'), tool('grype')] }),
    ]);
    expect(merged[0]?.tools.map((t) => t.name)).toEqual(['trivy', 'grype']);
  });

  it('returns nothing for no findings', () => {
    expect(dedupeFindings([])).toEqual([]);
  });

  it('does not mutate its input', () => {
    const first = finding({ severity: 'low', vulnerabilityIds: ['CVE-1'] });
    dedupeFindings([first, finding({ severity: 'high', vulnerabilityIds: ['CVE-2'] })]);
    expect(first.severity).toBe('low');
    expect(first.vulnerabilityIds).toEqual(['CVE-1']);
    expect(first.tools).toEqual([]);
  });
});
