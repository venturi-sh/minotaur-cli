import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ADVISORY_MAX_AGE_MS, lookupAdvisories, rankFindings, type AdvisoryFetchers } from './advisories.js';
import type { LocalFinding } from './sources.js';

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'minotaur-advisories-'));
});
afterEach(() => rm(dir, { recursive: true, force: true }));

const NOW = 1_800_000_000_000;

function fetchers(options: { offline?: boolean } = {}) {
  const fail = () => Promise.reject(Object.assign(new Error('fetch failed'), { cause: { code: 'ENOTFOUND' } }));
  const kev = vi.fn<AdvisoryFetchers['kev']>(() =>
    options.offline ? fail() : Promise.resolve([{ id: 'cve-2021-44228', ransomware: true }]),
  );
  const epss = vi.fn<AdvisoryFetchers['epss']>((ids) =>
    options.offline
      ? fail()
      : Promise.resolve(ids.filter((id) => id !== 'CVE-2099-0001').map((id) => ({ id, score: 0.94, percentile: 0.99 }))),
  );
  return { kev, epss };
}

describe('lookupAdvisories', () => {
  it('fetches KEV and EPSS for CVEs only, then serves them from the cache for a day', async () => {
    const network = fetchers();
    const ids = ['CVE-2021-44228', 'GHSA-xxxx-yyyy-zzzz', 'CVE-2099-0001'];
    const first = await lookupAdvisories(dir, ids, { now: NOW, fetchers: network });
    expect(first.note).toBeUndefined();
    expect(first.risks.get('CVE-2021-44228')).toEqual({ kev: true, kevRansomware: true, epss: 0.94, epssPercentile: 0.99 });
    expect(first.risks.get('CVE-2099-0001')).toEqual({ kev: false, kevRansomware: false });
    expect(first.risks.has('GHSA-xxxx-yyyy-zzzz')).toBe(false);
    expect(network.epss).toHaveBeenCalledWith(['CVE-2021-44228', 'CVE-2099-0001']);

    // A CVE that EPSS does not score is not asked about again either.
    const again = await lookupAdvisories(dir, ids, { now: NOW + 1000, fetchers: network });
    expect(again.risks).toEqual(first.risks);
    expect(network.kev).toHaveBeenCalledTimes(1);
    expect(network.epss).toHaveBeenCalledTimes(1);

    await lookupAdvisories(dir, ids, { now: NOW + ADVISORY_MAX_AGE_MS + 1, fetchers: network });
    expect(network.kev).toHaveBeenCalledTimes(2);
    expect(network.epss).toHaveBeenCalledTimes(2);
  });

  it('uses the older copy when offline, and says so', async () => {
    await lookupAdvisories(dir, ['CVE-2021-44228'], { now: NOW, fetchers: fetchers() });
    const later = NOW + 2 * ADVISORY_MAX_AGE_MS + 1;
    const offline = await lookupAdvisories(dir, ['CVE-2021-44228'], { now: later, fetchers: fetchers({ offline: true }) });
    expect(offline.risks.get('CVE-2021-44228')).toMatchObject({ kev: true, epss: 0.94 });
    expect(offline.note).toContain('the copy from 2 days ago is used');
    expect(offline.note).toContain('older scores are used for 1 of them');
  });

  it('still answers offline without any copy, with a note', async () => {
    const offline = await lookupAdvisories(dir, ['CVE-2021-44228'], { now: NOW, fetchers: fetchers({ offline: true }) });
    expect(offline.risks.get('CVE-2021-44228')).toEqual({ kev: false, kevRansomware: false });
    expect(offline.note).toContain('Could not fetch the CISA exploited list (ENOTFOUND)');
    expect(offline.note).toContain('Could not fetch EPSS scores (ENOTFOUND)');
  });

  it('asks for nothing when the scan found no CVE', async () => {
    const network = fetchers();
    expect((await lookupAdvisories(dir, ['GHSA-1'], { now: NOW, fetchers: network })).risks.size).toBe(0);
    expect(network.kev).not.toHaveBeenCalled();
  });
});

function finding(id: string, overrides: Partial<LocalFinding> = {}): LocalFinding {
  return {
    id,
    fingerprint: id.padEnd(64, '0'),
    kind: 'sast',
    severity: 'medium',
    title: `finding ${id}`,
    vulnerabilityIds: [],
    references: [],
    tool: { name: 'opengrep', version: '1' },
    tools: [],
    location: { path: `src/${id}.js`, startLine: 1 },
    ...overrides,
  };
}

describe('rankFindings', () => {
  it('puts likely issues first and marks exploited dependencies', () => {
    const risks = new Map([['CVE-2021-44228', { kev: true, kevRansomware: false }]]);
    const ranked = rankFindings(
      [
        finding('noise001', { rule: { category: 'correctness', subcategory: [] } }),
        finding('maybe001', { rule: { category: 'security', subcategory: ['audit'] } }),
        finding('dep00001', { kind: 'sca', severity: 'high', vulnerabilityIds: ['cve-2021-44228'] }),
      ],
      risks,
    );
    expect(ranked.map((item) => [item.id, item.focus])).toEqual([
      ['dep00001', 'likely'],
      ['maybe001', 'maybe'],
      ['noise001', 'noise'],
    ]);
    expect(ranked[0]).toMatchObject({ kev: true });
    expect(ranked[0]!.focusReasons!.join(' ')).toMatch(/exploited/i);
  });

  it('follows the focus settings', () => {
    const [kept] = rankFindings([finding('noise001', { rule: { category: 'correctness', subcategory: [] } })], new Map(), {
      keep: { rules: ['finding*'], paths: ['src/**'] },
    });
    expect(kept!.focus).not.toBe('noise');
  });
});
