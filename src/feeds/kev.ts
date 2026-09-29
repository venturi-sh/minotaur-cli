/**
 * The CISA Known Exploited Vulnerabilities catalog.
 *
 * The highest-signal input the risk model has, and the only one reporting
 * observed fact rather than prediction: every entry is a vulnerability someone
 * has been caught exploiting. Small enough — roughly 1,400 entries — to hold in
 * memory, unlike EPSS.
 */

import { z } from 'zod';

import { fetchOk, type FetchOptions } from './http.js';

export const KEV_FEED = 'cisa-kev';
export const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const entrySchema = z
  .object({
    cveID: z.string().min(1),
    vulnerabilityName: z.string().optional(),
    dateAdded: z.string().optional(),
    dueDate: z.string().optional(),
    /** CISA writes "Known" or "Unknown" rather than a boolean. */
    knownRansomwareCampaignUse: z.string().optional(),
  })
  .loose();

const catalogSchema = z
  .object({
    catalogVersion: z.string().optional(),
    dateReleased: z.string().optional(),
    vulnerabilities: z.array(entrySchema),
  })
  .loose();

export interface KevEntry {
  id: string;
  name: string | undefined;
  addedAt: Date | undefined;
  dueAt: Date | undefined;
  ransomware: boolean;
}

export interface KevFeed {
  revision: string | undefined;
  entries: KevEntry[];
}

export async function fetchKev(options: FetchOptions = {}): Promise<KevFeed> {
  const response = await fetchOk(KEV_URL, options);
  const catalog = catalogSchema.parse(await response.json());

  return {
    revision: catalog.catalogVersion,
    entries: catalog.vulnerabilities.map((entry) => ({
      id: entry.cveID.trim().toUpperCase(),
      name: entry.vulnerabilityName,
      addedAt: parseDate(entry.dateAdded),
      dueAt: parseDate(entry.dueDate),
      ransomware: entry.knownRansomwareCampaignUse?.trim().toLowerCase() === 'known',
    })),
  };
}

function parseDate(value: string | undefined): Date | undefined {
  if (value === undefined || value.trim().length === 0) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}
