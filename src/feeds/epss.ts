/**
 * The EPSS daily scores feed from FIRST.
 *
 * Roughly 290,000 CVEs, each with a probability of being exploited in the next
 * 30 days. Delivered as a gzipped CSV, streamed rather than buffered: the
 * decompressed file is tens of megabytes and there is no reason for all of it
 * to be resident at once when it is going straight into Postgres.
 *
 * The first line is a comment carrying the model version and the score date,
 * which is the provenance recorded against the feed.
 */

import { createInterface } from 'node:readline';
import { Readable } from 'node:stream';
import { createGunzip } from 'node:zlib';

import { z } from 'zod';

import { fetchOk, type FetchOptions } from './http.js';

export const EPSS_FEED = 'epss';
export const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';

export interface EpssRow {
  id: string;
  score: number;
  percentile: number;
}

export interface EpssFeed {
  /** The model version and score date from the header comment. */
  revision: string | undefined;
  scoreDate: Date | undefined;
  count: number;
  skipped: number;
}

export interface EpssMeta {
  revision: string | undefined;
  scoreDate: Date | undefined;
}

export interface StreamEpssOptions {
  /** Rows are delivered in batches so the caller can write them incrementally. */
  batchSize?: number;
  /** Fired when the header comment is parsed, which is before the first batch. */
  onMeta?: (meta: EpssMeta) => void;
  onBatch(rows: EpssRow[]): Promise<void>;
}

const DEFAULT_BATCH_SIZE = 5_000;

export async function streamEpss(options: StreamEpssOptions): Promise<EpssFeed> {
  const batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE;
  const response = await fetchOk(EPSS_URL);

  const source = Readable.fromWeb(response.body as Parameters<typeof Readable.fromWeb>[0]);
  const gunzip = createGunzip();
  // `pipe` does not forward errors, and a truncated download that silently
  // produced a short file would look like a successful sync of fewer CVEs.
  source.on('error', (error) => gunzip.destroy(error));
  source.pipe(gunzip);

  const lines = createInterface({ input: gunzip, crlfDelay: Infinity });

  let revision: string | undefined;
  let scoreDate: Date | undefined;
  let seenHeader = false;
  let count = 0;
  let skipped = 0;
  let batch: EpssRow[] = [];

  for await (const line of lines) {
    if (line.length === 0) continue;

    if (line.startsWith('#')) {
      const meta = parseMeta(line);
      revision = meta.revision;
      scoreDate = meta.scoreDate;
      options.onMeta?.(meta);
      continue;
    }

    if (!seenHeader) {
      seenHeader = true;
      // The column header, not a record. Anything else means the format moved.
      if (line.startsWith('cve,')) continue;
      throw new Error(`Unexpected EPSS header: ${line.slice(0, 80)}`);
    }

    const row = parseRow(line);
    if (row === undefined) {
      skipped += 1;
      continue;
    }

    batch.push(row);
    count += 1;

    if (batch.length >= batchSize) {
      await options.onBatch(batch);
      batch = [];
    }
  }

  if (batch.length > 0) await options.onBatch(batch);

  if (count === 0) throw new Error('EPSS feed contained no rows');

  return { revision, scoreDate, count, skipped };
}

/** FIRST's query API, for a handful of CVEs where the full daily file would be a waste. */
export const EPSS_API_URL = 'https://api.first.org/data/v1/epss';

/** The API pages at 100 rows, and a long CVE list would also overrun the URL. */
const LOOKUP_BATCH = 100;

const lookupSchema = z.object({
  data: z.array(z.object({ cve: z.string(), epss: z.coerce.number(), percentile: z.coerce.number() }).loose()),
});

/** Current scores of just these CVEs. Ids EPSS does not score are left out. */
export async function lookupEpss(ids: readonly string[], options: FetchOptions = {}): Promise<EpssRow[]> {
  const wanted = [...new Set(ids.map((id) => id.trim().toUpperCase()).filter((id) => /^CVE-\d{4}-\d+$/.test(id)))];
  const rows: EpssRow[] = [];
  for (let start = 0; start < wanted.length; start += LOOKUP_BATCH) {
    const batch = wanted.slice(start, start + LOOKUP_BATCH);
    const response = await fetchOk(`${EPSS_API_URL}?cve=${batch.join(',')}&limit=${LOOKUP_BATCH}`, options);
    for (const row of lookupSchema.parse(await response.json()).data) {
      if (!Number.isFinite(row.epss) || !Number.isFinite(row.percentile)) continue;
      rows.push({ id: row.cve.trim().toUpperCase(), score: clamp01(row.epss), percentile: clamp01(row.percentile) });
    }
  }
  return rows;
}

/** `#model_version:v2025.03.14,score_date:2026-08-16T00:00:00+0000` */
function parseMeta(line: string): { revision: string | undefined; scoreDate: Date | undefined } {
  const fields = new Map<string, string>();
  for (const part of line.slice(1).split(',')) {
    const separator = part.indexOf(':');
    if (separator === -1) continue;
    fields.set(part.slice(0, separator).trim(), part.slice(separator + 1).trim());
  }

  const model = fields.get('model_version');
  const date = fields.get('score_date');
  const parsed = date !== undefined ? new Date(date) : undefined;
  const scoreDate = parsed !== undefined && !Number.isNaN(parsed.getTime()) ? parsed : undefined;

  const revision = [model, date].filter((value) => value !== undefined).join(' ');

  return { revision: revision.length > 0 ? revision : undefined, scoreDate };
}

function parseRow(line: string): EpssRow | undefined {
  const [id, score, percentile] = line.split(',');
  if (id === undefined || score === undefined || percentile === undefined) return undefined;

  const parsedScore = Number.parseFloat(score);
  const parsedPercentile = Number.parseFloat(percentile);
  if (!Number.isFinite(parsedScore) || !Number.isFinite(parsedPercentile)) return undefined;

  return {
    id: id.trim().toUpperCase(),
    score: clamp01(parsedScore),
    percentile: clamp01(parsedPercentile),
  };
}

function clamp01(value: number): number {
  return Math.min(1, Math.max(0, value));
}
