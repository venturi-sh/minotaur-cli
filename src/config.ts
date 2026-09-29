/**
 * `.minotaur.yml` at the repository root. Everything in it is optional, and
 * flags win over it. API keys are deliberately not accepted here: the file is
 * meant to be committed, and a key in it would be too.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { REPORT_FORMATS } from './scanners/index.js';
import { parse } from 'yaml';
import { z } from 'zod';

export const CONFIG_FILE = '.minotaur.yml';

const scannerSourceSchema = z.strictObject({
  scanner: z.string().min(1),
  args: z.array(z.string()).optional(),
});

const reportSourceSchema = z.strictObject({
  report: z.string().min(1),
  format: z.enum(REPORT_FORMATS).optional(),
});

export const sourceSchema = z.union([scannerSourceSchema, reportSourceSchema]);
export type SourceConfig = z.infer<typeof sourceSchema>;

export const configSchema = z.strictObject({
  sources: z.array(sourceSchema).optional(),
  model: z.string().min(1).optional(),
  baseUrl: z.url().optional(),
  triage: z
    .strictObject({
      maxSteps: z.number().int().min(2).optional(),
      maxUsd: z.number().positive().optional(),
      maxTokens: z.number().int().positive().optional(),
      effort: z.string().optional(),
    })
    .optional(),
  /** Rule ids and paths, as globs, to always set aside as noise or always keep. */
  focus: z
    .strictObject({
      noise: z.strictObject({ rules: z.array(z.string()).optional(), paths: z.array(z.string()).optional() }).optional(),
      keep: z.strictObject({ rules: z.array(z.string()).optional(), paths: z.array(z.string()).optional() }).optional(),
    })
    .optional(),
});
export type Config = z.infer<typeof configSchema>;

export async function loadConfig(root: string): Promise<{ config: Config; path: string | null }> {
  const path = join(root, CONFIG_FILE);
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { config: {}, path: null };
    throw error;
  }
  return { config: parseConfig(text, path), path };
}

export function parseConfig(text: string, path = CONFIG_FILE): Config {
  let raw: unknown;
  try {
    raw = parse(text) ?? {};
  } catch (error) {
    throw new Error(`${path} is not valid YAML: ${(error as Error).message}`);
  }
  if (typeof raw === 'object' && raw !== null && ('apiKey' in raw || 'api_key' in raw)) {
    throw new Error(`${path} must not contain an API key; set MINOTAUR_API_KEY or ANTHROPIC_API_KEY instead`);
  }
  const parsed = configSchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const where = issue?.path.length ? issue.path.join('.') : 'top level';
    throw new Error(`${path}: ${where}: ${issue?.message ?? 'invalid'}`);
  }
  return parsed.data;
}

/**
 * A `--source` value is a scanner name or a report path. Anything that looks
 * like a file wins, so `--source semgrep.json` reads the report rather than
 * running Semgrep.
 */
export function sourceFromFlag(value: string, scannerNames: readonly string[]): SourceConfig {
  const looksLikeFile = /[/\\]/.test(value) || /\.(json|sarif|jsonl)$/i.test(value);
  if (!looksLikeFile && scannerNames.includes(value)) return { scanner: value };
  if (!looksLikeFile) throw new Error(`unknown source "${value}"; expected one of ${scannerNames.join(', ')} or a report file`);
  return { report: value };
}
