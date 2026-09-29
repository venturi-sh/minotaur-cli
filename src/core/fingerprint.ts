/**
 * Stable finding identity. Kept apart from `finding.ts`, which stays free of
 * Node builtins, and computed the same way as the Minotaur platform does, so a
 * finding has the same fingerprint in both.
 */

import { createHash } from 'node:crypto';

import { normalizeSnippet, purlWithoutVersion } from './finding.js';


/** Null-separated so that ['ab', 'c'] and ['a', 'bc'] cannot collide. */
function digest(parts: readonly (string | number)[]): string {
  const hash = createHash('sha256');
  for (const part of parts) {
    hash.update(String(part));
    hash.update('\u0000');
  }
  return hash.digest('hex');
}

/**
 * Dependency findings are identified by the package and the advisory, never by
 * the installed version: upgrading from one vulnerable version to another
 * vulnerable version is the same finding, and the triage history should follow.
 */
export function fingerprintSca(input: {
  projectId: string;
  vulnerabilityId: string;
  purl?: string | undefined;
  ecosystem?: string | undefined;
  packageName?: string | undefined;
}): string {
  const identity = input.purl
    ? purlWithoutVersion(input.purl)
    : `${input.ecosystem ?? 'unknown'}/${input.packageName ?? 'unknown'}`;
  return digest([input.projectId, 'sca', identity, input.vulnerabilityId]);
}

/**
 * Code findings are identified by content, not position. Line numbers shift
 * whenever anyone edits above the finding, and position-based identity would
 * silently discard the triage decision every time that happened.
 *
 * `ordinal` disambiguates genuinely identical matches in one file. It is
 * assigned by `assignOrdinals` in scan order, which is stable for a given
 * scanner version and input.
 */
export function fingerprintSast(input: {
  projectId: string;
  ruleId: string;
  path: string;
  snippet?: string | undefined;
  startLine?: number | undefined;
  ordinal?: number | undefined;
}): string {
  // Falling back to a line number is a knowingly weaker identity, used only
  // when a scanner gives us no code context at all.
  const anchor = input.snippet
    ? `snippet:${normalizeSnippet(input.snippet)}`
    : `line:${input.startLine ?? 0}`;
  return digest([input.projectId, 'sast', input.ruleId, input.path, anchor, input.ordinal ?? 0]);
}

/** The secret itself is hashed, never carried, so the fingerprint is safe to store and log. */
export function fingerprintSecret(input: {
  projectId: string;
  ruleId: string;
  path: string;
  match: string;
}): string {
  return digest([
    input.projectId,
    'secret',
    input.ruleId,
    input.path,
    createHash('sha256').update(input.match).digest('hex'),
  ]);
}

export function fingerprintIac(input: {
  projectId: string;
  ruleId: string;
  path: string;
  resource?: string | undefined;
  ordinal?: number | undefined;
}): string {
  return digest([
    input.projectId,
    'iac',
    input.ruleId,
    input.path,
    input.resource ?? '',
    input.ordinal ?? 0,
  ]);
}
