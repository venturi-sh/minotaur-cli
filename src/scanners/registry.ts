/**
 * The scanner fleet.
 *
 * Order matters only for presentation; the worker runs these concurrently.
 */

import { checkovAdapter } from './checkov.js';
import type { DetectedTarget } from './detect.js';
import { grypeAdapter } from './grype.js';
import { opengrepAdapter } from './opengrep.js';
import { osvAdapter } from './osv.js';
import { semgrepAdapter } from './semgrep.js';
import { trivyAdapter } from './trivy.js';
import { trufflehogAdapter } from './trufflehog.js';
import type { ScannerAdapter } from './adapter.js';

export const SCANNERS: readonly ScannerAdapter[] = [
  trivyAdapter,
  osvAdapter,
  grypeAdapter,
  semgrepAdapter,
  trufflehogAdapter,
  checkovAdapter,
];

export function scannerByName(name: string): ScannerAdapter | undefined {
  return SCANNERS.find((scanner) => scanner.name === name);
}

/** What the CLI can run on the local machine: the fleet, plus scanners that never run in a container. */
export const LOCAL_SCANNERS: readonly ScannerAdapter[] = [...SCANNERS.filter((scanner) => scanner.native), opengrepAdapter];

export function localScannerByName(name: string): ScannerAdapter | undefined {
  return LOCAL_SCANNERS.find((scanner) => scanner.name === name);
}

export interface ScannerSelection {
  applicable: ScannerAdapter[];
  skipped: ScannerAdapter[];
}

export function selectScanners(
  target: DetectedTarget,
  enabled: readonly string[] = SCANNERS.map((scanner) => scanner.name),
): ScannerSelection {
  const applicable: ScannerAdapter[] = [];
  const skipped: ScannerAdapter[] = [];

  for (const scanner of SCANNERS) {
    if (!enabled.includes(scanner.name)) continue;
    if (scanner.appliesTo(target)) applicable.push(scanner);
    else skipped.push(scanner);
  }

  return { applicable, skipped };
}
