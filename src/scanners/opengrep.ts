/**
 * Opengrep adapter, for the CLI only.
 *
 * Opengrep is the open-source fork of Semgrep CE. It ships as one standalone
 * binary, which is what lets the CLI download it instead of asking for a
 * Python install, and it writes Semgrep's JSON report, so parsing is shared.
 * The platform keeps running Semgrep in its sandbox; this adapter is not part
 * of the container fleet.
 */

import type { Finding } from '../core/index.js';

import type { ScanContext, ScannerAdapter } from './adapter.js';
import type { DetectedTarget } from './detect.js';
import type { SandboxSpec } from './runtime.js';
import { parseSemgrepOutput, ruleDirectoriesFor } from './semgrep.js';

export const OPENGREP_VERSION = '1.30.0';

const TOOL = { name: 'opengrep', version: OPENGREP_VERSION } as const;

export const opengrepAdapter: ScannerAdapter = {
  name: TOOL.name,
  version: TOOL.version,

  appliesTo: (target: DetectedTarget) => ruleDirectoriesFor(target).length > 0,

  spec: (): SandboxSpec => {
    throw new Error('opengrep runs only on the local machine; the platform uses semgrep');
  },

  isSuccess: (exitCode: number) => exitCode === 0 || exitCode === 1,

  native: {
    binary: 'opengrep',
    args: (root, extra) => ['scan', '--json', '--quiet', '--disable-version-check', '--timeout', '30', ...extra, root],
  },

  parse: (stdout: string, context: ScanContext): Finding[] => parseSemgrepOutput(stdout, context, TOOL),
};
