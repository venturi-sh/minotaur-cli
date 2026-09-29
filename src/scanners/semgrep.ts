/**
 * Semgrep adapter.
 *
 * The only source of first-party code findings in the fleet: everything else
 * looks at dependencies, configuration or credentials, while Semgrep looks at
 * the code the team actually wrote.
 *
 * Two things shape this adapter. Semgrep's registry needs the network, so the
 * community ruleset is cloned into the cache volume by the sync job and used
 * from disk. And the free tier redacts the matched source line, returning the
 * literal string "requires login" where the snippet should be, so snippets are
 * read from the workspace instead. That matters more than it sounds: snippets
 * are what make a code finding's identity survive an edit above it.
 */

import { assignOrdinals, normalizeSeverity, type Finding, type RuleMeta, type Severity } from '../core/index.js';
import { fingerprintSast } from '../core/fingerprint.js';
import { z } from 'zod';

import {
  CACHE_MOUNT,
  WORKSPACE_MOUNT,
  standardMounts,
  type DatabaseSyncOptions,
  type ScanContext,
  type ScannerAdapter,
} from './adapter.js';
import type { DetectedTarget, Language } from './detect.js';
import type { SandboxSpec } from './runtime.js';

export const SEMGREP_VERSION = '1.172.0';
export const SEMGREP_IMAGE =
  'semgrep/semgrep@sha256:65dcd4408adda7c183a6b4550cb1e9b19f7f627a6fbb7e0559bd466bedc44d7b';

const GIT_IMAGE = 'alpine/git@sha256:3b44767883ac77bddae0160cc27b6b039345e23fa3504f4159efaa32264ab57f';

const TOOL = { name: 'semgrep', version: SEMGREP_VERSION } as const;

const RULES_DIR = `${CACHE_MOUNT}/semgrep-rules`;
const RULES_REPO = 'https://github.com/semgrep/semgrep-rules';

/** Directories in the ruleset repository, keyed by the language we detected. */
const RULE_DIRECTORIES: Partial<Record<Language, readonly string[]>> = {
  javascript: ['javascript', 'typescript'],
  typescript: ['typescript', 'javascript'],
  python: ['python'],
  go: ['go'],
  ruby: ['ruby'],
  java: ['java'],
  kotlin: ['kotlin'],
  csharp: ['csharp'],
  php: ['php'],
  rust: ['rust'],
  scala: ['scala'],
  swift: ['swift'],
  c: ['c'],
  cpp: ['c'],
};

/**
 * Loading every rule in the repository costs about a minute of startup before
 * a single file is read, so only the languages actually present are loaded.
 */
export function ruleDirectoriesFor(target: DetectedTarget): string[] {
  const directories = new Set<string>();
  for (const language of target.languages) {
    for (const directory of RULE_DIRECTORIES[language] ?? []) directories.add(directory);
  }
  if (target.hasContainerfile) directories.add('dockerfile');
  if (target.hasKubernetes) directories.add('yaml');
  return [...directories].sort();
}

const resultSchema = z
  .object({
    check_id: z.string(),
    path: z.string(),
    start: z.object({ line: z.number(), col: z.number().optional() }).loose(),
    end: z.object({ line: z.number(), col: z.number().optional() }).loose(),
    extra: z
      .object({
        message: z.string().optional(),
        severity: z.string().optional(),
        lines: z.string().optional(),
        metadata: z
          .object({
            cwe: z.union([z.array(z.string()), z.string()]).optional(),
            owasp: z.union([z.array(z.string()), z.string()]).optional(),
            references: z.array(z.string()).optional(),
            confidence: z.string().optional(),
            impact: z.string().optional(),
            likelihood: z.string().optional(),
            category: z.string().optional(),
            subcategory: z.union([z.array(z.string()), z.string()]).optional(),
          })
          .loose()
          .optional(),
      })
      .loose(),
  })
  .loose();

const reportSchema = z
  .object({
    results: z.array(resultSchema).optional(),
    errors: z.array(z.object({ message: z.string().optional() }).loose()).optional(),
  })
  .loose();

export const semgrepAdapter: ScannerAdapter = {
  name: TOOL.name,
  version: TOOL.version,

  appliesTo: (target: DetectedTarget) => ruleDirectoriesFor(target).length > 0,

  spec: (context: ScanContext): SandboxSpec => {
    const configs = ruleDirectoriesFor(context.target).flatMap((directory) => [
      '--config',
      `${RULES_DIR}/${directory}`,
    ]);

    return {
      image: SEMGREP_IMAGE,
      network: 'none',
      args: [
        'semgrep',
        'scan',
        ...configs,
        '--json',
        '--quiet',
        '--metrics=off',
        '--disable-version-check',
        // Respecting .gitignore would be right for a developer running semgrep
        // locally and wrong here: an ignored build output can still be the file
        // that ships.
        '--no-git-ignore',
        '--timeout',
        '30',
        WORKSPACE_MOUNT,
      ],
      mounts: standardMounts(context),
      env: { HOME: '/tmp', TMPDIR: '/tmp', SEMGREP_SEND_METRICS: 'off' },
      timeoutMs: 20 * 60 * 1000,
      memory: '4g',
    };
  },

  /** Exit 1 is "findings were produced"; anything above that is a real failure. */
  isSuccess: (exitCode: number) => exitCode === 0 || exitCode === 1,

  databaseSync: ({ cacheVolume }: DatabaseSyncOptions): SandboxSpec[] => [
    {
      image: GIT_IMAGE,
      network: 'bridge',
      // A shallow re-clone is cheaper to reason about than a pull into a
      // directory that a previous sync may have left half-pruned.
      args: [
        'sh',
        '-c',
        `rm -rf ${RULES_DIR} && git clone --depth 1 -q ${RULES_REPO} ${RULES_DIR} && ` +
          // The repository is not purely rules: CI config, editor config and
          // rule test fixtures all live alongside, and Semgrep aborts the whole
          // scan if any file under a --config path fails to parse as a rule.
          `cd ${RULES_DIR} && rm -rf .git .github stats scripts libsonnet Pipfile Pipfile.lock Makefile ` +
          `template.yaml metadata-schema.yaml.schm .pre-commit-config.yaml && ` +
          `find . -name '*.test.yaml' -delete && find . -maxdepth 1 -name '*.yml' -delete`,
      ],
      mounts: [{ type: 'volume', source: cacheVolume, target: CACHE_MOUNT, readOnly: false }],
      env: { HOME: '/tmp' },
      timeoutMs: 10 * 60 * 1000,
    },
  ],

  cachePaths: ['semgrep-rules'],

  native: {
    binary: 'semgrep',
    defaultArgs: ['--config', 'p/default'],
    args: (root, extra) => [
      'scan',
      '--json',
      '--quiet',
      '--metrics=off',
      '--disable-version-check',
      ...extra,
      root,
    ],
  },

  parse: (stdout: string, context: ScanContext): Finding[] => parseSemgrepOutput(stdout, context, TOOL),
};

/** Semgrep's JSON report, which Opengrep writes too. */
export function parseSemgrepOutput(
  stdout: string,
  context: ScanContext,
  tool: { name: string; version: string },
): Finding[] {
  const report = reportSchema.safeParse(safeJson(stdout));
  if (!report.success) return [];

  const results = report.data.results ?? [];
  const ordinals = assignOrdinals(results, (result) => `${ruleId(result.check_id)}\u0000${relative(result.path)}`);

  return results.map((result) => {
    const rule = ruleId(result.check_id);
    const path = relative(result.path);
    const snippet = usableSnippet(result.extra.lines) ?? context.readSnippet?.(path, result.start.line, result.end.line);
    const metadata = result.extra.metadata ?? {};

    return {
      fingerprint: fingerprintSast({
        projectId: context.projectId,
        ruleId: rule,
        path,
        ...(snippet !== undefined ? { snippet } : {}),
        startLine: result.start.line,
        ordinal: ordinals.get(result) ?? 0,
      }),
      kind: 'sast',
      severity: severityOf(result),
      title: rule.split('.').pop() ?? rule,
      ...(result.extra.message !== undefined ? { description: result.extra.message } : {}),
      ruleId: rule,
      rule: ruleMeta(rule, metadata),
      vulnerabilityIds: asArray(metadata.cwe),
      location: {
        path,
        startLine: result.start.line,
        endLine: result.end.line,
        ...(snippet !== undefined ? { snippet } : {}),
      },
      references: (metadata.references ?? []).slice(0, 10),
      tool,
      tools: [tool],
      raw: result,
    };
  });
}

/**
 * Semgrep derives rule ids from the config path, so a rule loaded from
 * `/cache/semgrep-rules/python/...` is called `cache.semgrep-rules.python...`.
 * Left alone, moving the cache mount would change every fingerprint. Opengrep's
 * copy of the same rules lives in `opengrep-rules`, and keeps the same ids.
 */
/** The categories the community rules are filed under, which the rule id repeats as a path segment. */
const RULE_CATEGORIES = ['security', 'correctness', 'best-practice', 'maintainability', 'performance', 'portability', 'compatibility'];

/**
 * The rule's own metadata, lower-cased. A rule without a category gets the one
 * its id is filed under, such as `javascript.lang.security.audit.x`.
 */
export function ruleMeta(
  rule: string,
  metadata: { category?: string | undefined; subcategory?: string | string[] | undefined; confidence?: string | undefined; likelihood?: string | undefined; impact?: string | undefined },
): RuleMeta {
  const segments = rule.toLowerCase().split('.');
  const category = metadata.category?.toLowerCase() ?? segments.find((segment) => RULE_CATEGORIES.includes(segment));
  const subcategory = asArray(metadata.subcategory).map((item) => item.toLowerCase());
  if (category === 'security' && segments.includes('audit') && !subcategory.includes('audit')) subcategory.push('audit');
  const lower = (value: string | undefined) => value?.toLowerCase();
  return {
    ...(category ? { category } : {}),
    subcategory,
    ...(metadata.confidence ? { confidence: lower(metadata.confidence) } : {}),
    ...(metadata.likelihood ? { likelihood: lower(metadata.likelihood) } : {}),
    ...(metadata.impact ? { impact: lower(metadata.impact) } : {}),
  };
}

export function ruleId(checkId: string): string {
  for (const marker of ['semgrep-rules.', 'opengrep-rules.']) {
    const index = checkId.indexOf(marker);
    if (index !== -1) return checkId.slice(index + marker.length);
  }
  return checkId;
}

/** The free tier substitutes this for the matched source. */
function usableSnippet(lines: string | undefined): string | undefined {
  if (lines === undefined) return undefined;
  const trimmed = lines.trim();
  if (trimmed.length === 0 || trimmed === 'requires login') return undefined;
  return trimmed;
}

/**
 * Semgrep's own severity is coarse. `impact` is a better guide to whether a
 * finding is worth waking someone up for, so a high-impact error is promoted.
 */
function severityOf(result: z.infer<typeof resultSchema>): Severity {
  const base = normalizeSeverity(result.extra.severity);
  if (base === 'high' && result.extra.metadata?.impact?.toUpperCase() === 'HIGH') return 'critical';
  return base;
}

function asArray(value: string[] | string | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function relative(path: string): string {
  const prefix = `${WORKSPACE_MOUNT}/`;
  return path.startsWith(prefix) ? path.slice(prefix.length) : path;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
