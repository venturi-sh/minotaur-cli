/**
 * OSV-Scanner adapter.
 *
 * Overlaps heavily with Trivy on dependency scanning, which is deliberate:
 * OSV-Scanner queries the OSV database directly and is often ahead of Trivy on
 * ecosystems outside the container world, while Trivy is stronger on OS
 * packages. Where they agree, correlation collapses the duplicate and the
 * agreement itself becomes a confidence signal.
 *
 * OSV reports vulnerabilities under their GHSA or PYSEC identifiers with the
 * CVE listed as an alias, so this adapter carries the whole alias set through
 * rather than picking one.
 */

import { normalizeSeverity, type Finding, type Severity } from '../core/index.js';
import { fingerprintSca } from '../core/fingerprint.js';
import { z } from 'zod';

import {
  CACHE_MOUNT,
  WORKSPACE_MOUNT,
  standardMounts,
  type DatabaseSyncOptions,
  type ScanContext,
  type ScannerAdapter,
} from './adapter.js';
import type { DetectedTarget } from './detect.js';
import type { SandboxSpec } from './runtime.js';

export const OSV_VERSION = '2.5.0';
export const OSV_IMAGE =
  'ghcr.io/google/osv-scanner@sha256:5b8b38e45bb2c5c4976f0f1f07860551ea6e1f235f642cf215f74d266fec2c1b';

const TOOL = { name: 'osv-scanner', version: OSV_VERSION } as const;

/**
 * OSV-Scanner resolves its offline databases relative to the user cache
 * directory, so pointing XDG_CACHE_HOME at the shared volume is what makes a
 * no-network scan possible.
 */
const OFFLINE_ENV = { HOME: '/tmp', TMPDIR: '/tmp', XDG_CACHE_HOME: CACHE_MOUNT } as const;

/**
 * ConanCenter is the one ecosystem OSV-Scanner extracts but publishes no
 * offline database for, and the fetch 404 aborts the entire extraction phase
 * instead of just that ecosystem. Leaving it enabled means a single conan.lock
 * anywhere in a repository costs us every dependency finding in it, so the
 * extractor is switched off rather than handled after the fact.
 */
const DISABLED_PLUGINS = ['cpp/conanlock'] as const;

const disablePluginArgs = (): string[] =>
  DISABLED_PLUGINS.flatMap((plugin) => ['--experimental-disable-plugins', plugin]);

/**
 * Ecosystems with a downloadable offline database, which is also the set the
 * priming workspace covers. Checked individually at startup because the cache
 * is per-ecosystem: a volume holding only npm looks populated from the outside
 * but fails every scan that touches anything else.
 */
const OFFLINE_ECOSYSTEMS = [
  'CRAN',
  'Go',
  'Hackage',
  'Hex',
  'Maven',
  'NuGet',
  'Packagist',
  'Pub',
  'PyPI',
  'RubyGems',
  'SwiftURL',
  'crates.io',
  'npm',
] as const;

/**
 * Minimal lockfiles, one per ecosystem, used only to make the database sync
 * download the right offline databases.
 *
 * OSV-Scanner only downloads databases for ecosystems it can actually see, and
 * in `--offline` mode an ecosystem whose database is absent is a hard error
 * that fails the whole scan rather than just that ecosystem. So this list has
 * to stay ahead of what we might encounter: every ecosystem missing here is a
 * repository that returns no dependency findings at all.
 *
 * Each lives in its own directory so one unparseable manifest cannot stop the
 * others from being extracted.
 */
const PRIMING_FILES: Readonly<Record<string, string>> = {
  'npm/package-lock.json': JSON.stringify(
    {
      name: 'priming',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': { name: 'priming', version: '1.0.0' },
        'node_modules/lodash': { version: '4.17.15' },
      },
    },
    null,
    2,
  ),
  'pypi/requirements.txt': 'flask==0.12.2\n',
  'go/go.mod': 'module priming\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.0\n',
  'rubygems/Gemfile.lock': 'GEM\n  specs:\n    rack (2.0.1)\n\nDEPENDENCIES\n  rack\n',
  'cargo/Cargo.lock':
    'version = 3\n\n[[package]]\nname = "smallvec"\nversion = "0.6.13"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
  'maven/pom.xml': [
    '<project xmlns="http://maven.apache.org/POM/4.0.0">',
    '  <modelVersion>4.0.0</modelVersion>',
    '  <groupId>dev.minotaur</groupId>',
    '  <artifactId>priming</artifactId>',
    '  <version>1.0.0</version>',
    '  <dependencies>',
    '    <dependency>',
    '      <groupId>org.apache.logging.log4j</groupId>',
    '      <artifactId>log4j-core</artifactId>',
    '      <version>2.14.1</version>',
    '    </dependency>',
    '  </dependencies>',
    '</project>',
    '',
  ].join('\n'),
  'nuget/packages.lock.json': JSON.stringify(
    {
      version: 1,
      dependencies: {
        'net6.0': {
          'Newtonsoft.Json': { type: 'Direct', requested: '[12.0.1, )', resolved: '12.0.1' },
        },
      },
    },
    null,
    2,
  ),
  'packagist/composer.lock': JSON.stringify(
    {
      'content-hash': 'priming',
      packages: [{ name: 'guzzlehttp/guzzle', version: '6.5.0' }],
      'packages-dev': [],
    },
    null,
    2,
  ),
  // The checksums have to look real: OSV-Scanner treats a short one as a git
  // commit and filters the package out before it triggers a database fetch.
  'hex/mix.lock': [
    '%{',
    '  "plug": {:hex, :plug, "1.11.0", ' +
      '"1b4b3b0c8e0e4b9e2b5b9b8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d", ' +
      '[:mix], [], "hexpm", ' +
      '"0d1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"},',
    '}',
    '',
  ].join('\n'),
  'pub/pubspec.lock': [
    'packages:',
    '  http:',
    '    dependency: "direct main"',
    '    description:',
    '      name: http',
    '      url: "https://pub.dartlang.org"',
    '    source: hosted',
    '    version: "0.13.0"',
    'sdks:',
    '  dart: ">=2.12.0 <3.0.0"',
    '',
  ].join('\n'),
  'cran/renv.lock': JSON.stringify(
    {
      R: { Version: '4.1.0', Repositories: [{ Name: 'CRAN', URL: 'https://cloud.r-project.org' }] },
      Packages: {
        commonmark: {
          Package: 'commonmark',
          Version: '1.7',
          Source: 'Repository',
          Repository: 'CRAN',
        },
      },
    },
    null,
    2,
  ),
  'swift/Package.resolved': JSON.stringify(
    {
      version: 2,
      pins: [
        {
          identity: 'swift-nio',
          kind: 'remoteSourceControl',
          location: 'https://github.com/apple/swift-nio.git',
          state: { revision: '0000000000000000000000000000000000000000', version: '2.40.0' },
        },
      ],
    },
    null,
    2,
  ),
  'haskell/cabal.project.freeze': 'constraints: any.aeson ==1.5.6.0\n',
};

const severitySchema = z.object({ type: z.string(), score: z.string() }).loose();

const vulnerabilitySchema = z
  .object({
    id: z.string(),
    aliases: z.array(z.string()).optional(),
    related: z.array(z.string()).optional(),
    summary: z.string().optional(),
    details: z.string().optional(),
    severity: z.array(severitySchema).optional(),
    references: z.array(z.object({ url: z.string() }).loose()).optional(),
    affected: z
      .array(
        z
          .object({
            ranges: z
              .array(
                z
                  .object({
                    type: z.string().optional(),
                    events: z.array(z.record(z.string(), z.string())).optional(),
                  })
                  .loose(),
              )
              .optional(),
          })
          .loose(),
      )
      .optional(),
    database_specific: z.object({ severity: z.string().optional() }).loose().optional(),
  })
  .loose();

const groupSchema = z
  .object({
    ids: z.array(z.string()).optional(),
    aliases: z.array(z.string()).optional(),
    max_severity: z.string().optional(),
  })
  .loose();

const reportSchema = z
  .object({
    results: z
      .array(
        z
          .object({
            source: z.object({ path: z.string(), type: z.string().optional() }).loose(),
            packages: z
              .array(
                z
                  .object({
                    package: z
                      .object({
                        name: z.string(),
                        version: z.string().optional(),
                        ecosystem: z.string().optional(),
                      })
                      .loose(),
                    vulnerabilities: z.array(vulnerabilitySchema).optional(),
                    groups: z.array(groupSchema).optional(),
                  })
                  .loose(),
              )
              .optional(),
          })
          .loose(),
      )
      .optional(),
  })
  .loose();

export const osvAdapter: ScannerAdapter = {
  name: TOOL.name,
  version: TOOL.version,

  appliesTo: (target: DetectedTarget) => target.ecosystems.length > 0,

  spec: (context: ScanContext): SandboxSpec => ({
    image: OSV_IMAGE,
    network: 'none',
    args: [
      'scan',
      'source',
      '--recursive',
      '--offline',
      '--format',
      'json',
      // Projects that do not commit a lockfile usually gitignore it, so the one
      // the resolution stage just generated is invisible to OSV-Scanner's
      // default behaviour. Skipping it reports zero dependency findings on
      // exactly the repositories that most need them.
      '--no-ignore',
      // Without this a directory holding only manifests, or one where every
      // lockfile sits in a subdirectory we did not resolve, exits as an error
      // rather than an empty result.
      '--allow-no-lockfiles',
      ...disablePluginArgs(),
      '--verbosity',
      'error',
      WORKSPACE_MOUNT,
    ],
    mounts: standardMounts(context),
    env: OFFLINE_ENV,
    timeoutMs: 10 * 60 * 1000,
  }),

  /** Exit 1 means vulnerabilities were found, which is a successful scan. */
  isSuccess: (exitCode: number) => exitCode === 0 || exitCode === 1,

  primingFiles: PRIMING_FILES,

  native: {
    binary: 'osv-scanner',
    args: (root, extra) => [
      'scan',
      'source',
      '--recursive',
      '--format',
      'json',
      '--allow-no-lockfiles',
      '--verbosity',
      'error',
      ...extra,
      root,
    ],
  },

  cachePaths: OFFLINE_ECOSYSTEMS.map((ecosystem) => `osv-scalibr/${ecosystem}/all.zip`),

  // The priming workspace is what tells OSV-Scanner which databases to fetch:
  // it only downloads the ecosystems it can actually see in the target.
  databaseSync: ({ cacheVolume, primingDir }: DatabaseSyncOptions): SandboxSpec[] => [
    {
      image: OSV_IMAGE,
      network: 'bridge',
      args: [
        'scan',
        'source',
        '--recursive',
        '--download-offline-databases',
        '--offline',
        '--allow-no-lockfiles',
        // The priming manifests are pinned direct dependencies; resolving them
        // transitively adds minutes and cannot reach a registry under --offline
        // anyway.
        '--no-resolve',
        ...disablePluginArgs(),
        '--format',
        'json',
        WORKSPACE_MOUNT,
      ],
      mounts: [
        { type: 'bind', source: primingDir, target: WORKSPACE_MOUNT, readOnly: true },
        { type: 'volume', source: cacheVolume, target: CACHE_MOUNT, readOnly: false },
      ],
      env: OFFLINE_ENV,
      timeoutMs: 30 * 60 * 1000,
    },
  ],

  parse(stdout: string, context: ScanContext): Finding[] {
    const report = reportSchema.safeParse(safeJson(stdout));
    if (!report.success) return [];

    const findings: Finding[] = [];

    for (const result of report.data.results ?? []) {
      const sourcePath = relative(result.source.path);

      for (const entry of result.packages ?? []) {
        const pkg = entry.package;
        const purl = buildPurl(pkg.ecosystem, pkg.name, pkg.version);
        const scores = maxSeverityByGroup(entry.groups ?? []);

        for (const vulnerability of entry.vulnerabilities ?? []) {
          const ids = [
            vulnerability.id,
            ...(vulnerability.aliases ?? []),
            ...(vulnerability.related ?? []),
          ];
          const score = scores.get(vulnerability.id);
          const fixedVersion = firstFixedVersion(vulnerability);

          findings.push({
            fingerprint: fingerprintSca({
              projectId: context.projectId,
              vulnerabilityId: vulnerability.id,
              ...(purl !== undefined ? { purl } : {}),
              ...(pkg.ecosystem !== undefined ? { ecosystem: pkg.ecosystem } : {}),
              packageName: pkg.name,
            }),
            kind: 'sca',
            severity: severityOf(vulnerability, score),
            title: vulnerability.summary ?? `${vulnerability.id} in ${pkg.name}`,
            ...(vulnerability.details !== undefined ? { description: vulnerability.details } : {}),
            ruleId: vulnerability.id,
            vulnerabilityIds: [...new Set(ids)].sort(),
            ...(score !== undefined ? { cvss: cvssOf(vulnerability, score) } : {}),
            location: { path: sourcePath },
            package: {
              name: pkg.name,
              ...(pkg.version !== undefined ? { version: pkg.version } : {}),
              ...(pkg.ecosystem !== undefined ? { ecosystem: pkg.ecosystem } : {}),
              ...(purl !== undefined ? { purl } : {}),
              ...(fixedVersion !== undefined ? { fixedVersion } : {}),
            },
            references: (vulnerability.references ?? []).map((reference) => reference.url).slice(0, 10),
            tool: TOOL,
            tools: [TOOL],
            raw: vulnerability,
          });
        }
      }
    }

    return findings;
  },
};

function severityOf(
  vulnerability: z.infer<typeof vulnerabilitySchema>,
  score: number | undefined,
): Severity {
  const stated = vulnerability.database_specific?.severity;
  if (stated) return normalizeSeverity(stated);
  if (score === undefined) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

function cvssOf(vulnerability: z.infer<typeof vulnerabilitySchema>, score: number) {
  const entry = vulnerability.severity?.find((item) => item.type.startsWith('CVSS'));
  return {
    score,
    ...(entry !== undefined ? { vector: entry.score, version: entry.type } : {}),
    source: 'osv',
  };
}

/** `groups` is where OSV puts the resolved score for each vulnerability in a package. */
function maxSeverityByGroup(groups: readonly z.infer<typeof groupSchema>[]): Map<string, number> {
  const scores = new Map<string, number>();
  for (const group of groups) {
    const value = Number.parseFloat(group.max_severity ?? '');
    if (!Number.isFinite(value)) continue;
    for (const id of group.ids ?? []) scores.set(id, value);
  }
  return scores;
}

function firstFixedVersion(vulnerability: z.infer<typeof vulnerabilitySchema>): string | undefined {
  for (const affected of vulnerability.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event['fixed'] !== undefined) return event['fixed'];
      }
    }
  }
  return undefined;
}

function buildPurl(
  ecosystem: string | undefined,
  name: string,
  version: string | undefined,
): string | undefined {
  const type = purlType(ecosystem);
  if (type === undefined) return undefined;
  return `pkg:${type}/${name}${version !== undefined ? `@${version}` : ''}`;
}

const PURL_TYPES: Readonly<Record<string, string>> = {
  npm: 'npm',
  pypi: 'pypi',
  go: 'golang',
  rubygems: 'gem',
  maven: 'maven',
  'crates.io': 'cargo',
  nuget: 'nuget',
  packagist: 'composer',
  hex: 'hex',
  pub: 'pub',
};

function purlType(ecosystem: string | undefined): string | undefined {
  if (ecosystem === undefined) return undefined;
  // OSV qualifies some ecosystems with a distribution, as in "Alpine:v3.18".
  const base = ecosystem.split(':')[0]?.toLowerCase() ?? '';
  return PURL_TYPES[base];
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
