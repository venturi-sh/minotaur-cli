/**
 * Target detection.
 *
 * Walks a workspace once and records what is actually in it, so that each
 * scanner can be asked whether it has anything to do. Running Checkov over a
 * repository with no infrastructure code, or OSV-Scanner over one with no
 * dependency manifests, wastes a container start and produces a scan task whose
 * "0 findings" means nothing.
 *
 * Detection runs on the host rather than in a container: it is a directory
 * walk, and paying container startup to list files would cost more than the
 * walk itself.
 */

import { readdir, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';

/** Directories that never contain first-party code worth scanning. */
const IGNORED_DIRECTORIES = new Set([
  '.git',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'target',
  '.next',
  '.nuxt',
  '.venv',
  'venv',
  '__pycache__',
  '.terraform',
  '.gradle',
  '.idea',
  '.turbo',
  'coverage',
]);

export const ECOSYSTEMS = ['npm', 'pypi', 'go', 'rubygems', 'maven', 'cargo', 'nuget'] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];

interface EcosystemSignature {
  manifests: string[];
  lockfiles: string[];
  /** Whether we know how to generate the lockfile when it is missing. */
  resolvable: boolean;
}

const SIGNATURES: Record<Ecosystem, EcosystemSignature> = {
  npm: {
    manifests: ['package.json'],
    lockfiles: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json'],
    resolvable: true,
  },
  pypi: {
    manifests: ['requirements.txt', 'pyproject.toml', 'setup.py'],
    lockfiles: ['poetry.lock', 'Pipfile.lock', 'uv.lock', 'requirements.lock'],
    resolvable: false,
  },
  go: { manifests: ['go.mod'], lockfiles: ['go.sum'], resolvable: false },
  rubygems: { manifests: ['Gemfile'], lockfiles: ['Gemfile.lock'], resolvable: false },
  maven: { manifests: ['pom.xml', 'build.gradle'], lockfiles: [], resolvable: false },
  cargo: { manifests: ['Cargo.toml'], lockfiles: ['Cargo.lock'], resolvable: false },
  nuget: { manifests: ['*.csproj'], lockfiles: ['packages.lock.json'], resolvable: false },
};

const IAC_EXTENSIONS = new Set(['.tf', '.tfvars']);
const IAC_FILENAMES = new Set(['cloudformation.yaml', 'cloudformation.yml', 'serverless.yml']);
const CONTAINER_FILENAMES = new Set(['dockerfile', 'containerfile', 'docker-compose.yml', 'docker-compose.yaml']);

export const LANGUAGES = [
  'javascript', 'typescript', 'python', 'go', 'ruby', 'java',
  'kotlin', 'csharp', 'php', 'rust', 'c', 'cpp', 'scala', 'swift',
] as const;
export type Language = (typeof LANGUAGES)[number];

const LANGUAGE_BY_EXTENSION: Readonly<Record<string, Language>> = {
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript',
  '.py': 'python', '.go': 'go', '.rb': 'ruby',
  '.java': 'java', '.kt': 'kotlin', '.cs': 'csharp',
  '.php': 'php', '.rs': 'rust',
  '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.hpp': 'cpp', '.cc': 'cpp',
  '.scala': 'scala', '.swift': 'swift',
};


export interface EcosystemPresence {
  ecosystem: Ecosystem;
  /** Workspace-relative directories containing a manifest. */
  manifestDirs: string[];
  hasLockfile: boolean;
  /** A manifest with no lockfile, in an ecosystem we can resolve. */
  needsResolution: boolean;
}

export interface DetectedTarget {
  ecosystems: EcosystemPresence[];
  /** Languages with at least one source file, driving which rulesets load. */
  languages: Language[];
  hasIac: boolean;
  hasContainerfile: boolean;
  hasKubernetes: boolean;
  hasCode: boolean;
  fileCount: number;
}

/** A one-line description of what was found, for the scan log. */
export function describeTarget(target: DetectedTarget): string {
  const parts: string[] = [`${target.fileCount} files`];
  if (target.languages.length > 0) parts.push(target.languages.join(', '));
  if (target.ecosystems.length > 0) {
    parts.push(target.ecosystems.map((entry) => entry.ecosystem).join(', '));
  }
  if (target.hasIac) parts.push('iac');
  if (target.hasContainerfile) parts.push('containers');
  return parts.join('; ');
}

export function ecosystemsNeedingResolution(target: DetectedTarget): EcosystemPresence[] {
  return target.ecosystems.filter((entry) => entry.needsResolution);
}

export function hasDependencyManifests(target: DetectedTarget): boolean {
  return target.ecosystems.length > 0;
}

export async function detectTarget(workspace: string): Promise<DetectedTarget> {
  const manifestDirs = new Map<Ecosystem, Set<string>>();
  const lockfilesFound = new Set<Ecosystem>();

  const languageCounts = new Map<Language, number>();

  let hasIac = false;
  let hasContainerfile = false;
  let hasKubernetes = false;
  let hasCode = false;
  let fileCount = 0;

  await walk(workspace, workspace, (absolute, name, directory) => {
    fileCount += 1;
    const lower = name.toLowerCase();
    const extension = lower.includes('.') ? lower.slice(lower.lastIndexOf('.')) : '';
    const relativeDir = relative(workspace, directory) || '.';

    for (const ecosystem of ECOSYSTEMS) {
      const signature = SIGNATURES[ecosystem];
      if (matches(name, signature.manifests)) {
        const dirs = manifestDirs.get(ecosystem) ?? new Set<string>();
        dirs.add(relativeDir);
        manifestDirs.set(ecosystem, dirs);
      }
      if (matches(name, signature.lockfiles)) {
        lockfilesFound.add(ecosystem);
      }
    }

    if (IAC_EXTENSIONS.has(extension) || IAC_FILENAMES.has(lower)) hasIac = true;
    if (CONTAINER_FILENAMES.has(lower) || lower.startsWith('dockerfile.')) hasContainerfile = true;

    const language = LANGUAGE_BY_EXTENSION[extension];
    if (language !== undefined) {
      hasCode = true;
      languageCounts.set(language, (languageCounts.get(language) ?? 0) + 1);
    }

    // Kubernetes manifests have no distinguishing name, so this is a cheap
    // heuristic; Trivy and Checkov both do proper content sniffing themselves.
    if ((extension === '.yaml' || extension === '.yml') && /(^|\/)(k8s|kubernetes|manifests|charts)(\/|$)/.test(relativeDir)) {
      hasKubernetes = true;
    }
    void absolute;
  });

  const ecosystems: EcosystemPresence[] = [...manifestDirs.entries()].map(([ecosystem, dirs]) => {
    const hasLockfile = lockfilesFound.has(ecosystem);
    return {
      ecosystem,
      manifestDirs: [...dirs].sort(),
      hasLockfile,
      needsResolution: !hasLockfile && SIGNATURES[ecosystem].resolvable,
    };
  });

  // A single file in a language is enough to load its rules. Loading a ruleset
  // that finds nothing costs seconds; skipping one that would have found
  // something costs a vulnerability.
  const languages = [...languageCounts.keys()].sort();

  return {
    ecosystems: ecosystems.sort((a, b) => a.ecosystem.localeCompare(b.ecosystem)),
    languages,
    hasIac,
    hasContainerfile,
    hasKubernetes,
    hasCode,
    fileCount,
  };
}

function matches(name: string, patterns: readonly string[]): boolean {
  for (const pattern of patterns) {
    if (pattern.startsWith('*.')) {
      if (name.toLowerCase().endsWith(pattern.slice(1).toLowerCase())) return true;
    } else if (name.toLowerCase() === pattern.toLowerCase()) {
      return true;
    }
  }
  return false;
}

async function walk(
  root: string,
  directory: string,
  visit: (absolute: string, name: string, directory: string) => void,
): Promise<void> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const absolute = join(directory, entry.name);

    if (entry.isDirectory()) {
      if (IGNORED_DIRECTORIES.has(entry.name)) continue;
      await walk(root, absolute, visit);
      continue;
    }

    if (entry.isSymbolicLink()) {
      // Follow only links that stay inside the workspace, so a repository
      // cannot point the walk at the host filesystem.
      try {
        const target = await stat(absolute);
        if (target.isDirectory()) continue;
      } catch {
        continue;
      }
    }

    visit(absolute, entry.name, directory);
  }
}
