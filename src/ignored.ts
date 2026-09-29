/**
 * Which finding paths git ignores, so findings in dependencies, build output
 * and local caches stay out of the list. Scanners still look at those files: a
 * secret in an ignored config file must still keep that file away from the model.
 */

import { spawn } from 'node:child_process';

/** A path no ignore rule names, so it is only ignored when the whole directory is. */
const PROBE = '.minotaur-probe-3f9a1c2e';

/**
 * The given repository-relative paths that git ignores. Null when the directory
 * is not in a git work tree, or is itself ignored by an enclosing repository,
 * since the person asked to scan it anyway.
 */
export async function gitIgnored(root: string, paths: readonly string[]): Promise<Set<string> | null> {
  const output = await checkIgnore(root, [PROBE, ...paths]);
  if (output === null) return null;
  const ignored = new Set(output.split('\0').filter(Boolean));
  if (ignored.has(PROBE)) return null;
  return ignored;
}

/** `git check-ignore` exits 1 when nothing is ignored and 128 outside a work tree. */
function checkIgnore(cwd: string, paths: readonly string[]): Promise<string | null> {
  return new Promise((resolve) => {
    const child = spawn('git', ['check-ignore', '-z', '--stdin'], { cwd, stdio: ['pipe', 'pipe', 'ignore'] });
    const chunks: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    child.on('error', () => resolve(null));
    child.on('close', (code) => resolve(code === 0 || code === 1 ? Buffer.concat(chunks).toString('utf8') : null));
    child.stdin.on('error', () => resolve(null));
    child.stdin.end(paths.map((path) => `${path}\0`).join(''));
  });
}
