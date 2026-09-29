import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { detectReportFormat, isInstalled, parseReport, remapRoot } from './local.js';

let root: string;
beforeEach(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), 'minotaur-local-')));
  await mkdir(join(root, 'routes'));
  await writeFile(join(root, 'routes', 'login.ts'), "import db from '../db';\nconst q = `SELECT * FROM users WHERE email = '${req.body.email}'`;\ndb.query(q);\n");
});
afterEach(() => rm(root, { recursive: true, force: true }));

function semgrepReport(path: string) {
  return JSON.stringify({
    version: '1.172.0',
    results: [
      {
        check_id: 'cache.semgrep-rules.javascript.sequelize.security.audit.sequelize-injection-express',
        path,
        start: { line: 2, col: 1 },
        end: { line: 2, col: 80 },
        extra: { message: 'SQL built from request data', severity: 'ERROR', lines: 'requires login', metadata: {} },
      },
    ],
    errors: [],
    paths: { scanned: [path] },
  });
}

describe('detectReportFormat', () => {
  it('tells the supported formats apart by shape', () => {
    expect(detectReportFormat(JSON.stringify({ version: '2.1.0', runs: [] }))).toBe('sarif');
    expect(detectReportFormat(semgrepReport('a.ts'))).toBe('semgrep');
    expect(detectReportFormat(JSON.stringify({ results: [], errors: [], paths: { scanned: [] } }))).toBe('semgrep');
    expect(detectReportFormat(JSON.stringify({ SchemaVersion: 2, Results: [] }))).toBe('trivy');
    expect(detectReportFormat(JSON.stringify({ matches: [], descriptor: { name: 'grype' } }))).toBe('grype');
    expect(detectReportFormat(JSON.stringify({ results: [{ source: { path: 'a' }, packages: [] }] }))).toBe('osv-scanner');
    expect(detectReportFormat(JSON.stringify({ check_type: 'dockerfile', results: {} }))).toBe('checkov');
    expect(detectReportFormat(JSON.stringify([{ check_type: 'terraform' }]))).toBe('checkov');
    expect(detectReportFormat('{"DetectorName":"Github","SourceMetadata":{}}\n{"DetectorName":"AWS"}')).toBe('trufflehog');
    expect(detectReportFormat('not json')).toBeNull();
    expect(detectReportFormat('{"hello": 1}')).toBeNull();
  });
});

describe('parseReport', () => {
  it('gives a report with absolute paths the same findings as one run in the sandbox', async () => {
    const native = await parseReport(semgrepReport(join(root, 'routes', 'login.ts')), root);
    const sandboxed = await parseReport(semgrepReport('/workspace/routes/login.ts'), root);
    const relative = await parseReport(semgrepReport('routes/login.ts'), root);

    expect(native.format).toBe('semgrep');
    expect(native.findings[0]?.location?.path).toBe('routes/login.ts');
    expect(native.findings[0]?.location?.snippet).toContain('SELECT * FROM users');
    expect(native.findings[0]?.fingerprint).toBe(sandboxed.findings[0]?.fingerprint);
    expect(relative.findings[0]?.fingerprint).toBe(sandboxed.findings[0]?.fingerprint);
  });

  it('parses SARIF through the same path handling', async () => {
    const report = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'semgrep', rules: [{ id: 'r' }] } },
          results: [{ ruleId: 'r', locations: [{ physicalLocation: { artifactLocation: { uri: `file://${root}/routes/login.ts` }, region: { startLine: 2 } } }] }],
        },
      ],
    });
    const { format, findings } = await parseReport(report, root);
    expect(format).toBe('sarif');
    expect(findings[0]?.location?.path).toBe('routes/login.ts');
  });

  it('refuses a report it does not recognize', async () => {
    await expect(parseReport('{"hello": 1}', root)).rejects.toThrow(/unrecognized report format/);
  });
});

describe('remapRoot', () => {
  it('rewrites plain and JSON-escaped forms of the root, and leaves lookalikes alone', async () => {
    const text = `${root}/a.ts ${root.replaceAll('/', '\\/')}\\/b.ts ${root}-other/c.ts`;
    expect(await remapRoot(text, root)).toBe(`/workspace/a.ts /workspace/b.ts ${root}-other/c.ts`);
  });
});

describe('isInstalled', () => {
  it('finds an executable on the given PATH', async () => {
    const bin = join(root, 'bin');
    await mkdir(bin);
    await writeFile(join(bin, 'fake-scanner'), '#!/bin/sh\n');
    await chmod(join(bin, 'fake-scanner'), 0o755);
    expect(await isInstalled('fake-scanner', bin)).toBe(true);
    expect(await isInstalled('missing-scanner', bin)).toBe(false);
  });
});
