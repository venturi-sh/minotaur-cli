import { describe, expect, it } from 'vitest';

import { isSarif, normalizeReportedPath, parseSarif } from './sarif.js';

const context = { projectId: 'local', readSnippet: () => undefined };

function sarif(driver: Record<string, unknown>, results: unknown[]) {
  return JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver }, results }] });
}

function location(uri: string, startLine?: number, snippet?: string) {
  return [
    {
      physicalLocation: {
        artifactLocation: { uri },
        ...(startLine ? { region: { startLine, ...(snippet ? { snippet: { text: snippet } } : {}) } } : {}),
      },
    },
  ];
}

describe('isSarif', () => {
  it('recognizes SARIF by version or schema', () => {
    expect(isSarif({ version: '2.1.0', runs: [] })).toBe(true);
    expect(isSarif({ $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [] })).toBe(true);
    expect(isSarif({ results: [] })).toBe(false);
    expect(isSarif(null)).toBe(false);
  });
});

describe('parseSarif', () => {
  it('reads a code finding with its rule, location and severity', () => {
    const [finding] = parseSarif(
      sarif(
        {
          name: 'CodeQL',
          semanticVersion: '2.20.0',
          rules: [
            {
              id: 'js/sql-injection',
              shortDescription: { text: 'Database query built from user-controlled sources' },
              properties: { tags: ['security', 'external/cwe/cwe-089'], 'security-severity': '8.8' },
            },
          ],
        },
        [
          {
            ruleId: 'js/sql-injection',
            ruleIndex: 0,
            level: 'error',
            message: { text: 'This query depends on a user-provided value.' },
            locations: location('file:///workspace/routes/login.ts', 34, 'sequelize.query(sql)'),
          },
        ],
      ),
      context,
    );
    expect(finding).toMatchObject({
      kind: 'sast',
      severity: 'high',
      title: 'Database query built from user-controlled sources',
      ruleId: 'js/sql-injection',
      vulnerabilityIds: ['CWE-89'],
      location: { path: 'routes/login.ts', startLine: 34, endLine: 34, snippet: 'sequelize.query(sql)' },
      tool: { name: 'codeql', version: '2.20.0' },
    });
    expect(finding?.fingerprint).toHaveLength(64);
  });

  it('never keeps the matched text of a secret', () => {
    const [finding] = parseSarif(
      sarif({ name: 'gitleaks', rules: [{ id: 'github-pat' }] }, [
        { ruleId: 'github-pat', locations: location('config/deploy.py', 1, 'TOKEN = "ghp_abcdef"') },
      ]),
      context,
    );
    expect(finding?.kind).toBe('secret');
    expect(finding?.location).toEqual({ path: 'config/deploy.py', startLine: 1, endLine: 1 });
    expect(JSON.stringify(finding)).not.toContain('ghp_');
  });

  it('reads package details back out of Trivy and Grype messages', () => {
    const findings = parseSarif(
      sarif({ name: 'Trivy', version: '0.73.0', rules: [{ id: 'CVE-2019-10906', properties: { tags: ['vulnerability'] } }] }, [
        {
          ruleId: 'CVE-2019-10906',
          message: { text: 'Package: jinja2\nInstalled Version: 2.10\nVulnerability CVE-2019-10906\nFixed Version: 2.10.1' },
          locations: location('requirements.txt', 1),
        },
      ]),
      context,
    );
    expect(findings[0]).toMatchObject({
      kind: 'sca',
      title: 'CVE-2019-10906 in jinja2',
      vulnerabilityIds: ['CVE-2019-10906'],
      package: { name: 'jinja2', version: '2.10', fixedVersion: '2.10.1' },
    });

    const [grype] = parseSarif(
      sarif({ name: 'grype' }, [
        {
          ruleId: 'GHSA-8qvm-5x2c-j2w7-requests',
          message: { text: 'A medium vulnerability in pypi package: requests, version 2.19.0 was found at: /requirements.txt' },
        },
      ]),
      context,
    );
    expect(grype?.package).toEqual({ name: 'requests', version: '2.19.0' });
  });

  it('classifies misconfigurations as infrastructure findings', () => {
    const [finding] = parseSarif(sarif({ name: 'checkov' }, [{ ruleId: 'CKV_DOCKER_2', level: 'warning' }]), context);
    expect(finding?.kind).toBe('iac');
    expect(finding?.severity).toBe('medium');
  });

  it('gives Semgrep findings the same rule id and tool as the native adapter', () => {
    const [finding] = parseSarif(
      sarif(
        {
          name: 'Semgrep OSS',
          semanticVersion: '1.172.0',
          rules: [{ id: 'cache.semgrep-rules.javascript.express.xss', shortDescription: { text: 'Semgrep Finding: x' } }],
        },
        [{ ruleId: 'cache.semgrep-rules.javascript.express.xss', locations: location('app.js', 3) }],
      ),
      context,
    );
    expect(finding).toMatchObject({ ruleId: 'javascript.express.xss', title: 'xss', tool: { name: 'semgrep' } });
  });

  it('rates code rules from their id, tags and CWEs', () => {
    const findings = parseSarif(
      sarif(
        {
          name: 'opengrep',
          rules: [
            { id: 'javascript.lang.correctness.no-replaceall' },
            { id: 'js/sql-injection', properties: { tags: ['security'] } },
            { id: 'custom-rule', properties: { tags: ['external/cwe/cwe-079'] } },
          ],
        },
        [
          { ruleId: 'javascript.lang.correctness.no-replaceall', locations: location('a.js', 1) },
          { ruleId: 'js/sql-injection', locations: location('b.js', 1) },
          { ruleId: 'custom-rule', locations: location('c.js', 1) },
        ],
      ),
      context,
    );
    expect(findings.map((finding) => finding.rule?.category)).toEqual(['correctness', 'security', 'security']);
  });

  it('prefers the file over the report for snippets, and ignores redacted ones', () => {
    const [fromFile] = parseSarif(
      sarif({ name: 'semgrep' }, [{ ruleId: 'r', locations: location('a.js', 2, 'requires login') }]),
      { projectId: 'local', readSnippet: () => 'eval(input)' },
    );
    expect(fromFile?.location?.snippet).toBe('eval(input)');
    const [redacted] = parseSarif(
      sarif({ name: 'semgrep' }, [{ ruleId: 'r', locations: location('a.js', 2, 'requires login') }]),
      context,
    );
    expect(redacted?.location?.snippet).toBeUndefined();
  });

  it('keeps identical matches in one file apart', () => {
    const findings = parseSarif(
      sarif({ name: 'semgrep' }, [
        { ruleId: 'r', locations: location('a.js', 2) },
        { ruleId: 'r', locations: location('a.js', 2) },
      ]),
      context,
    );
    expect(new Set(findings.map((finding) => finding.fingerprint)).size).toBe(2);
  });

  it('rejects something that is not SARIF', () => {
    expect(() => parseSarif('{"runs": "no"}', context)).toThrow(/not a SARIF report/);
  });
});

describe('normalizeReportedPath', () => {
  it('strips file URIs, the sandbox mount and leading ./', () => {
    expect(normalizeReportedPath('file:///workspace/src/a%20b.ts')).toBe('src/a b.ts');
    expect(normalizeReportedPath('./src/a.ts')).toBe('src/a.ts');
    expect(normalizeReportedPath('/elsewhere/a.ts')).toBe('/elsewhere/a.ts');
  });
});
