import { describe, expect, it } from 'vitest';

import { focusOf, globToRegExp, type FocusSubject } from './focus.js';

const code = (overrides: Partial<FocusSubject> = {}): FocusSubject => ({
  kind: 'sast',
  severity: 'medium',
  ruleId: 'javascript.lang.security.audit.detect-non-literal-regexp',
  rule: { category: 'security', subcategory: [] },
  location: { path: 'src/server.ts', startLine: 3 },
  ...overrides,
});

describe('focusOf', () => {
  it('sets aside rules that are not about security, and says why', () => {
    const style = focusOf(code({ rule: { category: 'best-practice', subcategory: [] } }));
    expect(style).toMatchObject({ focus: 'noise', reasons: ['best-practice rule, not a security rule'] });
    expect(focusOf(code({ rule: { category: 'portability', subcategory: [] } })).focus).toBe('noise');
  });

  it('rates security rules likely, and audit rules maybe', () => {
    expect(focusOf(code({ rule: { category: 'security', subcategory: ['vuln'], confidence: 'high' } }))).toMatchObject({
      focus: 'likely',
      reasons: ['security rule, high confidence'],
    });
    const audit = focusOf(code({ rule: { category: 'security', subcategory: ['audit'], confidence: 'low', likelihood: 'low' } }));
    expect(audit).toMatchObject({ focus: 'maybe', reasons: ['security audit rule with low confidence'] });
  });

  it('does not call a rule noise when it says nothing about itself', () => {
    const { rule: _rule, ...bare } = code();
    expect(focusOf(bare).focus).toBe('maybe');
  });

  it('lowers code findings in tests, fixtures and examples by one level', () => {
    const inTests = focusOf(code({ location: { path: 'src/__tests__/server.ts' } }));
    expect(inTests).toMatchObject({ focus: 'maybe', reasons: ['security rule', 'in test, example or docs code'] });
    const audit = { category: 'security', subcategory: ['audit'] };
    expect(focusOf(code({ rule: audit, location: { path: 'packages/scanners/src/fixture.ts' } })).focus).toBe('noise');
    expect(focusOf(code({ location: { path: 'lib/login.spec.js' } })).focus).toBe('maybe');
  });

  it('never calls a dependency, secret or misconfiguration noise on its own', () => {
    const dependency: FocusSubject = { kind: 'sca', severity: 'low', location: { path: 'test/package-lock.json' } };
    expect(focusOf(dependency).focus).toBe('maybe');
    expect(focusOf({ kind: 'secret', severity: 'high', location: { path: 'test/key.pem' } }).focus).toBe('maybe');
    expect(focusOf({ kind: 'secret', severity: 'high', location: { path: 'config/prod.env' } }).focus).toBe('likely');
    expect(focusOf({ kind: 'iac', severity: 'critical', location: { path: 'deploy/main.tf' } }).focus).toBe('likely');
  });

  it('rates a dependency by its exploitation evidence', () => {
    const dependency: FocusSubject = { kind: 'sca', severity: 'medium', cvss: { score: 5 } };
    const exploited = focusOf(dependency, { advisory: { kev: true, kevRansomware: false } });
    expect(exploited.focus).toBe('likely');
    expect(exploited.reasons[0]).toBe('on the CISA list of exploited vulnerabilities');
    const quiet = focusOf(dependency, { advisory: { kev: false, kevRansomware: false, epss: 0.0004 } });
    expect(quiet.focus).toBe('maybe');
    expect(quiet.reasons[0]).toBe('EPSS under 0.1% chance of exploitation in 30 days');
    expect(exploited.riskScore).toBeGreaterThan(quiet.riskScore);
  });

  it('follows the overrides, with keep winning over noise', () => {
    const overrides = { noise: { paths: ['apps/web/**'] }, keep: { rules: ['*.jsx-not-internationalized'] } };
    const i18n = code({ ruleId: 'typescript.react.portability.i18next.jsx-not-internationalized', location: { path: 'apps/web/a.tsx' } });
    expect(focusOf(i18n, { overrides }).focus).toBe('likely');
    expect(focusOf(code({ location: { path: 'apps/web/b.ts' } }), { overrides })).toMatchObject({
      focus: 'noise',
      reasons: ['set aside by the focus settings (apps/web/**)'],
    });
  });
});

describe('globToRegExp', () => {
  it('spans directories only with **', () => {
    expect(globToRegExp('**/tests/**').test('tests/a.ts')).toBe(true);
    expect(globToRegExp('**/tests/**').test('pkg/tests/deep/a.ts')).toBe(true);
    expect(globToRegExp('src/*.ts').test('src/deep/a.ts')).toBe(false);
    expect(globToRegExp('**/*.test.*').test('a.test.ts')).toBe(true);
    expect(globToRegExp('a.b').test('axb')).toBe(false);
  });
});
