import { describe, expect, it } from 'vitest';

import { ruleMeta } from './semgrep.js';

describe('ruleMeta', () => {
  it('keeps the rule metadata, lower-cased', () => {
    expect(
      ruleMeta('javascript.express.security.x', {
        category: 'Security',
        subcategory: ['Vuln'],
        confidence: 'HIGH',
        likelihood: 'MEDIUM',
        impact: 'HIGH',
      }),
    ).toEqual({ category: 'security', subcategory: ['vuln'], confidence: 'high', likelihood: 'medium', impact: 'high' });
  });

  it('takes the category from the rule id when the metadata has none', () => {
    expect(ruleMeta('javascript.lang.correctness.no-replaceall', {})).toEqual({ category: 'correctness', subcategory: [] });
    expect(ruleMeta('javascript.lang.security.audit.detect-non-literal-regexp', {})).toEqual({
      category: 'security',
      subcategory: ['audit'],
    });
    expect(ruleMeta('my-rule', {})).toEqual({ subcategory: [] });
    // The community rules file audit rules under `audit` but label them `vuln`.
    expect(ruleMeta('javascript.lang.security.audit.x', { category: 'security', subcategory: ['vuln'] }).subcategory).toEqual([
      'vuln',
      'audit',
    ]);
  });

  it('accepts a single subcategory', () => {
    expect(ruleMeta('r', { category: 'security', subcategory: 'audit' }).subcategory).toEqual(['audit']);
  });
});
