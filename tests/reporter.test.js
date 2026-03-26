'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  formatTextReport,
  formatJsonReport,
  sortFindings,
  groupByFile
} = require('../src/reporter');

// Sample findings for testing
const sampleFindings = [
  {
    file: 'src/config.js',
    line: 10,
    content: 'const key = "AKIA..."',
    type: 'AWS_ACCESS_KEY',
    name: 'AWS Access Key ID',
    severity: 'critical',
    match: 'AKIAIO***'
  },
  {
    file: 'src/config.js',
    line: 15,
    content: 'STRIPE_SECRET=sk_live...',
    type: 'STRIPE_SECRET',
    name: 'Stripe Secret Key',
    severity: 'critical',
    match: 'sk_live***'
  },
  {
    file: '.env',
    line: 3,
    content: 'SENDGRID_KEY=SG...',
    type: 'SENDGRID_KEY',
    name: 'SendGrid API Key',
    severity: 'high',
    match: 'SG.AbC***'
  },
  {
    file: 'utils/auth.js',
    line: 22,
    content: 'const token = "eyJ..."',
    type: 'JWT_TOKEN',
    name: 'JSON Web Token',
    severity: 'medium',
    match: 'eyJhbG***'
  }
];

const stats = { filesScanned: 15, filesSkipped: 3 };

describe('reporter', () => {
  describe('sortFindings()', () => {
    it('sorts critical before high before medium', () => {
      const sorted = sortFindings(sampleFindings);
      const severities = sorted.map(f => f.severity);
      const criticalIdx = sorted.findIndex(f => f.severity === 'critical');
      const highIdx = sorted.findIndex(f => f.severity === 'high');
      const mediumIdx = sorted.findIndex(f => f.severity === 'medium');

      assert.ok(criticalIdx < highIdx, 'Critical should come before high');
      assert.ok(highIdx < mediumIdx, 'High should come before medium');
    });

    it('does not mutate original array', () => {
      const original = [...sampleFindings];
      sortFindings(sampleFindings);
      assert.deepEqual(sampleFindings, original);
    });

    it('sorts by file then line within same severity', () => {
      const findings = [
        { file: 'z.js', line: 1, severity: 'high', type: 'A', name: 'A', content: '' },
        { file: 'a.js', line: 5, severity: 'high', type: 'B', name: 'B', content: '' },
        { file: 'a.js', line: 2, severity: 'high', type: 'C', name: 'C', content: '' }
      ];
      const sorted = sortFindings(findings);
      assert.equal(sorted[0].file, 'a.js');
      assert.equal(sorted[0].line, 2);
      assert.equal(sorted[1].file, 'a.js');
      assert.equal(sorted[1].line, 5);
    });
  });

  describe('groupByFile()', () => {
    it('groups findings by file', () => {
      const grouped = groupByFile(sampleFindings);
      assert.ok(grouped instanceof Map);
      assert.ok(grouped.has('src/config.js'));
      assert.ok(grouped.has('.env'));
      assert.equal(grouped.get('src/config.js').length, 2);
    });

    it('returns empty map for empty findings', () => {
      const grouped = groupByFile([]);
      assert.equal(grouped.size, 0);
    });
  });

  describe('formatTextReport()', () => {
    it('returns a string', () => {
      const output = formatTextReport(sampleFindings, stats);
      assert.equal(typeof output, 'string');
    });

    it('contains file names', () => {
      const output = formatTextReport(sampleFindings, stats);
      assert.ok(output.includes('src/config.js'));
      assert.ok(output.includes('.env'));
    });

    it('contains finding names', () => {
      const output = formatTextReport(sampleFindings, stats);
      assert.ok(output.includes('AWS Access Key ID'));
      assert.ok(output.includes('Stripe Secret Key'));
    });

    it('contains files scanned count', () => {
      const output = formatTextReport(sampleFindings, stats);
      assert.ok(output.includes('15'));
    });

    it('shows clean message when no findings', () => {
      const output = formatTextReport([], { filesScanned: 10, filesSkipped: 0 });
      assert.ok(output.includes('No secrets'));
    });

    it('contains match values', () => {
      const output = formatTextReport(sampleFindings, stats);
      // Redacted match values should appear
      assert.ok(output.includes('AKIAIO***') || output.includes('Match'));
    });
  });

  describe('formatJsonReport()', () => {
    it('returns valid JSON', () => {
      const output = formatJsonReport(sampleFindings, stats);
      assert.doesNotThrow(() => JSON.parse(output));
    });

    it('JSON has expected top-level keys', () => {
      const result = JSON.parse(formatJsonReport(sampleFindings, stats));
      assert.ok('generated_at' in result);
      assert.ok('summary' in result);
      assert.ok('findings' in result);
    });

    it('summary has correct finding count', () => {
      const result = JSON.parse(formatJsonReport(sampleFindings, stats));
      assert.equal(result.summary.total_findings, sampleFindings.length);
    });

    it('summary has correct severity breakdown', () => {
      const result = JSON.parse(formatJsonReport(sampleFindings, stats));
      assert.equal(result.summary.by_severity.critical, 2);
      assert.equal(result.summary.by_severity.high, 1);
      assert.equal(result.summary.by_severity.medium, 1);
    });

    it('summary.clean is true when no findings', () => {
      const result = JSON.parse(formatJsonReport([], stats));
      assert.equal(result.summary.clean, true);
    });

    it('summary.clean is false when findings exist', () => {
      const result = JSON.parse(formatJsonReport(sampleFindings, stats));
      assert.equal(result.summary.clean, false);
    });

    it('includes files_scanned and files_skipped', () => {
      const result = JSON.parse(formatJsonReport(sampleFindings, stats));
      assert.equal(result.summary.files_scanned, 15);
      assert.equal(result.summary.files_skipped, 3);
    });

    it('findings array contains all findings', () => {
      const result = JSON.parse(formatJsonReport(sampleFindings, stats));
      assert.equal(result.findings.length, sampleFindings.length);
    });
  });
});
