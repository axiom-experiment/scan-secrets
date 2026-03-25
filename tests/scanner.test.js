'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { scan, scanFile, scanLine, redact } = require('../src/scanner');

// Create a temp directory for test fixtures
let tmpDir;

before(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-secrets-test-'));
});

after(() => {
  // Cleanup temp dir
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeFixture(filename, content) {
  const fp = path.join(tmpDir, filename);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, content, 'utf8');
  return fp;
}

describe('scanner', () => {
  describe('redact()', () => {
    it('redacts all chars for short strings', () => {
      assert.equal(redact('abc', 6), '***');
    });

    it('shows first N chars and asterisks', () => {
      const result = redact('AKIAIOSFODNN7EXAMPLE', 6);
      assert.equal(result.slice(0, 6), 'AKIAIO');
      assert.ok(result.includes('*'));
    });

    it('handles empty string', () => {
      assert.equal(redact('', 6), '***');
    });

    it('handles null/undefined gracefully', () => {
      assert.equal(redact(null, 6), '***');
      assert.equal(redact(undefined, 6), '***');
    });
  });

  describe('scanLine()', () => {
    it('detects AWS access key', () => {
      const line = 'const key = "AKIAIOSFODNN7EXAMPLE";';
      const findings = scanLine(line, 1, 'test.js');
      const awsFinding = findings.find(f => f.type === 'AWS_ACCESS_KEY');
      assert.ok(awsFinding, 'Should detect AWS key');
      assert.equal(awsFinding.line, 1);
      assert.equal(awsFinding.file, 'test.js');
      assert.equal(awsFinding.severity, 'critical');
    });

    it('detects GitHub PAT', () => {
      const token = 'ghp_' + 'A'.repeat(36);
      const line = `const token = "${token}";`;
      const findings = scanLine(line, 5, 'config.js');
      const ghFinding = findings.find(f => f.type === 'GITHUB_PAT');
      assert.ok(ghFinding, 'Should detect GitHub PAT');
      assert.equal(ghFinding.severity, 'critical');
    });

    it('detects npm token', () => {
      const token = 'npm_' + 'B'.repeat(36);
      const line = `//registry.npmjs.org/:_authToken=${token}`;
      const findings = scanLine(line, 1, '.npmrc');
      const npmFinding = findings.find(f => f.type === 'NPM_TOKEN');
      assert.ok(npmFinding, 'Should detect npm token');
    });

    it('detects Stripe secret key', () => {
      const line = 'STRIPE_SECRET_KEY=' + 'sk_live_' + 'AbCdEfGhIjKlMnOpQrStUvWxYz';
      const findings = scanLine(line, 1, '.env');
      const stripeFinding = findings.find(f => f.type === 'STRIPE_SECRET');
      assert.ok(stripeFinding, 'Should detect Stripe secret key');
      assert.equal(stripeFinding.severity, 'critical');
    });

    it('detects Stripe test key with medium severity', () => {
      const line = 'STRIPE_TEST_KEY=' + 'sk_test_' + 'AbCdEfGhIjKlMnOpQrStUvWx';
      const findings = scanLine(line, 1, '.env');
      const stripeFinding = findings.find(f => f.type === 'STRIPE_TEST');
      assert.ok(stripeFinding, 'Should detect Stripe test key');
      assert.equal(stripeFinding.severity, 'medium');
    });

    it('detects Google API key', () => {
      const key = 'AIza' + 'A'.repeat(35);
      const line = `GOOGLE_API_KEY="${key}"`;
      const findings = scanLine(line, 1, 'config.py');
      const googleFinding = findings.find(f => f.type === 'GOOGLE_API_KEY');
      assert.ok(googleFinding, 'Should detect Google API key');
    });

    it('detects SendGrid API key', () => {
      const key = 'SG.' + 'A'.repeat(22) + '.' + 'B'.repeat(43);
      const line = `SENDGRID_API_KEY = "${key}"`;
      const findings = scanLine(line, 1, 'mailer.py');
      const sgFinding = findings.find(f => f.type === 'SENDGRID_KEY');
      assert.ok(sgFinding, 'Should detect SendGrid key');
    });

    it('detects PEM private key header', () => {
      const line = '-----BEGIN RSA PRIVATE KEY-----';
      const findings = scanLine(line, 1, 'key.pem');
      const pemFinding = findings.find(f => f.type === 'PRIVATE_KEY_PEM');
      assert.ok(pemFinding, 'Should detect PEM private key');
      assert.equal(pemFinding.severity, 'critical');
    });

    it('detects OpenAI key', () => {
      const key = 'sk-' + 'A'.repeat(48);
      const line = `OPENAI_API_KEY = "${key}"`;
      const findings = scanLine(line, 1, 'openai.js');
      const oaFinding = findings.find(f => f.type === 'OPENAI_KEY');
      assert.ok(oaFinding, 'Should detect OpenAI key');
    });

    it('detects Slack webhook URL', () => {
      const line = 'SLACK_WEBHOOK=https://hooks.slack.com' + '/services/' + 'T123456789/B987654321/AbCdEfGhIjKlMnOpQrStUvWx';
      const findings = scanLine(line, 1, '.env');
      const slackFinding = findings.find(f => f.type === 'SLACK_WEBHOOK');
      assert.ok(slackFinding, 'Should detect Slack webhook');
    });

    it('detects Bearer token', () => {
      const token = 'eyJhbGciOiJIUzI1NiJ9.' + 'A'.repeat(40) + '.' + 'B'.repeat(40);
      const line = `Authorization: Bearer ${token}`;
      const findings = scanLine(line, 1, 'request.http');
      // Could be detected as BEARER_TOKEN or JWT_TOKEN
      assert.ok(findings.length > 0, 'Should detect a token');
    });

    it('returns empty array for clean lines', () => {
      const findings = scanLine('const x = 42;', 1, 'index.js');
      // Filter out entropy findings for this test (normal strings)
      const patternFindings = findings.filter(f => f.type !== 'HIGH_ENTROPY');
      assert.equal(patternFindings.length, 0);
    });

    it('sets finding file and line properties correctly', () => {
      const line = 'AKIAIOSFODNN7EXAMPLE in code';
      const findings = scanLine(line, 42, 'src/config.js');
      assert.ok(findings.length > 0);
      assert.equal(findings[0].file, 'src/config.js');
      assert.equal(findings[0].line, 42);
    });

    it('each finding has required shape', () => {
      const line = 'const key = "AKIAIOSFODNN7EXAMPLE";';
      const findings = scanLine(line, 1, 'test.js');
      for (const f of findings) {
        assert.ok('file' in f, 'missing file');
        assert.ok('line' in f, 'missing line');
        assert.ok('type' in f, 'missing type');
        assert.ok('name' in f, 'missing name');
        assert.ok('severity' in f, 'missing severity');
      }
    });
  });

  describe('scanFile()', () => {
    it('detects secrets in a file', () => {
      const fp = writeFixture('secrets.env', [
        'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
        'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'STRIPE_SECRET=' + 'sk_live_' + 'AbCdEfGhIjKlMnOpQrStUvWx'
      ].join('\n'));

      const findings = scanFile(fp, tmpDir);
      assert.ok(findings.length >= 2, `Expected ≥2 findings, got ${findings.length}`);
      const types = findings.map(f => f.type);
      assert.ok(types.includes('AWS_ACCESS_KEY'), 'Should find AWS key');
    });

    it('returns empty array for clean file', () => {
      const fp = writeFixture('clean.js', [
        "const message = 'Hello, world!';",
        'function add(a, b) { return a + b; }',
        "module.exports = { add };"
      ].join('\n'));

      const findings = scanFile(fp, tmpDir);
      const patternFindings = findings.filter(f => f.type !== 'HIGH_ENTROPY');
      assert.equal(patternFindings.length, 0);
    });

    it('skips binary extensions', () => {
      const fp = path.join(tmpDir, 'image.png');
      fs.writeFileSync(fp, Buffer.from([0x89, 0x50, 0x4E, 0x47]));
      const findings = scanFile(fp, tmpDir);
      assert.equal(findings.length, 0);
    });

    it('uses relative path in findings', () => {
      const fp = writeFixture('subdir/config.js', 'const k = "AKIAIOSFODNN7EXAMPLE";');
      const findings = scanFile(fp, tmpDir);
      assert.ok(findings.length > 0);
      assert.equal(findings[0].file, 'subdir/config.js');
    });

    it('handles empty file gracefully', () => {
      const fp = writeFixture('empty.js', '');
      const findings = scanFile(fp, tmpDir);
      assert.equal(findings.length, 0);
    });
  });

  describe('scan() — directory scan', () => {
    it('scans a directory and returns findings', () => {
      const scanDir = fs.mkdtempSync(path.join(tmpDir, 'scantest-'));
      fs.writeFileSync(path.join(scanDir, 'app.js'),
        'const KEY = "AKIAIOSFODNN7EXAMPLE";\n');
      fs.writeFileSync(path.join(scanDir, 'clean.js'),
        'const x = 1 + 1;\n');

      const { findings, filesScanned } = scan(scanDir, { entropy: false });
      assert.ok(filesScanned >= 2, `Expected ≥2 files scanned, got ${filesScanned}`);
      const awsFindings = findings.filter(f => f.type === 'AWS_ACCESS_KEY');
      assert.ok(awsFindings.length > 0, 'Should find AWS key in directory scan');
    });

    it('skips node_modules directory', () => {
      const scanDir = fs.mkdtempSync(path.join(tmpDir, 'nm-test-'));
      const nmDir = path.join(scanDir, 'node_modules', 'some-pkg');
      fs.mkdirSync(nmDir, { recursive: true });
      fs.writeFileSync(path.join(nmDir, 'index.js'),
        'const KEY = "AKIAIOSFODNN7EXAMPLE";\n');
      fs.writeFileSync(path.join(scanDir, 'clean.js'), 'const x = 1;\n');

      const { findings } = scan(scanDir, { entropy: false });
      const awsFindings = findings.filter(f => f.type === 'AWS_ACCESS_KEY');
      assert.equal(awsFindings.length, 0, 'Should not scan node_modules');
    });

    it('respects entropy option: false disables entropy findings', () => {
      const scanDir = fs.mkdtempSync(path.join(tmpDir, 'entropy-test-'));
      // A line that would only trigger entropy, not a pattern
      fs.writeFileSync(path.join(scanDir, 'config.js'),
        'const apiKey = "wJalrXUtnFEMIK7MDENGbPxRfiCY";\n');

      const withEntropy = scan(scanDir, { entropy: true });
      const withoutEntropy = scan(scanDir, { entropy: false });

      const entropyOnly = withEntropy.findings.filter(f => f.type === 'HIGH_ENTROPY');
      const entropyDisabled = withoutEntropy.findings.filter(f => f.type === 'HIGH_ENTROPY');

      // If entropy was detected, it should be gone when disabled
      if (entropyOnly.length > 0) {
        assert.equal(entropyDisabled.length, 0);
      }
    });

    it('returns filesScanned and filesSkipped counts', () => {
      const scanDir = fs.mkdtempSync(path.join(tmpDir, 'counts-test-'));
      fs.writeFileSync(path.join(scanDir, 'a.js'), 'const x = 1;\n');
      fs.writeFileSync(path.join(scanDir, 'b.js'), 'const y = 2;\n');

      const { filesScanned, filesSkipped } = scan(scanDir);
      assert.ok(filesScanned >= 2, `Expected ≥2 scanned, got ${filesScanned}`);
      assert.ok(typeof filesSkipped === 'number');
    });

    it('can scan a single file directly', () => {
      const fp = writeFixture('single-scan.env',
        'GITHUB_TOKEN=ghp_' + 'X'.repeat(36) + '\n');

      const { findings, filesScanned } = scan(fp, { entropy: false });
      assert.equal(filesScanned, 1);
      const ghFinding = findings.find(f => f.type === 'GITHUB_PAT');
      assert.ok(ghFinding, 'Should find GitHub PAT in single-file scan');
    });
  });
});
