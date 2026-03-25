'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { PATTERNS, SKIP_EXTENSIONS, SKIP_DIRS } = require('../src/patterns');

describe('patterns', () => {
  describe('PATTERNS array', () => {
    it('should export an array with at least 20 patterns', () => {
      assert.ok(Array.isArray(PATTERNS));
      assert.ok(PATTERNS.length >= 20, `Expected ≥20 patterns, got ${PATTERNS.length}`);
    });

    it('every pattern has required fields', () => {
      for (const p of PATTERNS) {
        assert.ok(typeof p.id === 'string', `${p.id} missing id`);
        assert.ok(typeof p.name === 'string', `${p.id} missing name`);
        assert.ok(p.regex instanceof RegExp, `${p.id} regex must be RegExp`);
        assert.ok(['critical', 'high', 'medium', 'low'].includes(p.severity),
          `${p.id} severity must be critical|high|medium|low, got ${p.severity}`);
      }
    });

    it('every pattern id is unique', () => {
      const ids = PATTERNS.map(p => p.id);
      const unique = new Set(ids);
      assert.equal(unique.size, ids.length, 'Duplicate pattern IDs found');
    });

    it('AWS_ACCESS_KEY pattern matches real key format', () => {
      const pat = PATTERNS.find(p => p.id === 'AWS_ACCESS_KEY');
      assert.ok(pat);
      pat.regex.lastIndex = 0;
      assert.ok(pat.regex.test('AKIAIOSFODNN7EXAMPLE'));
      pat.regex.lastIndex = 0;
      assert.ok(!pat.regex.test('NOTANAWSKEY12345678'));
    });

    it('GITHUB_PAT pattern matches ghp_ format', () => {
      const pat = PATTERNS.find(p => p.id === 'GITHUB_PAT');
      assert.ok(pat);
      pat.regex.lastIndex = 0;
      const fakeToken = 'ghp_' + 'A'.repeat(36);
      assert.ok(pat.regex.test(fakeToken));
    });

    it('NPM_TOKEN pattern matches npm_ format', () => {
      const pat = PATTERNS.find(p => p.id === 'NPM_TOKEN');
      assert.ok(pat);
      pat.regex.lastIndex = 0;
      const fakeToken = 'npm_' + 'A'.repeat(36);
      assert.ok(pat.regex.test(fakeToken));
    });

    it('STRIPE_SECRET pattern matches sk_live_ format', () => {
      const pat = PATTERNS.find(p => p.id === 'STRIPE_SECRET');
      assert.ok(pat);
      pat.regex.lastIndex = 0;
      assert.ok(pat.regex.test('sk_live_' + 'AbCdEfGhIjKlMnOpQrStUvWx'));
    });

    it('PRIVATE_KEY_PEM pattern matches PEM header', () => {
      const pat = PATTERNS.find(p => p.id === 'PRIVATE_KEY_PEM');
      assert.ok(pat);
      pat.regex.lastIndex = 0;
      assert.ok(pat.regex.test('-----BEGIN RSA PRIVATE KEY-----'));
      pat.regex.lastIndex = 0;
      assert.ok(pat.regex.test('-----BEGIN PRIVATE KEY-----'));
      pat.regex.lastIndex = 0;
      assert.ok(pat.regex.test('-----BEGIN OPENSSH PRIVATE KEY-----'));
    });

    it('GOOGLE_API_KEY pattern matches AIza format', () => {
      const pat = PATTERNS.find(p => p.id === 'GOOGLE_API_KEY');
      assert.ok(pat);
      pat.regex.lastIndex = 0;
      assert.ok(pat.regex.test('AIza' + 'A'.repeat(35)));
    });

    it('OPENAI_KEY pattern matches sk- format with 48 chars', () => {
      const pat = PATTERNS.find(p => p.id === 'OPENAI_KEY');
      assert.ok(pat);
      pat.regex.lastIndex = 0;
      assert.ok(pat.regex.test('sk-' + 'A'.repeat(48)));
    });

    it('JWT_TOKEN pattern matches three-part dot-separated token', () => {
      const pat = PATTERNS.find(p => p.id === 'JWT_TOKEN');
      assert.ok(pat);
      pat.regex.lastIndex = 0;
      const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNjE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      assert.ok(pat.regex.test(fakeJwt));
    });

    it('SLACK_TOKEN pattern matches xoxb- format', () => {
      const pat = PATTERNS.find(p => p.id === 'SLACK_TOKEN');
      assert.ok(pat);
      pat.regex.lastIndex = 0;
      assert.ok(pat.regex.test('xoxb-' + '123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx'));
    });
  });

  describe('SKIP_EXTENSIONS', () => {
    it('is a Set', () => {
      assert.ok(SKIP_EXTENSIONS instanceof Set);
    });

    it('contains common binary extensions', () => {
      assert.ok(SKIP_EXTENSIONS.has('.png'));
      assert.ok(SKIP_EXTENSIONS.has('.exe'));
      assert.ok(SKIP_EXTENSIONS.has('.zip'));
      assert.ok(SKIP_EXTENSIONS.has('.pdf'));
    });

    it('does not contain .js or .env', () => {
      assert.ok(!SKIP_EXTENSIONS.has('.js'));
      assert.ok(!SKIP_EXTENSIONS.has('.env'));
    });
  });

  describe('SKIP_DIRS', () => {
    it('is a Set', () => {
      assert.ok(SKIP_DIRS instanceof Set);
    });

    it('contains node_modules and .git', () => {
      assert.ok(SKIP_DIRS.has('node_modules'));
      assert.ok(SKIP_DIRS.has('.git'));
      assert.ok(SKIP_DIRS.has('dist'));
      assert.ok(SKIP_DIRS.has('coverage'));
    });
  });
});
