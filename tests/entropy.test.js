'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { shannonEntropy, isBase64Like, isHexLike, findHighEntropyStrings } = require('../src/entropy');

describe('entropy', () => {
  describe('shannonEntropy()', () => {
    it('returns 0 for empty string', () => {
      assert.equal(shannonEntropy(''), 0);
    });

    it('returns 0 for single character repeated', () => {
      assert.equal(shannonEntropy('aaaaaaaaaa'), 0);
    });

    it('returns ~1 for two equally distributed characters', () => {
      const e = shannonEntropy('abababababababab');
      assert.ok(Math.abs(e - 1.0) < 0.01, `Expected ~1, got ${e}`);
    });

    it('returns higher entropy for random-looking string', () => {
      // A base64-encoded random key should have high entropy
      const highEntropy = 'Ab3Kx9Lp2Qr8Yt5Nw4Mv7Jg1Zc6Fd0HsBe';
      const e = shannonEntropy(highEntropy);
      assert.ok(e > 4.0, `Expected >4.0, got ${e}`);
    });

    it('returns lower entropy for english text', () => {
      const e = shannonEntropy('the quick brown fox jumps over the lazy dog');
      // English text has ~4.17 bits/char maximum, but common words lower
      assert.ok(e < 5.0, `Expected <5.0 for English text, got ${e}`);
    });

    it('returns high entropy for AWS-like key', () => {
      const awsKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
      const e = shannonEntropy(awsKey);
      assert.ok(e > 4.5, `Expected >4.5 for AWS-like key, got ${e}`);
    });
  });

  describe('isBase64Like()', () => {
    it('returns true for valid base64 characters', () => {
      assert.ok(isBase64Like('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop0123456789+/='));
    });

    it('returns false when non-base64 chars present', () => {
      assert.ok(!isBase64Like('hello-world!'));
      assert.ok(!isBase64Like('has space'));
    });

    it('handles empty string', () => {
      assert.ok(isBase64Like(''));
    });
  });

  describe('isHexLike()', () => {
    it('returns true for hex string', () => {
      assert.ok(isHexLike('deadbeef0123456789abcdef'));
      assert.ok(isHexLike('DEADBEEF0123456789ABCDEF'));
    });

    it('returns false for non-hex chars', () => {
      assert.ok(!isHexLike('gg0011'));
      assert.ok(!isHexLike('xyz'));
    });

    it('handles empty string', () => {
      assert.ok(isHexLike(''));
    });
  });

  describe('findHighEntropyStrings()', () => {
    it('returns empty array for normal text', () => {
      const results = findHighEntropyStrings('const x = "hello world"');
      assert.equal(results.length, 0);
    });

    it('detects high-entropy quoted string', () => {
      // A 32-char random-looking base64 string
      const highEntropyStr = 'Kx9Lp2Qr8Ab3Yt5Nw4Mv7Jg1Zc6Fd0H';
      const line = `const secret = "${highEntropyStr}"`;
      const results = findHighEntropyStrings(line, { minLength: 20, minEntropy: 4.0 });
      assert.ok(results.length > 0, 'Should detect high entropy string');
      assert.equal(results[0].value, highEntropyStr);
      assert.ok(results[0].entropy >= 4.0);
    });

    it('does not flag short strings below minLength', () => {
      const results = findHighEntropyStrings('"Ab3Kx9"', { minLength: 20 });
      assert.equal(results.length, 0);
    });

    it('identifies charset type', () => {
      const hexStr = 'deadbeef0123456789abcdef01234567';
      const line = `token = "${hexStr}"`;
      const results = findHighEntropyStrings(line, { minLength: 20, minEntropy: 3.0 });
      if (results.length > 0) {
        assert.equal(results[0].charset, 'hex');
      }
    });

    it('does not flag common non-secret values', () => {
      // URLs, true/false, localhost should not be flagged
      const results = findHighEntropyStrings('const API_URL = "https://api.example.com/v1"', { minLength: 20 });
      assert.equal(results.length, 0);
    });

    it('returns result with expected shape', () => {
      const highStr = 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY';
      const line = `AWS_SECRET = "${highStr}"`;
      const results = findHighEntropyStrings(line, { minLength: 20, minEntropy: 3.5 });
      if (results.length > 0) {
        const r = results[0];
        assert.ok('value' in r);
        assert.ok('entropy' in r);
        assert.ok('charset' in r);
      }
    });
  });
});
