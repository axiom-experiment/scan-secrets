'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { Ignorer, buildIgnorer } = require('../src/ignorer');

let tmpDir;

before(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-secrets-ignorer-test-'));
});

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('ignorer', () => {
  describe('Ignorer class', () => {
    it('ignores nothing by default', () => {
      const ig = new Ignorer();
      assert.ok(!ig.ignores('src/index.js'));
      assert.ok(!ig.ignores('README.md'));
    });

    it('ignores files matching simple pattern', () => {
      const ig = new Ignorer();
      ig.addRule('*.log');
      assert.ok(ig.ignores('app.log'));
      assert.ok(ig.ignores('server.log'));
      assert.ok(!ig.ignores('app.js'));
    });

    it('ignores directories matching pattern', () => {
      const ig = new Ignorer();
      ig.addRule('node_modules/');
      assert.ok(ig.ignoresDir('node_modules'));
      assert.ok(!ig.ignoresDir('src'));
    });

    it('supports negation with !', () => {
      const ig = new Ignorer();
      ig.addRule('*.log');
      ig.addRule('!important.log');
      assert.ok(ig.ignores('debug.log'));
      assert.ok(!ig.ignores('important.log'));
    });

    it('ignores files matching path pattern', () => {
      const ig = new Ignorer();
      ig.addRule('fixtures/**');
      assert.ok(ig.ignores('fixtures/test.env'));
      assert.ok(ig.ignores('fixtures/nested/secret.txt'));
      assert.ok(!ig.ignores('src/index.js'));
    });

    it('loads rules from a file', () => {
      const ignoreFile = path.join(tmpDir, '.testignore');
      fs.writeFileSync(ignoreFile, '*.secret\n# comment\ndist/\n\n');

      const ig = new Ignorer();
      ig.loadFile(ignoreFile);
      assert.ok(ig.ignores('config.secret'));
      assert.ok(!ig.ignores('config.js'));
    });

    it('handles non-existent ignore file gracefully', () => {
      const ig = new Ignorer();
      assert.doesNotThrow(() => ig.loadFile('/nonexistent/.gitignore'));
    });

    it('skips comment lines in ignore file', () => {
      const ignoreFile = path.join(tmpDir, '.commentignore');
      fs.writeFileSync(ignoreFile, '# This is a comment\n*.log\n');

      const ig = new Ignorer();
      ig.loadFile(ignoreFile);
      assert.ok(ig.ignores('server.log'));
    });

    it('skips blank lines in ignore file', () => {
      const ignoreFile = path.join(tmpDir, '.blankignore');
      fs.writeFileSync(ignoreFile, '\n\n*.tmp\n\n');

      const ig = new Ignorer();
      ig.loadFile(ignoreFile);
      assert.ok(ig.ignores('temp.tmp'));
    });
  });

  describe('buildIgnorer()', () => {
    it('returns an Ignorer instance', () => {
      const ig = buildIgnorer(tmpDir);
      assert.ok(ig instanceof Ignorer);
    });

    it('always ignores node_modules', () => {
      const ig = buildIgnorer(tmpDir);
      assert.ok(ig.ignoresDir('node_modules'));
    });

    it('always ignores .git', () => {
      const ig = buildIgnorer(tmpDir);
      assert.ok(ig.ignoresDir('.git'));
    });

    it('always ignores dist', () => {
      const ig = buildIgnorer(tmpDir);
      assert.ok(ig.ignoresDir('dist'));
    });

    it('loads .gitignore from root directory', () => {
      const scanDir = fs.mkdtempSync(path.join(tmpDir, 'gitignore-test-'));
      fs.writeFileSync(path.join(scanDir, '.gitignore'), '*.custom\n');
      const ig = buildIgnorer(scanDir);
      assert.ok(ig.ignores('myfile.custom'));
    });

    it('loads .secretsignore from root directory', () => {
      const scanDir = fs.mkdtempSync(path.join(tmpDir, 'secretsignore-test-'));
      fs.writeFileSync(path.join(scanDir, '.secretsignore'), 'fixtures/\n');
      const ig = buildIgnorer(scanDir);
      assert.ok(ig.ignoresDir('fixtures'));
    });

    it('handles directory without .gitignore gracefully', () => {
      const emptyDir = fs.mkdtempSync(path.join(tmpDir, 'empty-test-'));
      assert.doesNotThrow(() => buildIgnorer(emptyDir));
    });
  });
});
