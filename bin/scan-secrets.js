#!/usr/bin/env node
'use strict';

/**
 * scan-secrets CLI
 * Usage: npx scan-secrets [path] [options]
 */

const path = require('path');
const { scan } = require('../src/scanner');
const { formatTextReport, formatJsonReport, disableColor } = require('../src/reporter');

const VERSION = require('../package.json').version;

function usage() {
  return `
  scan-secrets v${VERSION}
  Scan files for accidentally committed secrets, API keys, and credentials.

  Usage:
    npx scan-secrets [path] [options]

  Arguments:
    path           Directory or file to scan (default: current directory)

  Options:
    --json         Output results as JSON
    --no-entropy   Disable high-entropy string detection (reduce noise)
    --no-color     Disable ANSI color output
    --exclude <p>  Exclude glob pattern (repeatable)
    --ci           Exit code 1 if any findings (default: always exit 1 on findings)
    --version      Print version
    --help         Show this help

  Examples:
    npx scan-secrets                     # scan current directory
    npx scan-secrets ./src               # scan ./src
    npx scan-secrets --json > report.json
    npx scan-secrets --no-entropy        # pattern matching only (faster)
    npx scan-secrets --exclude "*.test.js" --exclude "fixtures/"

  Config:
    Create a .secretsignore file (same syntax as .gitignore) to exclude
    specific files or directories from scanning.
`.trim();
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    target: '.',
    json: false,
    entropy: true,
    color: true,
    ci: false,
    exclude: [],
    help: false,
    version: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case '--json':      opts.json = true; break;
      case '--no-entropy':opts.entropy = false; break;
      case '--no-color':  opts.color = false; break;
      case '--ci':        opts.ci = true; break;
      case '--help':      opts.help = true; break;
      case '--version':   opts.version = true; break;
      case '--exclude':
        if (args[i + 1]) opts.exclude.push(args[++i]);
        break;
      default:
        if (!arg.startsWith('--')) opts.target = arg;
    }
  }

  return opts;
}

async function main() {
  const opts = parseArgs(process.argv);

  if (opts.version) {
    console.log(VERSION);
    process.exit(0);
  }

  if (opts.help) {
    console.log(usage());
    process.exit(0);
  }

  if (!opts.color) disableColor();

  const targetPath = path.resolve(opts.target);
  const fs = require('fs');

  if (!fs.existsSync(targetPath)) {
    console.error(`scan-secrets: path not found: ${targetPath}`);
    process.exit(2);
  }

  let result;
  try {
    result = scan(targetPath, {
      entropy: opts.entropy,
      exclude: opts.exclude
    });
  } catch (err) {
    console.error(`scan-secrets: error during scan: ${err.message}`);
    process.exit(2);
  }

  const { findings, filesScanned, filesSkipped } = result;
  const stats = { filesScanned, filesSkipped };

  if (opts.json) {
    process.stdout.write(formatJsonReport(findings, stats) + '\n');
  } else {
    process.stdout.write(formatTextReport(findings, stats));
  }

  // Exit code: 0 = clean, 1 = secrets found, 2 = error
  process.exit(findings.length > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Unexpected error:', err.message);
  process.exit(2);
});
