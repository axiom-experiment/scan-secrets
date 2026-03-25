'use strict';

/**
 * scan-secrets — public API
 *
 * A pure Node.js, zero-dependency secret and credential scanner.
 * Detects 25+ secret patterns including AWS keys, GitHub tokens,
 * Stripe keys, and high-entropy strings.
 *
 * @example
 * const { scan } = require('scan-secrets');
 * const { findings, filesScanned } = scan('./my-project');
 * if (findings.length > 0) {
 *   console.error('Secrets found!', findings);
 *   process.exit(1);
 * }
 */

const { scan, scanFile, scanLine, redact } = require('./scanner');
const { PATTERNS, SKIP_EXTENSIONS, SKIP_DIRS } = require('./patterns');
const { shannonEntropy, findHighEntropyStrings } = require('./entropy');
const { formatTextReport, formatJsonReport } = require('./reporter');
const { buildIgnorer } = require('./ignorer');

module.exports = {
  // Core scanning
  scan,
  scanFile,
  scanLine,

  // Utilities
  redact,
  shannonEntropy,
  findHighEntropyStrings,

  // Reporting
  formatTextReport,
  formatJsonReport,

  // Configuration
  buildIgnorer,
  PATTERNS,
  SKIP_EXTENSIONS,
  SKIP_DIRS
};
