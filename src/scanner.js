'use strict';

const fs = require('fs');
const path = require('path');
const { PATTERNS, SKIP_EXTENSIONS, SKIP_DIRS } = require('./patterns');
const { findHighEntropyStrings } = require('./entropy');
const { buildIgnorer } = require('./ignorer');

const MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024; // 1 MB — skip larger files

/**
 * A single finding (match in a file).
 * @typedef {Object} Finding
 * @property {string} file       - relative path of file
 * @property {number} line       - 1-based line number
 * @property {string} content    - the matched line content (redacted)
 * @property {string} type       - pattern id or 'HIGH_ENTROPY'
 * @property {string} name       - human-readable name
 * @property {string} severity   - 'critical' | 'high' | 'medium' | 'low'
 * @property {string} [match]    - redacted match value
 * @property {number} [entropy]  - entropy value (for HIGH_ENTROPY findings)
 */

/**
 * Redact a secret value for safe display.
 * Shows first N chars + asterisks.
 * @param {string} value
 * @param {number} showChars
 * @returns {string}
 */
function redact(value, showChars = 6) {
  if (!value || value.length <= showChars) return '***';
  const visible = value.slice(0, showChars);
  return visible + '*'.repeat(Math.min(12, value.length - showChars));
}

/**
 * Scan a single line against all patterns.
 * @param {string} line
 * @param {number} lineNum (1-based)
 * @param {string} relPath
 * @returns {Finding[]}
 */
function scanLine(line, lineNum, relPath) {
  const findings = [];

  for (const pattern of PATTERNS) {
    // Reset lastIndex since regex has /g flag
    pattern.regex.lastIndex = 0;

    let match;
    while ((match = pattern.regex.exec(line)) !== null) {
      const matchValue = match[1] || match[0]; // capture group 1 if present, else full match
      const showChars = typeof pattern.redact === 'number' ? pattern.redact : 6;

      findings.push({
        file: relPath,
        line: lineNum,
        content: redactLine(line, match.index, match[0].length),
        type: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        match: showChars === 0 ? '[REDACTED]' : redact(matchValue, showChars)
      });

      // Don't infinite-loop on zero-length matches
      if (match[0].length === 0) pattern.regex.lastIndex++;
    }
  }

  // High-entropy string detection
  const entropyHits = findHighEntropyStrings(line);
  for (const hit of entropyHits) {
    // Check if this string was already caught by a pattern match
    const alreadyCaught = findings.some(f =>
      f.content && f.content.includes(hit.value.slice(0, 8))
    );
    if (alreadyCaught) continue;

    findings.push({
      file: relPath,
      line: lineNum,
      content: redactLine(line, line.indexOf(hit.value), hit.value.length),
      type: 'HIGH_ENTROPY',
      name: `High-Entropy String (${hit.charset})`,
      severity: 'medium',
      match: redact(hit.value, 6),
      entropy: hit.entropy
    });
  }

  return findings;
}

/**
 * Redact a specific range in a line for display.
 * @param {string} line
 * @param {number} start
 * @param {number} len
 * @returns {string}
 */
function redactLine(line, start, len) {
  const max = 120;
  let display = line.trim().slice(0, max);
  if (line.trim().length > max) display += '...';
  return display;
}

/**
 * Scan a single file. Returns array of findings.
 * @param {string} filePath absolute path
 * @param {string} rootDir  scan root for relative path calculation
 * @returns {Finding[]}
 */
function scanFile(filePath, rootDir) {
  const relPath = path.relative(rootDir, filePath).replace(/\\/g, '/');
  const ext = path.extname(filePath).toLowerCase();

  if (SKIP_EXTENSIONS.has(ext)) return [];

  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return [];
  }

  if (stat.size > MAX_FILE_SIZE_BYTES) return [];
  if (!stat.isFile()) return [];

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return []; // binary or unreadable file
  }

  const lines = content.split(/\r?\n/);
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.length > 2000) continue; // skip blank and pathological lines

    const lineFindings = scanLine(line, i + 1, relPath);
    findings.push(...lineFindings);
  }

  return findings;
}

/**
 * Recursively collect all files under a directory, respecting ignore rules.
 * @param {string} dir      absolute path
 * @param {string} rootDir  scan root
 * @param {object} ignorer  Ignorer instance
 * @param {string[]} files  accumulator
 * @returns {string[]}
 */
function collectFiles(dir, rootDir, ignorer, files = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return files;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(rootDir, fullPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      if (ignorer.ignoresDir(entry.name)) continue;
      if (ignorer.ignores(relPath + '/')) continue;
      collectFiles(fullPath, rootDir, ignorer, files);
    } else if (entry.isFile()) {
      if (ignorer.ignores(relPath)) continue;
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Main scan function. Scans a directory or single file.
 * @param {string} targetPath - absolute path to scan
 * @param {object} options
 * @param {boolean} [options.entropy=true] - include entropy detection
 * @param {string[]} [options.exclude=[]] - additional glob patterns to exclude
 * @returns {{ findings: Finding[], filesScanned: number, filesSkipped: number }}
 */
function scan(targetPath, options = {}) {
  const { entropy = true, exclude = [] } = options;

  const absTarget = path.resolve(targetPath);
  const stat = fs.statSync(absTarget);

  let rootDir, filePaths;

  if (stat.isFile()) {
    rootDir = path.dirname(absTarget);
    filePaths = [absTarget];
  } else {
    rootDir = absTarget;
    const ignorer = buildIgnorer(rootDir);
    for (const ex of exclude) ignorer.addRule(ex);
    filePaths = collectFiles(rootDir, rootDir, ignorer);
  }

  let filesScanned = 0;
  let filesSkipped = 0;
  const allFindings = [];

  for (const fp of filePaths) {
    const ext = path.extname(fp).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) {
      filesSkipped++;
      continue;
    }

    const findings = scanFile(fp, rootDir);

    // If entropy disabled, filter out HIGH_ENTROPY findings
    const filtered = entropy
      ? findings
      : findings.filter(f => f.type !== 'HIGH_ENTROPY');

    allFindings.push(...filtered);
    filesScanned++;
  }

  return { findings: allFindings, filesScanned, filesSkipped };
}

module.exports = { scan, scanFile, scanLine, redact };
