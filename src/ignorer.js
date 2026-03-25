'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Simple .gitignore / .secretsignore parser and matcher.
 * Handles the most common glob patterns without external dependencies.
 */
class Ignorer {
  constructor() {
    this._rules = []; // [{pattern, negate, dir}]
  }

  /**
   * Load rules from a .gitignore-style file.
   * @param {string} filePath absolute path to ignore file
   */
  loadFile(filePath) {
    if (!fs.existsSync(filePath)) return;
    const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      this.addRule(line);
    }
  }

  /**
   * Add a single ignore rule (gitignore pattern syntax).
   * @param {string} pattern
   */
  addRule(pattern) {
    let p = pattern;
    let negate = false;

    if (p.startsWith('!')) {
      negate = true;
      p = p.slice(1);
    }

    // Trailing slash = directory-only match
    const dirOnly = p.endsWith('/');
    if (dirOnly) p = p.slice(0, -1);

    this._rules.push({ pattern: p, negate, dirOnly });
  }

  /**
   * Check if a relative file path should be ignored.
   * @param {string} relPath relative path from scan root (forward slashes)
   * @returns {boolean}
   */
  ignores(relPath) {
    // Normalize separators
    const normalized = relPath.replace(/\\/g, '/');
    const parts = normalized.split('/');
    const basename = parts[parts.length - 1];

    let ignored = false;

    for (const rule of this._rules) {
      const matches = this._match(normalized, basename, parts, rule.pattern, rule.dirOnly);
      if (matches) {
        ignored = !rule.negate;
      }
    }

    return ignored;
  }

  /**
   * Check if a directory name should be skipped.
   * @param {string} dirName just the directory name
   * @returns {boolean}
   */
  ignoresDir(dirName) {
    for (const rule of this._rules) {
      if (this._matchSimple(dirName, rule.pattern)) {
        if (!rule.negate) return true;
      }
    }
    return false;
  }

  _match(relPath, basename, parts, pattern, dirOnly) {
    if (dirOnly) {
      // Only matches directories — we check against each segment
      return parts.some(part => this._matchSimple(part, pattern));
    }

    // Pattern with slash: match against full relative path
    if (pattern.includes('/')) {
      return this._matchGlob(relPath, pattern);
    }

    // No slash: match against basename or any path segment
    return this._matchSimple(basename, pattern);
  }

  _matchSimple(str, pattern) {
    // Convert simple glob pattern to regex
    const regex = this._globToRegex(pattern);
    return regex.test(str);
  }

  _matchGlob(str, pattern) {
    // Strip leading slash from pattern
    const p = pattern.startsWith('/') ? pattern.slice(1) : pattern;
    const regex = this._globToRegex(p, true);
    return regex.test(str);
  }

  _globToRegex(pattern, fullPath = false) {
    let regexStr = '';
    let i = 0;
    while (i < pattern.length) {
      const c = pattern[i];
      if (c === '*') {
        if (pattern[i + 1] === '*') {
          // ** matches any path segment
          regexStr += '.*';
          i += 2;
          if (pattern[i] === '/') i++; // skip trailing slash after **
        } else {
          // * matches any char except /
          regexStr += '[^/]*';
          i++;
        }
      } else if (c === '?') {
        regexStr += '[^/]';
        i++;
      } else if (c === '.') {
        regexStr += '\\.';
        i++;
      } else if ('[]{}'.includes(c)) {
        regexStr += '\\' + c;
        i++;
      } else {
        regexStr += c;
        i++;
      }
    }

    if (fullPath) {
      return new RegExp('^' + regexStr + '$');
    }
    return new RegExp('^' + regexStr + '$');
  }
}

/**
 * Build an Ignorer for a given scan root.
 * Loads .gitignore and .secretsignore if present.
 * Always ignores node_modules, .git, dist, build etc.
 * @param {string} rootDir
 * @returns {Ignorer}
 */
function buildIgnorer(rootDir) {
  const ig = new Ignorer();

  // Always ignore these
  const always = [
    'node_modules', '.git', '.svn', 'dist', 'build', 'coverage',
    '.nyc_output', '.cache', '__pycache__', '.next', '.nuxt', 'out',
    '.parcel-cache', '.turbo', '.tox', 'venv', '.venv', '*.lock',
    '*.map', '*.min.js', '*.min.css'
  ];
  for (const rule of always) ig.addRule(rule);

  // Load .gitignore from root
  ig.loadFile(path.join(rootDir, '.gitignore'));

  // Load custom .secretsignore (scan-secrets specific)
  ig.loadFile(path.join(rootDir, '.secretsignore'));

  return ig;
}

module.exports = { Ignorer, buildIgnorer };
