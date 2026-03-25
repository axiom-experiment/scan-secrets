'use strict';

/**
 * Shannon entropy calculation for detecting high-entropy (credential-like) strings.
 *
 * Formula: H = -Σ p_i * log2(p_i)
 * where p_i is the probability of character i appearing in the string.
 *
 * A completely random string of printable ASCII has entropy ~6.5 bits/char.
 * English text hovers around 3.5-4.5 bits/char.
 * Passwords/keys typically fall in the 4.5-6.5 range.
 */

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const HEX_CHARS = '0123456789abcdefABCDEF';

/**
 * Calculate Shannon entropy of a string (bits per character).
 * @param {string} s
 * @returns {number} entropy value (0 = no randomness, ~6.5 = fully random)
 */
function shannonEntropy(s) {
  if (!s || s.length === 0) return 0;

  const freq = Object.create(null);
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    freq[c] = (freq[c] || 0) + 1;
  }

  let entropy = 0;
  const len = s.length;
  for (const c in freq) {
    const p = freq[c] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Check if a string is a base64-like character set.
 * @param {string} s
 * @returns {boolean}
 */
function isBase64Like(s) {
  for (let i = 0; i < s.length; i++) {
    if (!BASE64_CHARS.includes(s[i])) return false;
  }
  return true;
}

/**
 * Check if a string is a hex-like character set.
 * @param {string} s
 * @returns {boolean}
 */
function isHexLike(s) {
  for (let i = 0; i < s.length; i++) {
    if (!HEX_CHARS.includes(s[i])) return false;
  }
  return true;
}

/**
 * Find all high-entropy strings in a line that look like secrets.
 * Returns array of {value, entropy, charset, start, end}
 *
 * @param {string} line
 * @param {object} options
 * @param {number} [options.minLength=20] minimum string length to evaluate
 * @param {number} [options.minEntropy=4.5] minimum entropy threshold
 * @returns {Array<{value: string, entropy: number, charset: string, start: number, end: number}>}
 */
function findHighEntropyStrings(line, options = {}) {
  const { minLength = 20, minEntropy = 4.5 } = options;
  const findings = [];

  // Extract quoted strings
  const quotedRegex = /['"`]([A-Za-z0-9/+_\-=.]{MIN,}?)['"`]/g.source
    .replace('MIN', minLength);
  const quotedPattern = new RegExp(quotedRegex, 'g');

  let match;
  while ((match = quotedPattern.exec(line)) !== null) {
    const candidate = match[1];
    if (candidate.length < minLength) continue;

    const entropy = shannonEntropy(candidate);
    if (entropy >= minEntropy) {
      const charset = isHexLike(candidate) ? 'hex'
        : isBase64Like(candidate) ? 'base64'
        : 'mixed';

      findings.push({
        value: candidate,
        entropy: Math.round(entropy * 100) / 100,
        charset,
        start: match.index + 1, // skip the quote char
        end: match.index + match[0].length - 1
      });
    }
  }

  // Also check unquoted assignments (VAR=SOMETHING_LONG)
  const assignRegex = /(?:^|[\s;,{(])(?:[A-Z_]{4,})\s*=\s*([A-Za-z0-9/+_\-=.]{MIN,})(?:\s|$|[;,})])/g.source
    .replace('MIN', minLength);
  const assignPattern = new RegExp(assignRegex, 'gm');

  while ((match = assignPattern.exec(line)) !== null) {
    const candidate = match[1];
    if (candidate.length < minLength) continue;

    // Skip common non-secrets
    if (/^(?:true|false|null|undefined|localhost|127\.0\.0\.1|0\.0\.0\.0)$/i.test(candidate)) continue;
    if (/^https?:\/\//.test(candidate)) continue;

    const entropy = shannonEntropy(candidate);
    if (entropy >= minEntropy) {
      // Avoid duplicate if already caught by quoted pattern
      const isDup = findings.some(f => f.value === candidate);
      if (!isDup) {
        const charset = isHexLike(candidate) ? 'hex'
          : isBase64Like(candidate) ? 'base64'
          : 'mixed';

        findings.push({
          value: candidate,
          entropy: Math.round(entropy * 100) / 100,
          charset,
          start: match.index,
          end: match.index + match[0].length
        });
      }
    }
  }

  return findings;
}

module.exports = { shannonEntropy, isBase64Like, isHexLike, findHighEntropyStrings };
