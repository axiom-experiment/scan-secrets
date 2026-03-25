'use strict';

/** ANSI color helpers (disabled automatically when --no-color) */
let useColor = process.stdout.isTTY !== false;

const c = {
  reset:  (s) => useColor ? `\x1b[0m${s}\x1b[0m` : s,
  bold:   (s) => useColor ? `\x1b[1m${s}\x1b[0m` : s,
  dim:    (s) => useColor ? `\x1b[2m${s}\x1b[0m` : s,
  red:    (s) => useColor ? `\x1b[31m${s}\x1b[0m` : s,
  yellow: (s) => useColor ? `\x1b[33m${s}\x1b[0m` : s,
  cyan:   (s) => useColor ? `\x1b[36m${s}\x1b[0m` : s,
  green:  (s) => useColor ? `\x1b[32m${s}\x1b[0m` : s,
  gray:   (s) => useColor ? `\x1b[90m${s}\x1b[0m` : s,
  orange: (s) => useColor ? `\x1b[38;5;208m${s}\x1b[0m` : s
};

function disableColor() { useColor = false; }

/**
 * Severity badge styling
 */
function severityBadge(severity) {
  switch (severity) {
    case 'critical': return c.red(c.bold('[CRITICAL]'));
    case 'high':     return c.orange(c.bold('[HIGH]'));
    case 'medium':   return c.yellow('[MEDIUM]');
    case 'low':      return c.gray('[LOW]');
    default:         return `[${severity.toUpperCase()}]`;
  }
}

function severityOrder(severity) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity] ?? 4;
}

/**
 * Sort findings: critical first, then high, medium, low. Then by file/line.
 * @param {import('./scanner').Finding[]} findings
 * @returns {import('./scanner').Finding[]}
 */
function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const sev = severityOrder(a.severity) - severityOrder(b.severity);
    if (sev !== 0) return sev;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });
}

/**
 * Group findings by file.
 * @param {import('./scanner').Finding[]} findings
 * @returns {Map<string, import('./scanner').Finding[]>}
 */
function groupByFile(findings) {
  const map = new Map();
  for (const f of findings) {
    if (!map.has(f.file)) map.set(f.file, []);
    map.get(f.file).push(f);
  }
  return map;
}

/**
 * Format a human-readable text report.
 * @param {import('./scanner').Finding[]} findings
 * @param {object} stats - { filesScanned, filesSkipped }
 * @returns {string}
 */
function formatTextReport(findings, stats) {
  const sorted = sortFindings(findings);
  const byFile = groupByFile(sorted);
  const lines = [];

  // Header
  lines.push('');
  lines.push(c.bold(c.cyan('╔═══════════════════════════════════════════╗')));
  lines.push(c.bold(c.cyan('║         scan-secrets — results            ║')));
  lines.push(c.bold(c.cyan('╚═══════════════════════════════════════════╝')));
  lines.push('');

  if (findings.length === 0) {
    lines.push(c.green(c.bold('  ✓ No secrets detected.')));
    lines.push('');
    lines.push(formatSummary(findings, stats));
    return lines.join('\n');
  }

  // Findings by file
  for (const [file, fileFindings] of byFile) {
    lines.push(c.bold(c.cyan(`  📄 ${file}`)));

    for (const f of fileFindings) {
      const lineRef = c.gray(`  Line ${f.line}:`);
      const badge = severityBadge(f.severity);
      const name = c.bold(f.name);
      lines.push(`${lineRef}  ${badge} ${name}`);

      if (f.match) {
        lines.push(c.gray(`            Match:   ${f.match}`));
      }
      if (f.entropy) {
        lines.push(c.gray(`            Entropy: ${f.entropy} bits/char`));
      }
      if (f.content) {
        const preview = f.content.trim().slice(0, 100);
        lines.push(c.dim(`            ${preview}`));
      }
      lines.push('');
    }
  }

  lines.push(formatSummary(findings, stats));
  return lines.join('\n');
}

/**
 * Format summary line.
 */
function formatSummary(findings, stats) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  const parts = [];
  if (counts.critical > 0) parts.push(c.red(c.bold(`${counts.critical} critical`)));
  if (counts.high > 0)     parts.push(c.orange(`${counts.high} high`));
  if (counts.medium > 0)   parts.push(c.yellow(`${counts.medium} medium`));
  if (counts.low > 0)      parts.push(c.gray(`${counts.low} low`));

  const total = findings.length;
  const summaryLine = total === 0
    ? c.green('No secrets found')
    : `${c.bold(total + ' finding' + (total !== 1 ? 's' : ''))} — ${parts.join(', ')}`;

  return [
    c.gray('  ─────────────────────────────────────────'),
    `  ${summaryLine}`,
    c.gray(`  Files scanned: ${stats.filesScanned}  |  Files skipped: ${stats.filesSkipped}`),
    ''
  ].join('\n');
}

/**
 * Format findings as JSON.
 * @param {import('./scanner').Finding[]} findings
 * @param {object} stats
 * @returns {string}
 */
function formatJsonReport(findings, stats) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  return JSON.stringify({
    generated_at: new Date().toISOString(),
    summary: {
      total_findings: findings.length,
      by_severity: counts,
      files_scanned: stats.filesScanned,
      files_skipped: stats.filesSkipped,
      clean: findings.length === 0
    },
    findings: sortFindings(findings)
  }, null, 2);
}

module.exports = {
  formatTextReport,
  formatJsonReport,
  formatSummary,
  sortFindings,
  groupByFile,
  disableColor,
  severityBadge
};
