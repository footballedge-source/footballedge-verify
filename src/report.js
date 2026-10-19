/** Plain-text report. Colour only on a terminal, and never with NO_COLOR set. */

const COLOURS = {
  pass: 32,
  fail: 31,
  warn: 33,
  skip: 90,
  info: 36,
  PASS: 32,
  FAIL: 31,
  INCOMPLETE: 33,
};

export function formatReport(report, { colour = false } = {}) {
  const paint = (key, text) =>
    colour && COLOURS[key] ? `\x1b[${COLOURS[key]}m${text}\x1b[0m` : text;
  const bold = (text) => (colour ? `\x1b[1m${text}\x1b[0m` : text);
  const lines = [];
  lines.push(bold(report.tool), '');
  if (report.batch) lines.push(`Batch      ${report.batch}`);
  if (report.kickoff)
    lines.push(
      `Kick-off   ${new Date(report.kickoff).toISOString().replace('T', ' ').slice(0, 16)} UTC`,
    );
  if (report.file) lines.push(`File       ${report.file.name} (${report.file.bytes} bytes)`);
  if (report.sha256) lines.push(`SHA-256    ${report.sha256}`);
  lines.push('');

  const width = Math.max(...report.checks.map((c) => c.name.length), 10);
  for (const c of report.checks) {
    lines.push(
      `${paint(c.status, c.status.toUpperCase().padEnd(4))}  ${c.name.padEnd(width)}  ${c.detail}`,
    );
  }

  if (report.entries.length > 0) {
    lines.push('', bold('Calls sealed in this batch'));
    for (const e of report.entries) {
      lines.push(
        `  ${e.call.padEnd(7)}  ${e.match} · ${e.market}: ${e.outcome} (${e.probabilityPct}%)`,
      );
      lines.push(`           ${e.url}`);
    }
    lines.push(
      '  Each pick must appear with the same call and percentage on the match page and the track record.',
    );
  }
  if (report.links.batch)
    lines.push('', `Batch page:    ${report.links.batch}`, `Track record:  ${report.links.record}`);
  if (report.workdir) lines.push(`Files kept in: ${report.workdir}`);

  lines.push('', `${bold('Result:')} ${paint(report.verdict, report.verdict)} — ${report.summary}`);
  lines.push(
    'What this shows: the file existed unchanged at the signed time. What it does not show: how the picks are made, or whether they will win.',
  );
  return `${lines.join('\n')}\n`;
}

export function exitCode(report) {
  return report.verdict === 'PASS' ? 0 : report.verdict === 'FAIL' ? 1 : 3;
}
