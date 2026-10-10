/**
 * The report, as it appears in a terminal.
 */

import { fixFor } from './fixes.js';

const enabled =
  process.env.NO_COLOR === undefined &&
  process.env.TERM !== 'dumb' &&
  (process.env.FORCE_COLOR !== undefined || Boolean(process.stdout.isTTY));

const wrap = (open, close) => (text) => (enabled ? `\u001b[${open}m${text}\u001b[${close}m` : String(text));

export const color = {
  bold: wrap(1, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  cyan: wrap(36, 39),
  grey: wrap(90, 39),
};

const MARK = { fail: '✖', warn: '▲', pass: '✔', skip: '–' };

const GRADE_COLOR = {
  'A+': color.green,
  A: color.green,
  B: color.yellow,
  C: color.yellow,
  D: color.red,
  F: color.red,
};

/**
 * @param {object} report       what analyse() returned
 * @param {object} observations what probe() collected
 * @param {{ server?: string }} [options]
 */
export function renderReport(report, observations, { server = 'nginx' } = {}) {
  const lines = [''];
  const grade = (GRADE_COLOR[report.grade] ?? color.grey)(color.bold(report.grade));

  lines.push(`  ${color.bold('frontdoor')}  ${color.cyan(report.host)}${pad(report.host)}${grade}  ${color.grey(`${report.score}/100`)}`);
  lines.push('');

  for (const line of summaryLines(report, observations)) lines.push(`  ${line}`);

  const problems = report.results.filter((result) => result.status === 'fail' || result.status === 'warn');

  for (const result of problems) {
    const tint = result.status === 'fail' ? color.red : color.yellow;
    lines.push('');
    lines.push(`  ${tint(MARK[result.status])}  ${color.bold(result.title)} ${color.grey(`— ${result.detail}`)}`);
    if (result.why) lines.push(`     ${result.why}`);

    const fix = fixFor(result.id, server, report.host);
    if (fix) {
      // Configuration lines are left exactly as they are — they get pasted —
      // but prose is wrapped, or a long note becomes one unreadable line.
      const body = fix.split('\n').flatMap((line) => (looksLikeConfig(line) ? [line] : wrapText(line, 76)));
      const [head, ...rest] = body;
      lines.push(`     ${color.grey(server.padEnd(7))}${color.cyan(head)}`);
      for (const extra of rest) lines.push(`     ${' '.repeat(7)}${color.cyan(extra)}`);
    }
  }

  lines.push('');

  const passed = report.results.filter((result) => result.status === 'pass');
  if (passed.length) {
    lines.push(`  ${color.green(MARK.pass)}  ${passed.length} passed   ${color.grey(list(passed.map((r) => r.title)))}`);
  }

  const skipped = report.results.filter((result) => result.status === 'skip');
  if (skipped.length) {
    lines.push(`  ${color.grey(MARK.skip)}  ${skipped.length} skipped  ${color.grey(list(skipped.map((r) => `${r.title} (${r.detail})`), 2))}`);
  }

  if (report.cappedByCritical) {
    lines.push('');
    lines.push(`  ${color.red('the grade is capped')} ${color.grey('because something a browser refuses outright is broken')}`);
  }

  if (problems.length) {
    lines.push('');
    lines.push(`  ${color.grey(`frontdoor ${report.host} --fix ${server}`)}  ${color.grey('prints all of that as one block')}`);
  }

  lines.push('');
  return lines.join('\n');
}

/** One line per host, for when several were checked. */
export function renderSummary(reports) {
  const lines = ['', `  ${color.bold('summary')}`, ''];
  const width = Math.max(...reports.map((report) => report.host.length));

  for (const report of reports) {
    const grade = (GRADE_COLOR[report.grade] ?? color.grey)(color.bold(report.grade.padEnd(2)));
    const counts = color.grey(`${report.counts.fail} to fix · ${report.counts.warn} to look at`);
    lines.push(`  ${report.host.padEnd(width)}  ${grade}  ${String(report.score).padStart(3)}/100  ${counts}`);
  }

  lines.push('');
  return lines.join('\n');
}

/* ----------------------------------------------------------------- pieces */

function summaryLines(report, observations) {
  const lines = [];
  const tls = observations.tls ?? {};

  if (tls.reachable) {
    const expiry = report.results.find((result) => result.id === 'tls.expiry');
    const bits = [expiry?.detail, tls.certificate?.issuer, tls.protocol].filter(Boolean);
    lines.push(`${color.grey('tls'.padEnd(10))}${bits.join(color.grey(' · '))}`);
  } else if (tls.error) {
    lines.push(`${color.grey('tls'.padEnd(10))}${color.red(tls.error)}`);
  }

  const redirect = report.results.find((result) => result.id === 'https.redirect');
  if (redirect && redirect.status !== 'skip') {
    lines.push(`${color.grey('http'.padEnd(10))}${redirect.status === 'pass' ? `goes to https, ${redirect.detail}` : redirect.detail}`);
  }

  const response = observations.https?.final ?? observations.http?.final;
  if (response) {
    lines.push(`${color.grey('page'.padEnd(10))}HTTP ${response.status}${response.ms ? color.grey(` · ${response.ms} ms`) : ''}`);
  }

  return lines;
}

function list(items, limit = 4) {
  if (items.length <= limit) return items.join(', ');
  return `${items.slice(0, limit).join(', ')} +${items.length - limit} more`;
}

function pad(host) {
  const width = Math.max(2, 46 - host.length);
  return ' '.repeat(width);
}

/** Config is pasted verbatim; a sentence is not. */
function looksLikeConfig(line) {
  return /^\s*(#|add_header|header|Header|server|ssl_|Server|<|}|{|\)|Redirect|Contact:|Expires:|[A-Za-z-]+\s+")/.test(line) || line.length <= 76;
}

function wrapText(text, width) {
  const words = String(text).split(/\s+/).filter(Boolean);
  const lines = [];
  let current = '';

  for (const word of words) {
    if (current && `${current} ${word}`.length > width) {
      lines.push(current);
      current = word;
    } else {
      current = current ? `${current} ${word}` : word;
    }
  }

  if (current) lines.push(current);
  return lines.length ? lines : [''];
}
