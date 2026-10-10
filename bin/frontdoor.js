#!/usr/bin/env node
/**
 * frontdoor — is the front door of your site locked?
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { probe } from '../src/probe.js';
import { analyse, GRADES } from '../src/checks.js';
import { fixBlock, SERVERS } from '../src/fixes.js';
import { renderReport, renderSummary, color } from '../src/report.js';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));

const EXIT = { ok: 0, below: 1, error: 2 };

const HELP = `
  ${color.bold('frontdoor')} — TLS, redirects, headers and cookies, from the outside

  ${color.bold('Usage')}
    frontdoor example.com
    frontdoor example.com another.com        Several at once, one after the other
    frontdoor example.com --fix nginx        Print the config to paste, and nothing else
    frontdoor example.com --min-grade B      Exit 1 below that grade, for CI

  ${color.bold('Options')}
        --fix <server>     ${SERVERS.join(' | ')} — print the block and stop
        --server <server>  which server the inline hints are for (default: nginx)
        --min-grade <g>    ${GRADES.join(' ')} — exit 1 below it
        --timeout <ms>     per request (default: 10000)
        --json             the whole thing as JSON
    -h, --help             this text
    -v, --version          print the version

  ${color.bold('Exit codes')}
    0  checked, and above --min-grade when you asked for one
    1  below the grade you asked for
    2  could not be checked at all, or a bad invocation

  It asks for the home page, /.well-known/security.txt and a TLS handshake or
  two — what a browser does on any visit. No payloads, no path guessing, no
  attempt to get past anything. Cookie values are never read.
`;

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(`frontdoor: ${error.message}\n`);
    process.exitCode = EXIT.error;
  });

async function main() {
  const { flags, targets } = parseArgs(process.argv.slice(2));

  if (flags.help || (!targets.length && !flags.version)) {
    process.stdout.write(`${HELP}\n`);
    return targets.length || flags.help ? EXIT.ok : EXIT.error;
  }
  if (flags.version) {
    process.stdout.write(`${pkg.version}\n`);
    return EXIT.ok;
  }

  const checked = [];

  for (const target of targets) {
    const observations = await probe(target, { timeout: flags.timeout });
    const report = analyse(observations);
    checked.push({ target, observations, report });
  }

  if (flags.json) {
    const payload = checked.map(({ report, observations }) => ({ ...report, observations: strip(observations) }));
    process.stdout.write(`${JSON.stringify(targets.length === 1 ? payload[0] : payload, null, 2)}\n`);
    return verdict(checked, flags);
  }

  if (flags.fix) {
    const blocks = checked.map(({ report }) => fixBlock(report, flags.fix, report.host));
    process.stdout.write(`${blocks.join('\n\n')}\n`);
    return verdict(checked, flags);
  }

  for (const { report, observations } of checked) {
    process.stdout.write(`${renderReport(report, observations, { server: flags.server })}\n`);
  }

  if (checked.length > 1) process.stdout.write(`${renderSummary(checked.map((item) => item.report))}\n`);

  return verdict(checked, flags);
}

function parseArgs(argv) {
  const flags = { server: 'nginx' };
  const targets = [];

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') flags.help = true;
    else if (arg === '-v' || arg === '--version') flags.version = true;
    else if (arg === '--json') flags.json = true;
    else if (arg === '--fix') flags.fix = argv[++i];
    else if (arg === '--server') flags.server = argv[++i];
    else if (arg === '--min-grade') flags.minGrade = argv[++i];
    else if (arg === '--timeout') flags.timeout = Number(argv[++i]);
    else if (arg.startsWith('-')) throw new Error(`unknown option "${arg}". Try --help.`);
    else targets.push(arg);
  }

  if (flags.fix && !SERVERS.includes(flags.fix)) {
    throw new Error(`--fix takes one of: ${SERVERS.join(', ')}`);
  }
  if (!SERVERS.includes(flags.server)) {
    throw new Error(`--server takes one of: ${SERVERS.join(', ')}`);
  }
  if (flags.minGrade && !GRADES.includes(flags.minGrade)) {
    throw new Error(`--min-grade takes one of: ${GRADES.join(', ')}`);
  }
  if (flags.timeout !== undefined && (!Number.isFinite(flags.timeout) || flags.timeout <= 0)) {
    throw new Error('--timeout takes a number of milliseconds');
  }

  return { flags, targets };
}

function verdict(checked, flags) {
  // Nothing answered on either scheme: that is not a bad grade, it is a failed
  // check — the difference matters to whatever called this.
  const unreachable = checked.filter(({ observations }) => !observations.https.final && !observations.http.final);

  if (unreachable.length === checked.length) {
    if (!flags.json && !flags.fix) {
      process.stderr.write(`frontdoor: nothing answered at ${unreachable.map((item) => item.report.host).join(', ')}\n`);
    }
    return EXIT.error;
  }

  if (!flags.minGrade) return EXIT.ok;

  const wanted = GRADES.indexOf(flags.minGrade);
  const below = checked.filter(({ report }) => GRADES.indexOf(report.grade) > wanted);

  if (below.length) {
    if (!flags.json && !flags.fix) {
      for (const { report } of below) {
        process.stderr.write(`frontdoor: ${report.host} is ${report.grade}, below ${flags.minGrade}\n`);
      }
    }
    return EXIT.below;
  }

  return EXIT.ok;
}

/** Headers are kept, bodies were never read, cookie values never collected. */
function strip(observations) {
  return {
    target: observations.target,
    tls: observations.tls,
    legacyTls: observations.legacyTls,
    cookies: observations.cookies,
    securityTxt: observations.securityTxt,
    http: { hops: observations.http.hops, error: observations.http.error },
    https: {
      hops: observations.https.hops,
      error: observations.https.error,
      status: observations.https.final?.status ?? null,
      headers: observations.https.final?.headers ?? null,
    },
  };
}
