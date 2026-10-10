/**
 * Programmatic API.
 *
 *   import { probe, analyse } from 'frontdoor';
 *
 *   const report = analyse(await probe('example.com'));
 *   if (report.grade === 'F') process.exitCode = 1;
 */

export { probe, parseTarget, fetchOnce, followChain, inspectTls, probeLegacyTls, parseCookies } from './probe.js';
export { analyse, checks, gradeFor, matchesHost, GRADES } from './checks.js';
export { fixFor, fixBlock, SERVERS } from './fixes.js';
export { renderReport, renderSummary } from './report.js';
