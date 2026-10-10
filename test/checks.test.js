import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyse, checks, gradeFor, matchesHost } from '../src/checks.js';
import { expiringIn, NOW, observations, replace, without } from './fixtures.js';

const run = (overrides) => analyse(observations(overrides), { now: NOW });
const find = (report, id) => report.results.find((result) => result.id === id);
const statusOf = (overrides, id) => find(run(overrides), id).status;

test('a well configured site comes out at the top', () => {
  const report = run();

  assert.equal(report.counts.fail, 0);
  assert.equal(report.counts.warn, 0);
  assert.equal(report.grade, 'A+');
  assert.equal(report.score, 100);
});

test('every check reports on every site, and ids are unique', () => {
  const report = run();

  assert.equal(report.results.length, checks.length);
  assert.equal(new Set(checks.map((check) => check.id)).size, checks.length);
  for (const result of report.results) {
    assert.ok(['pass', 'warn', 'fail', 'skip'].includes(result.status), `${result.id}: ${result.status}`);
    assert.ok(result.detail, `${result.id} says nothing`);
  }
});

/* --------------------------------------------------------------- redirect */

test('http that stays on http is the worst answer', () => {
  const result = find(
    run({
      http: {
        hops: [{ url: 'http://example.com/', status: 200, location: null }],
        final: { url: 'http://example.com/', status: 200, headers: {}, ms: 10 },
      },
    }),
    'https.redirect',
  );

  assert.equal(result.status, 'fail');
  assert.match(result.detail, /stays on http/);
});

test('a redirect that lands back on http is caught', () => {
  assert.equal(
    statusOf(
      {
        http: {
          hops: [
            { url: 'http://example.com/', status: 301, location: 'https://example.com/' },
            { url: 'https://example.com/', status: 302, location: 'http://www.example.com/' },
            { url: 'http://www.example.com/', status: 200, location: null },
          ],
          final: { url: 'http://www.example.com/', status: 200, headers: {}, ms: 10 },
        },
      },
      'https.redirect',
    ),
    'fail',
  );
});

test('a long redirect chain is a warning, not a failure', () => {
  const hops = [
    { url: 'http://example.com/', status: 301, location: 'http://www.example.com/' },
    { url: 'http://www.example.com/', status: 301, location: 'https://www.example.com/' },
    { url: 'https://www.example.com/', status: 301, location: 'https://www.example.com/en' },
    { url: 'https://www.example.com/en', status: 200, location: null },
  ];

  assert.equal(
    statusOf({ http: { hops, final: { url: 'https://www.example.com/en', status: 200, headers: {}, ms: 10 } } }, 'https.redirect'),
    'warn',
  );
});

test('nothing on port 80 is a warning', () => {
  assert.equal(statusOf({ http: { hops: [], final: null, error: 'ECONNREFUSED' } }, 'https.redirect'), 'warn');
});

/* -------------------------------------------------------------------- tls */

test('certificate expiry is graded by how close it is', () => {
  assert.equal(statusOf(expiringIn(60), 'tls.expiry'), 'pass');
  assert.equal(statusOf(expiringIn(30), 'tls.expiry'), 'pass');
  assert.equal(statusOf(expiringIn(14), 'tls.expiry'), 'warn');
  assert.equal(statusOf(expiringIn(3), 'tls.expiry'), 'fail');
  assert.match(find(run(expiringIn(-2)), 'tls.expiry').detail, /expired 2 days ago/);
});

test('an untrusted certificate fails and caps the grade', () => {
  const report = run({ tls: { authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' } });

  assert.equal(find(report, 'tls.chain').status, 'fail');
  assert.equal(report.cappedByCritical, true);
  assert.ok(['D', 'F'].includes(report.grade), `grade was ${report.grade}`);
});

test('the certificate has to carry the name that was asked for', () => {
  assert.equal(statusOf({ tls: { certificate: { subject: 'other.com', altNames: ['other.com'] } } }, 'tls.hostname'), 'fail');
  assert.equal(statusOf({ tls: { certificate: { subject: null, altNames: ['*.example.com', 'example.com'] } } }, 'tls.hostname'), 'pass');
});

test('wildcards cover one label, no more and no less', () => {
  assert.equal(matchesHost('*.example.com', 'www.example.com'), true);
  assert.equal(matchesHost('*.example.com', 'example.com'), false);
  assert.equal(matchesHost('*.example.com', 'a.b.example.com'), false);
  assert.equal(matchesHost('example.com', 'EXAMPLE.com'), true);
  assert.equal(matchesHost('', 'example.com'), false);
});

test('old protocols fail, current ones pass', () => {
  assert.equal(statusOf({ tls: { protocol: 'TLSv1.3' } }, 'tls.protocol'), 'pass');
  assert.equal(statusOf({ tls: { protocol: 'TLSv1.2' } }, 'tls.protocol'), 'pass');
  assert.equal(statusOf({ tls: { protocol: 'TLSv1' } }, 'tls.protocol'), 'fail');
});

test('a server that still accepts TLS 1.1 is told so, and an untested one is not judged', () => {
  assert.equal(statusOf({ legacyTls: { tested: true, accepted: true, protocol: 'TLSv1.1' } }, 'tls.legacy'), 'fail');
  assert.equal(statusOf({ legacyTls: { tested: false, reason: 'this Node build cannot speak TLS 1.0/1.1' } }, 'tls.legacy'), 'skip');
});

test('without TLS, the TLS checks say nothing instead of guessing', () => {
  const report = run({ tls: { reachable: false, error: 'ECONNREFUSED', certificate: {} } });

  for (const id of ['tls.chain', 'tls.hostname', 'tls.expiry', 'tls.protocol']) {
    assert.equal(find(report, id).status, 'skip', id);
  }
});

/* ---------------------------------------------------------------- headers */

test('HSTS is read, not just looked for', () => {
  assert.equal(statusOf(without('strict-transport-security'), 'hsts'), 'fail');
  assert.equal(statusOf({ https: { final: { headers: { 'strict-transport-security': 'max-age=86400' } } } }, 'hsts'), 'warn');
  assert.equal(statusOf({ https: { final: { headers: { 'strict-transport-security': 'max-age=31536000' } } } }, 'hsts'), 'warn');
  assert.equal(
    statusOf({ https: { final: { headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload' } } } }, 'hsts'),
    'pass',
  );
});

test('a policy that allows unsafe-inline is only half a policy', () => {
  assert.equal(statusOf(without('content-security-policy'), 'csp'), 'fail');
  assert.equal(
    statusOf({ https: { final: { headers: { 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'" } } } }, 'csp'),
    'warn',
  );
});

test('frame-ancestors in the policy replaces X-Frame-Options', () => {
  const headers = {
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  };

  assert.equal(statusOf({ https: { final: { headers } } }, 'framing'), 'pass');
  assert.equal(statusOf(without('x-frame-options', 'content-security-policy'), 'framing'), 'fail');
});

test('the small headers', () => {
  assert.equal(statusOf(without('x-content-type-options'), 'nosniff'), 'fail');
  assert.equal(statusOf(without('referrer-policy'), 'referrer'), 'warn');
  assert.equal(statusOf({ https: { final: { headers: { 'referrer-policy': 'unsafe-url' } } } }, 'referrer'), 'fail');
  assert.equal(statusOf(without('permissions-policy'), 'permissions'), 'warn');
});

test('a chatty server is a warning', () => {
  assert.equal(statusOf({ https: { final: { headers: { server: 'nginx' } } } }, 'leaks'), 'pass');
  assert.equal(statusOf({ https: { final: { headers: { server: 'nginx/1.18.0' } } } }, 'leaks'), 'warn');
  assert.equal(statusOf({ https: { final: { headers: { 'x-powered-by': 'Express' } } } }, 'leaks'), 'warn');
});

/* ---------------------------------------------------------------- cookies */

test('cookie flags are checked, and no value is ever looked at', () => {
  const report = run({
    cookies: [
      { name: 'session', secure: false, httpOnly: true, sameSite: 'lax', session: true },
      { name: 'theme', secure: true, httpOnly: true, sameSite: 'lax', session: false },
    ],
  });

  const result = find(report, 'cookies');
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /session \(Secure\)/);
  assert.ok(!JSON.stringify(report).includes('theme=')); // names only, never a value
});

test('a missing SameSite is a warning, a missing Secure is a failure', () => {
  assert.equal(statusOf({ cookies: [{ name: 'a', secure: true, httpOnly: true, sameSite: null }] }, 'cookies'), 'warn');
  assert.equal(statusOf({ cookies: [{ name: 'a', secure: false, httpOnly: true, sameSite: 'lax' }] }, 'cookies'), 'fail');
  assert.equal(statusOf({ cookies: [] }, 'cookies'), 'skip');
});

/* ----------------------------------------------------------------- grades */

test('skipped checks do not drag the grade down', () => {
  const healthy = run({ legacyTls: { tested: false, reason: 'cannot test' } });

  assert.equal(healthy.grade, 'A+');
  assert.equal(find(healthy, 'tls.legacy').status, 'skip');
});

test('the grade follows the ratio', () => {
  assert.equal(gradeFor(1), 'A+');
  assert.equal(gradeFor(0.95), 'A');
  assert.equal(gradeFor(0.85), 'B');
  assert.equal(gradeFor(0.75), 'C');
  assert.equal(gradeFor(0.65), 'D');
  assert.equal(gradeFor(0.2), 'F');
});

test('a site with nothing configured lands near the bottom', () => {
  const report = run({
    https: { final: { headers: replace({}) } },
    http: { final: { headers: replace({}) } },
    securityTxt: { found: false, status: 404 },
  });

  assert.ok(['D', 'F'].includes(report.grade), `grade was ${report.grade}`);
  assert.ok(report.counts.fail >= 4);
});

test('an unreachable site is an error, not an F', () => {
  const report = analyse(
    observations({
      https: { hops: [], final: null, error: 'ECONNREFUSED' },
      http: { hops: [], final: null, error: 'ECONNREFUSED' },
      tls: { reachable: false, error: 'ECONNREFUSED', certificate: {} },
      securityTxt: { found: false, status: null },
    }),
    { now: NOW },
  );

  assert.equal(find(report, 'https.reachable').status, 'fail');
  assert.equal(report.cappedByCritical, true);
});

test('a broken check is skipped, not fatal', () => {
  const broken = analyse({ target: { host: 'x' }, checkedAt: NOW }, { now: NOW });

  assert.equal(broken.results.length, checks.length);
  assert.ok(broken.results.every((result) => result.detail));
});
