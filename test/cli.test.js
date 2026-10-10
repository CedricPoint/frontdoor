import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyse } from '../src/checks.js';
import { fixBlock, fixFor, SERVERS } from '../src/fixes.js';
import { renderReport, renderSummary } from '../src/report.js';
import { NOW, observations, replace, without } from './fixtures.js';
import { closedPort, start, stopAll } from './server.js';

after(stopAll);

const bin = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'frontdoor.js');

/**
 * Asynchronous on purpose: the test server lives in this process, and
 * spawnSync would block the event loop that has to answer the child.
 */
function run(args = []) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bin, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

/* -------------------------------------------------------------------- fixes */

test('every server gets a line for every header we complain about', () => {
  const report = analyse(observations({ https: { final: { headers: replace({}) } } }), { now: NOW });
  const missing = report.results.filter((result) => result.status === 'fail' || result.status === 'warn');

  for (const server of SERVERS) {
    for (const result of missing) {
      const fix = fixFor(result.id, server, 'example.com');
      assert.ok(fix === null || typeof fix === 'string', `${result.id}/${server}`);
    }
  }

  assert.ok(fixFor('hsts', 'nginx').startsWith('add_header Strict-Transport-Security'));
  assert.ok(fixFor('hsts', 'caddy').startsWith('header Strict-Transport-Security'));
  assert.ok(fixFor('hsts', 'apache').startsWith('Header always set Strict-Transport-Security'));
});

test('the block is one paste, and it mentions the host where it has to', () => {
  const report = analyse(observations({ https: { final: { headers: replace({}) } } }), { now: NOW });
  const block = fixBlock(report, 'nginx', 'roofpilot.fr');

  assert.match(block, /^# frontdoor — roofpilot\.fr, nginx/);
  assert.match(block, /add_header Content-Security-Policy/);
  assert.match(block, /add_header X-Content-Type-Options "nosniff" always;/);
  assert.ok(!block.includes('HOST'), 'the placeholder was replaced');
});

test('the caddy block is a header block, not nginx lines', () => {
  const report = analyse(observations({ https: { final: { headers: replace({}) } } }), { now: NOW });
  const block = fixBlock(report, 'caddy', 'example.com');

  assert.match(block, /header \{/);
  assert.ok(!block.includes('add_header'));
});

test('a healthy site gets a block that says there is nothing to do', () => {
  const block = fixBlock(analyse(observations(), { now: NOW }), 'nginx', 'example.com');

  assert.match(block, /nothing to fix/);
});

test('an unknown server is refused', () => {
  assert.throws(() => fixBlock(analyse(observations(), { now: NOW }), 'iis', 'example.com'), /unknown server/);
});

/* ------------------------------------------------------------------ report */

test('the report shows the problems, the fix and what passed', () => {
  const data = observations(without('content-security-policy', 'strict-transport-security'));
  const text = renderReport(analyse(data, { now: NOW }), data, { server: 'nginx' });

  assert.match(text, /frontdoor/);
  assert.match(text, /Content-Security-Policy/);
  assert.match(text, /add_header Content-Security-Policy/);
  assert.match(text, /passed/);
  assert.match(text, /--fix nginx/);
});

test('the summary has one line per host', () => {
  const text = renderSummary([
    analyse(observations({ target: { host: 'a.example.com' } }), { now: NOW }),
    analyse(observations({ target: { host: 'b.example.com' }, https: { final: { headers: replace({}) } } }), { now: NOW }),
  ]);

  assert.match(text, /a\.example\.com/);
  assert.match(text, /b\.example\.com/);
  assert.equal(text.split('\n').filter((line) => line.includes('example.com')).length, 2);
});

/* --------------------------------------------------------------------- cli */

test('it checks a real server and reports on it', async () => {
  const server = await start(() => ({
    headers: {
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'x-frame-options': 'DENY',
      'set-cookie': 'sid=secret-value-here; HttpOnly',
      'x-powered-by': 'Express',
    },
  }));

  const { code, stdout } = await run([server.origin]);

  assert.equal(code, 0);
  assert.match(stdout, /frontdoor/);
  assert.match(stdout, /HTTP 200/);
  assert.ok(!stdout.includes('secret-value-here'), 'a cookie value must never be printed');
});

test('--json carries the whole thing, headers included, cookie values excluded', async () => {
  const server = await start(() => ({
    headers: { 'set-cookie': 'sid=do-not-print-me; Path=/', 'x-content-type-options': 'nosniff' },
  }));

  const payload = JSON.parse((await run([server.origin, '--json'])).stdout);

  assert.equal(payload.results.length > 10, true);
  assert.equal(payload.observations.cookies[0].name, 'sid');
  assert.ok(!JSON.stringify(payload).includes('do-not-print-me'));
});

test('--fix prints the configuration and nothing else', async () => {
  const server = await start(() => ({ headers: {} }));

  const { code, stdout } = await run([server.origin, '--fix', 'nginx']);

  assert.equal(code, 0);
  assert.match(stdout, /^# frontdoor/);
  assert.ok(!stdout.includes('passed'), 'the report is not mixed into the output');
});

test('--min-grade turns the grade into an exit code', async () => {
  const bare = await start(() => ({ headers: {} }));

  assert.equal((await run([bare.origin, '--min-grade', 'F'])).code, 0);
  assert.equal((await run([bare.origin, '--min-grade', 'A+'])).code, 1);
  assert.match((await run([bare.origin, '--min-grade', 'A+'])).stderr, /below A\+/);
});

test('several hosts in one run, with a summary at the end', async () => {
  const one = await start(() => ({ headers: {} }));
  const two = await start(() => ({ headers: {} }));

  const { code, stdout } = await run([one.origin, two.origin]);

  assert.equal(code, 0);
  assert.match(stdout, /summary/);
  assert.equal(stdout.match(/frontdoor {2}127\.0\.0\.1/g).length, 2);
});

test('nothing answering at all is an error, not a bad grade', async () => {
  const port = await closedPort();

  const { code, stderr } = await run([`http://127.0.0.1:${port}`]);

  assert.equal(code, 2);
  assert.match(stderr, /nothing answered/);
});

test('bad invocations say what is wrong', async () => {
  assert.equal((await run(['example.com', '--fix', 'iis'])).code, 2);
  assert.match((await run(['example.com', '--fix', 'iis'])).stderr, /--fix takes one of/);
  assert.match((await run(['example.com', '--min-grade', 'Z'])).stderr, /--min-grade takes one of/);
  assert.match((await run(['example.com', '--nonsense'])).stderr, /unknown option/);
  assert.match((await run(['example.com', '--timeout', 'soon'])).stderr, /milliseconds/);
});

test('help, version, and no arguments at all', async () => {
  assert.match((await run(['--help'])).stdout, /Usage/);
  assert.match((await run(['--version'])).stdout, /^\d+\.\d+\.\d+/);
  assert.equal((await run([])).code, 2, 'no target is a usage error');
  assert.match((await run([])).stdout, /Usage/);
});
