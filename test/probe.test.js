import { test, after } from 'node:test';
import assert from 'node:assert/strict';

import { fetchOnce, followChain, parseCookies, parseTarget, probe } from '../src/probe.js';
import { closedPort, start, stopAll } from './server.js';

after(stopAll);

test('a target can be a host, a host:port or a URL', () => {
  assert.deepEqual(parseTarget('example.com'), {
    input: 'example.com',
    scheme: 'https',
    host: 'example.com',
    port: 443,
    path: '/',
    explicitScheme: false,
  });

  assert.equal(parseTarget('https://example.com/some/page').path, '/some/page');
  assert.equal(parseTarget('example.com:8443').port, 8443);
  assert.equal(parseTarget('http://example.com').scheme, 'http');
  assert.equal(parseTarget('http://example.com').explicitScheme, true);
});

test('a target that is not one says so', () => {
  assert.throws(() => parseTarget(''), /empty target/);
  assert.throws(() => parseTarget('ftp://example.com'), /only http and https/);
  assert.throws(() => parseTarget('http://'), /not a host/);
});

test('cookies are reduced to their flags, never their value', () => {
  const [session, theme] = parseCookies([
    'sid=super-secret-value; Path=/; HttpOnly; Secure; SameSite=Lax',
    'theme=dark; Path=/; Max-Age=31536000',
  ]);

  assert.deepEqual(session, { name: 'sid', secure: true, httpOnly: true, sameSite: 'lax', session: true });
  assert.deepEqual(theme, { name: 'theme', secure: false, httpOnly: false, sameSite: null, session: false });

  assert.ok(!JSON.stringify([session, theme]).includes('super-secret-value'));
});

test('one request reads the headers and leaves the body alone', async () => {
  const server = await start(() => ({ status: 204, headers: { 'x-test': 'yes' }, body: 'should not matter' }));

  const response = await fetchOnce(`${server.origin}/`);

  assert.equal(response.ok, true);
  assert.equal(response.status, 204);
  assert.equal(response.headers['x-test'], 'yes');
  assert.equal(typeof response.ms, 'number');
});

test('redirects are followed, and every hop is written down', async () => {
  const server = await start((request) => {
    if (request.url === '/') return { status: 301, headers: { location: '/second' } };
    if (request.url === '/second') return { status: 302, headers: { location: '/third' } };
    return { status: 200 };
  });

  const chain = await followChain(`${server.origin}/`);

  assert.equal(chain.error, null);
  assert.equal(chain.hops.length, 3);
  assert.equal(chain.hops[0].status, 301);
  assert.match(chain.final.url, /\/third$/);
  assert.equal(chain.final.status, 200);
});

test('a redirect loop stops instead of spinning', async () => {
  const server = await start(() => ({ status: 302, headers: { location: '/round-again' } }));

  const chain = await followChain(`${server.origin}/`, { maxHops: 4 });

  assert.match(chain.error, /more than 4 redirects/);
  assert.equal(chain.hops.length, 4);
});

test('a relative redirect is resolved against where it came from', async () => {
  const server = await start((request) =>
    request.url === '/a/b' ? { status: 301, headers: { location: '../c' } } : { status: 200 },
  );

  const chain = await followChain(`${server.origin}/a/b`);

  assert.match(chain.final.url, /\/c$/);
});

test('a closed port is an error, not a crash', async () => {
  const port = await closedPort();

  const response = await fetchOnce(`http://127.0.0.1:${port}/`);

  assert.equal(response.ok, false);
  assert.match(response.error, /ECONNREFUSED/);
});

test('a server that never answers gives up', async () => {
  const server = await start(() => ({ hang: true }));

  const response = await fetchOnce(`${server.origin}/`, { timeout: 150 });

  assert.equal(response.ok, false);
  assert.match(response.error, /no answer within 150 ms/);
});

test('an http:// target is probed as http, with no pretend TLS findings', async () => {
  const server = await start(() => ({
    status: 200,
    headers: { 'set-cookie': 'sid=abc; HttpOnly', 'x-content-type-options': 'nosniff' },
  }));

  const observations = await probe(server.origin, { timeout: 2000 });

  assert.equal(observations.target.scheme, 'http');
  assert.equal(observations.http.final.status, 200);
  assert.equal(observations.https.final, null);
  assert.equal(observations.tls.reachable, false);
  assert.match(observations.tls.error, /given as http/);
  assert.deepEqual(observations.cookies, [{ name: 'sid', secure: false, httpOnly: true, sameSite: null, session: true }]);
});
