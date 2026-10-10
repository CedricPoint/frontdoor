/**
 * Looking at a site from the outside.
 *
 * This file only observes: it makes the handful of requests a browser would
 * make and writes down what came back. It never decides whether any of it is
 * good — that is checks.js, which is a pure function over what we collect here
 * and is therefore testable without a network.
 *
 * What it asks for, per host:
 *   http://host/                      to see whether it redirects to https
 *   https://host/                     the page itself, for the headers
 *   https://host/.well-known/security.txt
 *   one or two TLS handshakes         for the certificate and the protocol
 *
 * Nothing else. No payloads, no guessing at paths, no attempt to get past
 * anything. It reads what the server volunteers to every visitor.
 */

import { connect as tlsConnect } from 'node:tls';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';

export const DEFAULT_TIMEOUT = 10_000;
export const MAX_HOPS = 10;

/**
 * Turn whatever the user typed into a host and a port.
 *
 * @param {string} input  "example.com", "https://example.com/path", "host:8443"
 */
export function parseTarget(input) {
  const trimmed = String(input).trim();
  if (!trimmed) throw new Error('empty target');

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  let url;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error(`"${input}" is not a host or a URL`);
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`${url.protocol}// is not supported, only http and https`);
  }

  return {
    input: trimmed,
    scheme: url.protocol.replace(':', ''),
    host: url.hostname,
    port: url.port ? Number(url.port) : url.protocol === 'http:' ? 80 : 443,
    path: url.pathname === '/' ? '/' : url.pathname,
    explicitScheme: /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed),
  };
}

/**
 * One request, no redirect following.
 *
 * The certificate is deliberately not verified here: a site with an expired
 * certificate still has headers worth reading, and whether the certificate is
 * valid is answered properly by inspectTls().
 */
export function fetchOnce(url, { timeout = DEFAULT_TIMEOUT, userAgent } = {}) {
  return new Promise((resolve) => {
    let target;
    try {
      target = new URL(url);
    } catch {
      resolve({ ok: false, error: `invalid url: ${url}` });
      return;
    }

    const send = target.protocol === 'https:' ? httpsRequest : httpRequest;
    const started = Date.now();

    const request = send(
      target,
      {
        method: 'GET',
        rejectUnauthorized: false,
        servername: target.hostname,
        headers: {
          'user-agent': userAgent ?? 'frontdoor (+https://github.com/CedricPoint/frontdoor)',
          accept: 'text/html,*/*',
          'accept-encoding': 'identity',
        },
      },
      (response) => {
        // The headers are all we want; the body is never read.
        response.resume();
        resolve({
          ok: true,
          url: target.toString(),
          status: response.statusCode,
          headers: response.headers,
          location: response.headers.location ?? null,
          ms: Date.now() - started,
        });
        response.destroy();
      },
    );

    request.setTimeout(timeout, () => {
      request.destroy();
      resolve({ ok: false, url: target.toString(), error: `no answer within ${timeout} ms` });
    });

    request.on('error', (error) => {
      resolve({ ok: false, url: target.toString(), error: cleanError(error) });
    });

    request.end();
  });
}

/**
 * Follow redirects, writing down every hop.
 */
export async function followChain(startUrl, options = {}) {
  const hops = [];
  let current = startUrl;

  for (let i = 0; i < (options.maxHops ?? MAX_HOPS); i += 1) {
    const response = await fetchOnce(current, options);

    if (!response.ok) {
      return { hops, final: null, error: response.error };
    }

    hops.push({ url: response.url, status: response.status, location: response.location });

    const redirecting = response.status >= 300 && response.status < 400 && response.location;
    if (!redirecting) {
      return { hops, final: response, error: null };
    }

    try {
      current = new URL(response.location, response.url).toString();
    } catch {
      return { hops, final: response, error: `cannot follow "${response.location}"` };
    }
  }

  return { hops, final: null, error: `more than ${options.maxHops ?? MAX_HOPS} redirects` };
}

/**
 * The certificate and the protocol actually negotiated.
 */
export function inspectTls(host, port = 443, { timeout = DEFAULT_TIMEOUT } = {}) {
  return new Promise((resolve) => {
    const socket = tlsConnect(
      { host, port, servername: host, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] },
      () => {
        const certificate = socket.getPeerCertificate(false) ?? {};

        resolve({
          reachable: true,
          authorized: socket.authorized,
          authorizationError: socket.authorized ? null : String(socket.authorizationError ?? 'unknown'),
          protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name ?? null,
          certificate: {
            subject: certificate.subject?.CN ?? null,
            issuer: certificate.issuer?.O ?? certificate.issuer?.CN ?? null,
            validFrom: certificate.valid_from ?? null,
            validTo: certificate.valid_to ?? null,
            altNames: parseAltNames(certificate.subjectaltname),
          },
          error: null,
        });

        socket.end();
      },
    );

    socket.setTimeout(timeout, () => {
      socket.destroy();
      resolve({ reachable: false, error: `no TLS answer within ${timeout} ms` });
    });

    socket.on('error', (error) => {
      resolve({ reachable: false, error: cleanError(error) });
    });
  });
}

/**
 * Does the server still accept TLS 1.0 or 1.1?
 *
 * A connection that succeeds is the bad answer. A refusal is the good one.
 * Some Node builds will not even offer those versions, and then the honest
 * result is "could not test" rather than a pass.
 */
export function probeLegacyTls(host, port = 443, { timeout = DEFAULT_TIMEOUT } = {}) {
  return new Promise((resolve) => {
    let socket;

    try {
      socket = tlsConnect({
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        minVersion: 'TLSv1',
        maxVersion: 'TLSv1.1',
      });
    } catch (error) {
      resolve({ tested: false, reason: cleanError(error) });
      return;
    }

    socket.on('secureConnect', () => {
      const protocol = socket.getProtocol();
      socket.end();
      resolve({ tested: true, accepted: true, protocol });
    });

    socket.setTimeout(timeout, () => {
      socket.destroy();
      resolve({ tested: false, reason: 'timed out' });
    });

    socket.on('error', (error) => {
      const message = cleanError(error);
      // The client refusing is not an answer about the server.
      if (/no protocols available|unsupported protocol|invalid protocol version/i.test(message)) {
        resolve({ tested: false, reason: 'this Node build cannot speak TLS 1.0/1.1' });
        return;
      }
      resolve({ tested: true, accepted: false, reason: message });
    });
  });
}

/**
 * Set-Cookie, reduced to what is safe to print.
 *
 * The value never leaves this function. A report you cannot paste into an
 * issue is a report nobody shares.
 */
export function parseCookies(setCookie = []) {
  return setCookie.map((line) => {
    const [pair, ...attributes] = String(line).split(';');
    const name = pair.split('=')[0].trim();
    const flags = attributes.map((attribute) => attribute.trim().toLowerCase());

    const sameSite = flags.find((flag) => flag.startsWith('samesite='));

    return {
      name,
      secure: flags.includes('secure'),
      httpOnly: flags.includes('httponly'),
      sameSite: sameSite ? sameSite.slice('samesite='.length) : null,
      session: !flags.some((flag) => flag.startsWith('expires=') || flag.startsWith('max-age=')),
    };
  });
}

/**
 * Everything checks.js needs, in one object.
 *
 * @param {string} input
 * @param {{ timeout?: number }} [options]
 */
export async function probe(input, options = {}) {
  const target = parseTarget(input);
  const timeout = options.timeout ?? DEFAULT_TIMEOUT;
  const origin = `${target.host}${portSuffix(target)}`;

  const plain = await followChain(`http://${origin}${target.path}`, { timeout });

  // An explicit http:// target is checked as the user asked, without pretending
  // there is a TLS side to look at.
  if (target.explicitScheme && target.scheme === 'http') {
    return {
      target,
      checkedAt: Date.now(),
      http: plain,
      https: { hops: [], final: null, error: 'not checked: the target was given as http://' },
      tls: { reachable: false, error: 'not checked: the target was given as http://' },
      legacyTls: { tested: false, reason: 'not checked' },
      securityTxt: { found: false, status: null },
      cookies: plain.final ? parseCookies(plain.final.headers['set-cookie']) : [],
    };
  }

  const secure = await followChain(`https://${origin}${target.path}`, { timeout });
  const tls = await inspectTls(target.host, target.port, { timeout });
  const legacyTls = tls.reachable ? await probeLegacyTls(target.host, target.port, { timeout }) : { tested: false, reason: 'no TLS' };

  const wellKnown = await fetchOnce(`https://${origin}/.well-known/security.txt`, { timeout });

  return {
    target,
    checkedAt: Date.now(),
    http: plain,
    https: secure,
    tls,
    legacyTls,
    securityTxt: { found: Boolean(wellKnown.ok && wellKnown.status === 200), status: wellKnown.status ?? null },
    cookies: secure.final ? parseCookies(secure.final.headers['set-cookie']) : [],
  };
}

/* ----------------------------------------------------------------- pieces */

function portSuffix(target) {
  const standard = (target.scheme === 'http' && target.port === 80) || (target.scheme === 'https' && target.port === 443);
  return standard ? '' : `:${target.port}`;
}

function parseAltNames(subjectaltname) {
  if (!subjectaltname) return [];
  return String(subjectaltname)
    .split(',')
    .map((entry) => entry.trim().replace(/^DNS:/i, ''))
    .filter(Boolean);
}

function cleanError(error) {
  const code = error?.code ? `${error.code}: ` : '';
  return `${code}${error?.message ?? String(error)}`.replace(/\s+/g, ' ').trim();
}
