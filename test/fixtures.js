/**
 * A well configured site, as probe() would have seen it — and a deep merge so
 * a test can break exactly one thing and leave the rest healthy.
 */

export const NOW = Date.UTC(2026, 9, 10, 12, 0, 0);

const DAY = 86_400_000;

export const GOOD_HEADERS = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'SAMEORIGIN',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=()',
  server: 'nginx',
};

export function observations(overrides = {}) {
  const base = {
    target: {
      input: 'example.com',
      scheme: 'https',
      host: 'example.com',
      port: 443,
      path: '/',
      explicitScheme: false,
    },
    checkedAt: NOW,
    http: {
      hops: [
        { url: 'http://example.com/', status: 301, location: 'https://example.com/' },
        { url: 'https://example.com/', status: 200, location: null },
      ],
      final: { url: 'https://example.com/', status: 200, headers: { ...GOOD_HEADERS }, ms: 40 },
      error: null,
    },
    https: {
      hops: [{ url: 'https://example.com/', status: 200, location: null }],
      final: { url: 'https://example.com/', status: 200, headers: { ...GOOD_HEADERS }, ms: 38 },
      error: null,
    },
    tls: {
      reachable: true,
      authorized: true,
      authorizationError: null,
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      certificate: {
        subject: 'example.com',
        issuer: "Let's Encrypt",
        validFrom: new Date(NOW - 30 * DAY).toUTCString(),
        validTo: new Date(NOW + 60 * DAY).toUTCString(),
        altNames: ['example.com', 'www.example.com'],
      },
      error: null,
    },
    legacyTls: { tested: true, accepted: false },
    securityTxt: { found: true, status: 200 },
    cookies: [],
  };

  return merge(base, overrides);
}

/** A certificate expiring in `days`. */
export function expiringIn(days) {
  return { tls: { certificate: { validTo: new Date(NOW + days * DAY).toUTCString() } } };
}

/** The same headers, minus the ones named. */
export function without(...names) {
  const headers = { ...GOOD_HEADERS };
  for (const name of names) delete headers[name];
  return {
    https: { final: { headers: replace(headers) } },
    http: { final: { headers: replace(headers) } },
  };
}

/**
 * Merging is the right default — a test breaks one thing and leaves the rest
 * alone — but removing a header needs the opposite, or the base object simply
 * puts it back.
 */
const REPLACE = Symbol('replace');

export function replace(value) {
  return { [REPLACE]: value };
}

function merge(base, overrides) {
  if (isPlainObject(overrides) && REPLACE in overrides) return overrides[REPLACE];
  if (!isPlainObject(base) || !isPlainObject(overrides)) return overrides ?? base;

  const result = { ...base };
  for (const [key, value] of Object.entries(overrides)) {
    result[key] = isPlainObject(value) && isPlainObject(base[key]) ? merge(base[key], value) : value;
  }
  return result;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
