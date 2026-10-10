/**
 * The part people actually want: the lines to paste.
 *
 * Telling somebody a header is missing is half an answer. These are the
 * defaults that are safe for an ordinary site; a site that embeds third-party
 * widgets will have to widen the policy, and the README says so.
 */

export const SERVERS = ['nginx', 'caddy', 'apache'];

const HEADERS = {
  hsts: {
    name: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains',
    comment: 'one year, subdomains included',
  },
  csp: {
    name: 'Content-Security-Policy',
    value: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    comment: 'widen this one directive at a time, starting from the console errors',
  },
  nosniff: {
    name: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  framing: {
    name: 'X-Frame-Options',
    value: 'SAMEORIGIN',
    comment: "or frame-ancestors in the policy above, which replaces this header",
  },
  referrer: {
    name: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
  permissions: {
    name: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
    comment: 'list what you do not use; anything you do need goes to (self)',
  },
};

const NOTES = {
  'https.redirect': {
    nginx: ['server {', '    listen 80;', '    server_name HOST;', '    return 301 https://$host$request_uri;', '}'].join('\n'),
    caddy: 'Caddy already does this: a site address with no scheme redirects http to https on its own.',
    apache: ['<VirtualHost *:80>', '    ServerName HOST', '    Redirect permanent / https://HOST/', '</VirtualHost>'].join('\n'),
  },
  leaks: {
    nginx: 'server_tokens off;',
    caddy: 'Caddy sends no version. If something behind it does, strip it: header -X-Powered-By',
    apache: ['ServerTokens Prod', 'ServerSignature Off'].join('\n'),
  },
  cookies: {
    note:
      'Cookie flags come from whatever sets the cookie, not from the server config. ' +
      'Express: res.cookie(name, value, { secure: true, httpOnly: true, sameSite: "lax" }). ' +
      'PHP: session.cookie_secure=1, session.cookie_httponly=1, session.cookie_samesite=Lax.',
  },
  securitytxt: {
    note:
      'Create /.well-known/security.txt with a Contact: line and an Expires: date, for example\n' +
      '    Contact: mailto:security@HOST\n' +
      '    Expires: 2027-01-01T00:00:00.000Z\n' +
      'The format is RFC 9116.',
  },
  'tls.expiry': { note: 'Renew the certificate. If renewal is automatic, look at why the last run did not take.' },
  'tls.chain': { note: 'Serve the full chain, not just the leaf — with certbot that is fullchain.pem, not cert.pem.' },
  'tls.hostname': { note: 'Reissue the certificate with this name in it, or point the name at the host that has one.' },
  'tls.legacy': {
    nginx: 'ssl_protocols TLSv1.2 TLSv1.3;',
    caddy: 'tls { protocols tls1.2 tls1.3 }',
    apache: 'SSLProtocol -all +TLSv1.2 +TLSv1.3',
  },
  'tls.protocol': {
    nginx: 'ssl_protocols TLSv1.2 TLSv1.3;',
    caddy: 'tls { protocols tls1.2 tls1.3 }',
    apache: 'SSLProtocol -all +TLSv1.2 +TLSv1.3',
  },
};

/**
 * The one line (or block) that fixes a single check.
 *
 * @param {string} id      check id
 * @param {string} server  nginx | caddy | apache
 * @param {string} [host]
 * @returns {string|null}
 */
export function fixFor(id, server, host = 'example.com') {
  const header = HEADERS[id];
  if (header) return headerLine(header, server);

  const note = NOTES[id];
  if (!note) return null;

  const text = note[server] ?? note.note ?? null;
  return text ? text.replaceAll('HOST', host) : null;
}

/**
 * Everything that needs fixing, as one block to paste.
 *
 * @param {object} report    what analyse() returned
 * @param {string} server
 * @param {string} host
 */
export function fixBlock(report, server, host) {
  if (!SERVERS.includes(server)) {
    throw new Error(`unknown server "${server}". Try one of: ${SERVERS.join(', ')}`);
  }

  const broken = report.results.filter((result) => result.status === 'fail' || result.status === 'warn');
  const headers = broken.filter((result) => HEADERS[result.id]);
  const others = broken.filter((result) => !HEADERS[result.id] && fixFor(result.id, server, host));

  const lines = [`# frontdoor — ${host}, ${server}`];

  if (!broken.length) {
    lines.push('# nothing to fix.');
    return lines.join('\n');
  }

  if (headers.length) {
    lines.push('');
    if (server === 'caddy') {
      lines.push('header {');
      for (const result of headers) {
        const header = HEADERS[result.id];
        if (header.comment) lines.push(`    # ${header.comment}`);
        lines.push(`    ${header.name} "${header.value}"`);
      }
      lines.push('}');
    } else {
      for (const result of headers) {
        const header = HEADERS[result.id];
        if (header.comment) lines.push(`# ${header.comment}`);
        lines.push(headerLine(header, server));
      }
    }
  }

  for (const result of others) {
    lines.push('');
    lines.push(`# ${result.title.toLowerCase()}`);
    lines.push(
      fixFor(result.id, server, host)
        .split('\n')
        .map((line) => (line.startsWith('#') ? line : line))
        .join('\n'),
    );
  }

  return lines.join('\n');
}

function headerLine(header, server) {
  if (server === 'caddy') return `header ${header.name} "${header.value}"`;
  if (server === 'apache') return `Header always set ${header.name} "${header.value}"`;
  return `add_header ${header.name} "${header.value}" always;`;
}

export const internals = { HEADERS, NOTES };
