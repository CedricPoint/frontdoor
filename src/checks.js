/**
 * The opinions.
 *
 * Every check is a pure function of what probe.js collected, so the whole
 * catalogue can be tested without a network, a certificate or a server.
 *
 *   pass  nothing to do
 *   warn  works, but a browser would be better protected
 *   fail  a visitor is exposed to something avoidable
 *   skip  could not be answered honestly (and does not count towards the grade)
 */

const SCORE = { pass: 1, warn: 0.5, fail: 0 };

/** Six months, the shortest max-age the preload list will look at. */
export const HSTS_MINIMUM = 15_552_000;

export const checks = [
  {
    id: 'https.reachable',
    title: 'The site answers over HTTPS',
    weight: 5,
    critical: true,
    run({ https, target }) {
      if (target.explicitScheme && target.scheme === 'http') {
        return { status: 'skip', detail: 'you asked for http:// explicitly' };
      }
      if (https.final) return { status: 'pass', detail: `HTTP ${https.final.status}` };

      return {
        status: 'fail',
        detail: https.error ?? 'no answer',
        why: 'Everything else on this list only matters once the site answers over HTTPS.',
      };
    },
  },
  {
    id: 'https.redirect',
    title: 'http:// goes to https://',
    weight: 4,
    run({ http }) {
      if (http.error && !http.final) {
        return {
          status: 'warn',
          detail: `nothing answers on http:// (${http.error})`,
          why: 'Somebody typing the bare domain gets an error instead of your site. A redirect costs nothing.',
        };
      }

      const downgrade = http.hops.some((hop, index) => index > 0 && hop.url.startsWith('http://') && http.hops[index - 1].url.startsWith('https://'));
      if (downgrade) {
        return {
          status: 'fail',
          detail: 'the chain goes back down to http://',
          why: 'A redirect that lands on http:// hands the whole visit to anyone on the network.',
        };
      }

      const landed = http.final?.url ?? http.hops[http.hops.length - 1]?.url ?? '';
      if (landed.startsWith('https://')) {
        const hops = http.hops.length - 1;
        return {
          status: hops > 2 ? 'warn' : 'pass',
          detail: hops <= 1 ? 'in one hop' : `in ${hops} hops`,
          why: hops > 2 ? 'Every hop is a round trip before the page starts loading.' : undefined,
        };
      }

      return {
        status: 'fail',
        detail: `http:// stays on http:// (HTTP ${http.final?.status ?? '?'})`,
        why: 'Anything typed, read or sent on that page travels in the clear.',
      };
    },
  },
  {
    id: 'tls.chain',
    title: 'The certificate is trusted',
    weight: 5,
    critical: true,
    run({ tls }) {
      if (!tls.reachable) return { status: 'skip', detail: tls.error ?? 'no TLS' };
      if (tls.authorized) return { status: 'pass', detail: tls.certificate.issuer ?? 'trusted' };

      return {
        status: 'fail',
        detail: tls.authorizationError ?? 'not trusted',
        why: 'Browsers show a full-page warning, and visitors are taught to click through it.',
      };
    },
  },
  {
    id: 'tls.hostname',
    title: 'The certificate covers this name',
    weight: 4,
    critical: true,
    run({ tls, target }) {
      if (!tls.reachable) return { status: 'skip', detail: tls.error ?? 'no TLS' };

      const names = [...(tls.certificate.altNames ?? [])];
      if (tls.certificate.subject) names.push(tls.certificate.subject);
      if (!names.length) return { status: 'skip', detail: 'the certificate carries no names' };

      const covered = names.some((name) => matchesHost(name, target.host));
      return covered
        ? { status: 'pass', detail: shorten(names) }
        : {
            status: 'fail',
            detail: `covers ${shorten(names)}, not ${target.host}`,
            why: 'The name on the certificate is not the name visitors type.',
          };
    },
  },
  {
    id: 'tls.expiry',
    title: 'The certificate is not about to expire',
    weight: 5,
    critical: true,
    run({ tls }, { now = Date.now() } = {}) {
      if (!tls.reachable) return { status: 'skip', detail: tls.error ?? 'no TLS' };

      const validTo = Date.parse(tls.certificate.validTo ?? '');
      if (Number.isNaN(validTo)) return { status: 'skip', detail: 'no expiry date in the certificate' };

      const days = Math.floor((validTo - now) / 86_400_000);

      if (days < 0) {
        return { status: 'fail', detail: `expired ${-days} days ago`, why: 'Every visitor is being warned away right now.' };
      }
      if (days <= 7) {
        return { status: 'fail', detail: `${days} days left`, why: 'If renewal is automatic, it has already had its chance and did not take it.' };
      }
      if (days <= 21) {
        return { status: 'warn', detail: `${days} days left`, why: 'Close enough that a failed renewal leaves no room to notice.' };
      }

      return { status: 'pass', detail: `${days} days left` };
    },
  },
  {
    id: 'tls.protocol',
    title: 'A current TLS version is used',
    weight: 3,
    run({ tls }) {
      if (!tls.reachable) return { status: 'skip', detail: tls.error ?? 'no TLS' };

      const protocol = tls.protocol ?? 'unknown';
      if (protocol === 'TLSv1.3') return { status: 'pass', detail: protocol };
      if (protocol === 'TLSv1.2') return { status: 'pass', detail: `${protocol} (1.3 would be faster)` };

      return {
        status: 'fail',
        detail: protocol,
        why: 'Everything before TLS 1.2 has known weaknesses and is refused by current browsers.',
      };
    },
  },
  {
    id: 'tls.legacy',
    title: 'TLS 1.0 and 1.1 are refused',
    weight: 2,
    run({ legacyTls }) {
      if (!legacyTls.tested) return { status: 'skip', detail: legacyTls.reason ?? 'not tested' };
      if (!legacyTls.accepted) return { status: 'pass', detail: 'refused' };

      return {
        status: 'fail',
        detail: `${legacyTls.protocol ?? 'a legacy version'} was accepted`,
        why: 'Keeping them on only helps an attacker downgrade the connection; no current browser needs them.',
      };
    },
  },
  {
    id: 'hsts',
    title: 'Strict-Transport-Security',
    weight: 4,
    header: 'strict-transport-security',
    run(observations) {
      const value = headerOf(observations, 'strict-transport-security');
      if (!value) {
        return {
          status: secureResponse(observations) ? 'fail' : 'skip',
          detail: secureResponse(observations) ? 'missing' : 'no HTTPS answer to read it from',
          why: 'Without it, the first visit of every day can still be sent over http and hijacked.',
        };
      }

      const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(value)?.[1] ?? 0);
      const subdomains = /includesubdomains/i.test(value);

      if (maxAge < HSTS_MINIMUM) {
        return {
          status: 'warn',
          detail: `max-age=${maxAge}`,
          why: `A browser forgets after that; ${HSTS_MINIMUM} seconds (180 days) is the usual floor.`,
        };
      }

      return {
        status: subdomains ? 'pass' : 'warn',
        detail: subdomains ? `max-age=${maxAge}, includeSubDomains` : `max-age=${maxAge}, no includeSubDomains`,
        why: subdomains ? undefined : 'Subdomains are left out, and they are where forgotten services live.',
      };
    },
  },
  {
    id: 'csp',
    title: 'Content-Security-Policy',
    weight: 4,
    header: 'content-security-policy',
    run(observations) {
      const value = headerOf(observations, 'content-security-policy');
      if (!value) {
        return {
          status: secureResponse(observations) ? 'fail' : 'skip',
          detail: 'missing',
          why: 'It is the one header that limits what an injected script can do once it is on the page.',
        };
      }

      const problems = [];
      if (/'unsafe-inline'/i.test(value)) problems.push("'unsafe-inline'");
      if (/'unsafe-eval'/i.test(value)) problems.push("'unsafe-eval'");
      if (/default-src[^;]*\*/i.test(value)) problems.push('default-src *');

      if (problems.length) {
        return {
          status: 'warn',
          detail: `present, but allows ${problems.join(', ')}`,
          why: 'Those put back most of what the policy was meant to take away.',
        };
      }

      return { status: 'pass', detail: `${value.split(';').length} directives` };
    },
  },
  {
    id: 'nosniff',
    title: 'X-Content-Type-Options',
    weight: 2,
    header: 'x-content-type-options',
    run(observations) {
      const value = headerOf(observations, 'x-content-type-options');
      if (!secureResponse(observations) && !value) return { status: 'skip', detail: 'no answer to read it from' };

      return /nosniff/i.test(value ?? '')
        ? { status: 'pass', detail: 'nosniff' }
        : {
            status: 'fail',
            detail: value ? `"${value}"` : 'missing',
            why: 'Without it a browser may decide an uploaded file is a script and run it.',
          };
    },
  },
  {
    id: 'framing',
    title: 'The page cannot be framed',
    weight: 3,
    header: 'x-frame-options',
    run(observations) {
      const frameAncestors = /frame-ancestors/i.test(headerOf(observations, 'content-security-policy') ?? '');
      const legacy = headerOf(observations, 'x-frame-options');

      if (frameAncestors) return { status: 'pass', detail: "CSP frame-ancestors" };
      if (/deny|sameorigin/i.test(legacy ?? '')) return { status: 'pass', detail: legacy.trim() };
      if (!secureResponse(observations)) return { status: 'skip', detail: 'no answer to read it from' };

      return {
        status: 'fail',
        detail: 'missing',
        why: 'Anyone can put your page in an invisible frame and collect the clicks meant for it.',
      };
    },
  },
  {
    id: 'referrer',
    title: 'Referrer-Policy',
    weight: 2,
    header: 'referrer-policy',
    run(observations) {
      const value = headerOf(observations, 'referrer-policy');
      if (!value) {
        return {
          status: secureResponse(observations) ? 'warn' : 'skip',
          detail: 'missing',
          why: 'Browsers differ on the default, and some still send the full URL to third parties.',
        };
      }

      if (/unsafe-url/i.test(value)) {
        return { status: 'fail', detail: value, why: 'That sends the full URL, query string included, to every site you link to.' };
      }

      return { status: 'pass', detail: value };
    },
  },
  {
    id: 'permissions',
    title: 'Permissions-Policy',
    weight: 1,
    header: 'permissions-policy',
    run(observations) {
      const value = headerOf(observations, 'permissions-policy') ?? headerOf(observations, 'feature-policy');
      if (value) return { status: 'pass', detail: shorten(value.split(',').map((item) => item.split('=')[0].trim())) };
      if (!secureResponse(observations)) return { status: 'skip', detail: 'no answer to read it from' };

      return {
        status: 'warn',
        detail: 'missing',
        why: 'Embedded third-party code can ask for the camera, the microphone or the location on your behalf.',
      };
    },
  },
  {
    id: 'cookies',
    title: 'Cookies are Secure, HttpOnly and SameSite',
    weight: 3,
    run({ cookies }) {
      if (!cookies.length) return { status: 'skip', detail: 'the home page sets no cookie' };

      const bad = cookies.filter((cookie) => !cookie.secure || !cookie.httpOnly || !cookie.sameSite);
      if (!bad.length) return { status: 'pass', detail: `${cookies.length} cookie${cookies.length > 1 ? 's' : ''}, all three flags` };

      const missing = bad.map((cookie) => {
        const gaps = [!cookie.secure && 'Secure', !cookie.httpOnly && 'HttpOnly', !cookie.sameSite && 'SameSite'].filter(Boolean);
        return `${cookie.name} (${gaps.join(', ')})`;
      });

      return {
        status: bad.some((cookie) => !cookie.secure) ? 'fail' : 'warn',
        detail: shorten(missing),
        why: 'Secure keeps a cookie off plain http, HttpOnly keeps it away from scripts, SameSite blunts cross-site requests.',
      };
    },
  },
  {
    id: 'leaks',
    title: 'The server keeps its version to itself',
    weight: 1,
    run(observations) {
      const server = headerOf(observations, 'server');
      const powered = headerOf(observations, 'x-powered-by');

      const talkative = [];
      if (server && /\d+\.\d+/.test(server)) talkative.push(`Server: ${server}`);
      if (powered) talkative.push(`X-Powered-By: ${powered}`);

      if (!talkative.length) return { status: 'pass', detail: server ? `Server: ${server}` : 'nothing version-specific' };

      return {
        status: 'warn',
        detail: talkative.join(' · '),
        why: 'It saves an attacker the trouble of working out which advisories apply to you.',
      };
    },
  },
  {
    id: 'securitytxt',
    title: 'A way to report a vulnerability',
    weight: 1,
    run({ securityTxt, https }) {
      if (!https.final) return { status: 'skip', detail: 'no HTTPS answer' };
      if (securityTxt.found) return { status: 'pass', detail: '/.well-known/security.txt' };

      return {
        status: 'warn',
        detail: 'no /.well-known/security.txt',
        why: 'Somebody who finds a hole in your site has nowhere to tell you, so they tell nobody — or everybody.',
      };
    },
  },
];

/**
 * Run every check and grade the result.
 *
 * @param {object} observations  what probe() collected
 * @param {{ now?: number }} [options]
 */
export function analyse(observations, options = {}) {
  const results = checks.map((check) => {
    let outcome;
    try {
      outcome = check.run(observations, options) ?? { status: 'skip', detail: 'no answer' };
    } catch (error) {
      outcome = { status: 'skip', detail: `check failed: ${error.message}` };
    }

    return {
      id: check.id,
      title: check.title,
      weight: check.weight,
      critical: Boolean(check.critical),
      ...outcome,
    };
  });

  const counted = results.filter((result) => result.status !== 'skip');
  const total = counted.reduce((sum, result) => sum + result.weight, 0);
  const earned = counted.reduce((sum, result) => sum + result.weight * SCORE[result.status], 0);
  const ratio = total ? earned / total : 0;

  const brokenCritical = results.some((result) => result.critical && result.status === 'fail');

  return {
    host: observations.target.host,
    checkedAt: observations.checkedAt,
    results,
    counts: {
      pass: results.filter((r) => r.status === 'pass').length,
      warn: results.filter((r) => r.status === 'warn').length,
      fail: results.filter((r) => r.status === 'fail').length,
      skip: results.filter((r) => r.status === 'skip').length,
    },
    score: Math.round(ratio * 100),
    grade: brokenCritical ? worstOf(gradeFor(ratio), 'D') : gradeFor(ratio),
    cappedByCritical: brokenCritical,
  };
}

export const GRADES = ['A+', 'A', 'B', 'C', 'D', 'F'];

export function gradeFor(ratio) {
  if (ratio >= 0.97) return 'A+';
  if (ratio >= 0.9) return 'A';
  if (ratio >= 0.8) return 'B';
  if (ratio >= 0.7) return 'C';
  if (ratio >= 0.6) return 'D';
  return 'F';
}

/** The lower of two grades. */
export function worstOf(a, b) {
  return GRADES.indexOf(a) > GRADES.indexOf(b) ? a : b;
}

/* ----------------------------------------------------------------- pieces */

/** The response the headers are read from: the HTTPS one, or the http one. */
export function responseOf(observations) {
  return observations.https?.final ?? observations.http?.final ?? null;
}

function secureResponse(observations) {
  return Boolean(observations.https?.final);
}

function headerOf(observations, name) {
  const response = responseOf(observations);
  const value = response?.headers?.[name];
  return Array.isArray(value) ? value.join(', ') : (value ?? null);
}

/** Does a name on a certificate cover this host? */
export function matchesHost(name, host) {
  const candidate = String(name).trim().toLowerCase();
  const wanted = String(host).trim().toLowerCase();

  if (!candidate || !wanted) return false;
  if (candidate === wanted) return true;
  if (!candidate.startsWith('*.')) return false;

  // A wildcard covers exactly one label: *.example.com is foo.example.com,
  // neither example.com nor a.b.example.com.
  const suffix = candidate.slice(1);
  if (!wanted.endsWith(suffix)) return false;

  const label = wanted.slice(0, wanted.length - suffix.length);
  return label.length > 0 && !label.includes('.');
}

function shorten(list, limit = 3) {
  const items = Array.isArray(list) ? list : [list];
  if (items.length <= limit) return items.join(', ');
  return `${items.slice(0, limit).join(', ')} +${items.length - limit} more`;
}
