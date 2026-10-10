# frontdoor

**English** · [Français](README.fr.md)

**Is the front door of your site locked?** One command looks at it the way a
browser does — TLS, redirects, security headers, cookie flags — grades what it
finds, and prints the nginx, Caddy or Apache lines that fix what is missing.

[![CI](https://github.com/CedricPoint/frontdoor/actions/workflows/ci.yml/badge.svg)](https://github.com/CedricPoint/frontdoor/actions/workflows/ci.yml)
[![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](package.json)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](package.json)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

```console
$ npx github:CedricPoint/frontdoor github.com

  frontdoor  github.com                                    A  91/100

  tls       50 days left · Sectigo Limited · TLSv1.3
  http      goes to https, in one hop
  page      HTTP 200 · 80 ms

  ▲  Content-Security-Policy — present, but allows 'unsafe-inline'
     Those put back most of what the policy was meant to take away.
     nginx  add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;

  ▲  Permissions-Policy — missing
     Embedded third-party code can ask for the camera, the microphone or the location on your behalf.
     nginx  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

  ▲  Cookies are Secure, HttpOnly and SameSite — _octo (HttpOnly)
     Secure keeps a cookie off plain http, HttpOnly keeps it away from scripts, SameSite blunts cross-site requests.

  ✔  12 passed   The site answers over HTTPS, http:// goes to https://, The certificate is trusted +9 more
  –  1 skipped   TLS 1.0 and 1.1 are refused (this Node build cannot speak TLS 1.0/1.1)
```

Every finding comes with the reason it matters — in a sentence, not a CVE
number — and the line that closes it.

## The part you actually want

```bash
frontdoor example.com --fix nginx
```

```nginx
# frontdoor — example.com, nginx

# one year, subdomains included
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
# widen this one directive at a time, starting from the console errors
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# http:// goes to https://
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

`--fix caddy` and `--fix apache` print the same thing in their own syntax. The
policy is a starting point for an ordinary site: if you embed third-party
widgets you will have to widen it, one directive at a time, with the browser
console open.

## What it checks

| | |
| --- | --- |
| **TLS** | the site answers over HTTPS · the certificate is trusted, covers this exact name, and is not about to expire · TLS 1.2 or 1.3 is in use · TLS 1.0 and 1.1 are refused |
| **Redirects** | `http://` lands on `https://`, in how many hops, and never back down to `http://` |
| **Headers** | `Strict-Transport-Security` (read, not just counted) · `Content-Security-Policy` (and whether it allows `unsafe-inline`) · `X-Content-Type-Options` · framing, via `X-Frame-Options` or `frame-ancestors` · `Referrer-Policy` · `Permissions-Policy` |
| **Cookies** | `Secure`, `HttpOnly` and `SameSite`, per cookie, by name |
| **Hygiene** | a `Server:` header with a version in it, `X-Powered-By`, and whether `/.well-known/security.txt` exists |

Sixteen checks, weighted, and a check that cannot be answered honestly is
skipped rather than guessed — an untestable thing never costs you points. A
broken certificate caps the grade whatever the rest looks like, because a
browser stops there too.

## In CI, or on a cron

```bash
frontdoor example.com --min-grade B     # exit 1 below that grade
frontdoor a.com b.com c.com             # one after the other, then a summary
frontdoor example.com --json            # the whole report, headers included
```

| exit | meaning |
| --- | --- |
| `0` | checked, and above `--min-grade` if you asked for one |
| `1` | below the grade you asked for |
| `2` | nothing answered at all, or a bad invocation |

The certificate expiry check is the one worth putting on a weekly cron: it
warns at 21 days and fails at 7, which is enough time to notice that automatic
renewal quietly stopped working.

## What it does not do

This is a configuration review, not a penetration test, and the difference is
deliberate:

- It asks for the home page, `/.well-known/security.txt`, and makes one or two
  TLS handshakes. That is what a browser does on any visit.
- **No payloads, no path guessing, no attempt to get past anything.** It reads
  what the server volunteers to every visitor and nothing else.
- **Cookie values are never read.** Only the name and the flags, so the output
  is safe to paste into an issue or a chat.
- It says nothing about your application. A perfect grade here and an SQL
  injection on the login form are entirely compatible.

## Install

```bash
npx github:CedricPoint/frontdoor example.com      # nothing installed
npm install -g github:CedricPoint/frontdoor
```

Node 18 or newer. No dependencies, no build step, no configuration file.

## As a library

```js
import { probe, analyse } from 'frontdoor';

const report = analyse(await probe('example.com'));

if (report.grade === 'F') process.exitCode = 1;
for (const result of report.results.filter((r) => r.status === 'fail')) {
  console.log(result.title, '—', result.detail);
}
```

`probe()` only observes and `analyse()` only judges, which is why the whole
catalogue of checks is testable without a network.

## Tests

50 of them. Every check is exercised against crafted observations — an expired
certificate, a wildcard that does not cover the host, a redirect that drops
back to http, a cookie missing `Secure` — and the network layer runs against a
real local HTTP server: redirect chains, loops, relative redirects, closed
ports, timeouts.

```bash
npm test
```

## License

MIT
