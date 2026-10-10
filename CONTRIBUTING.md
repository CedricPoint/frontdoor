# Contributing

The most useful contribution is a check that would have caught something on a
site you run, or a correction to one that judges too harshly.

## Getting started

```bash
git clone https://github.com/CedricPoint/frontdoor.git
cd frontdoor
npm test                              # no install step: there are no dependencies
node bin/frontdoor.js example.com
```

## How it fits together

| file | what it does |
| --- | --- |
| `src/probe.js` | makes the requests and writes down what came back. Judges nothing. |
| `src/checks.js` | the opinions, as pure functions of what probe collected. |
| `src/fixes.js` | the nginx, Caddy and Apache lines, per check. |
| `src/report.js` | everything the user reads. |
| `bin/frontdoor.js` | flags and exit codes. |

That split is the whole testing strategy: because `analyse()` never touches the
network, every check can be tested against a fabricated site.

## Adding a check

```js
{
  id: 'area.name',
  title: 'What is being checked, as a statement',
  weight: 3,                // 1 trivial, 5 the site is broken without it
  critical: false,          // true caps the grade when it fails
  run(observations) {
    const value = observations.https.final?.headers['x-thing'];
    if (!value) return { status: 'fail', detail: 'missing', why: 'One sentence.' };
    return { status: 'pass', detail: value };
  },
}
```

Four statuses, and the fourth one matters: **`skip` when the answer cannot be
known honestly**. A check that could not run must not cost points — that is why
a Node build without TLS 1.0 support reports "could not test" instead of a pass.

Then add the fix to `src/fixes.js` for all three servers, and a test in
`test/checks.test.js` with both a passing and a failing fixture.

## Things this tool will not do

Pull requests that add any of these will be turned down, politely:

- sending payloads, guessing at paths, or anything else a browser would not do
  on an ordinary visit;
- reading or printing cookie values, request bodies, or page content;
- phoning home with what it found.

It is a configuration review. Keeping it to that is what makes it safe to point
at somebody else's site and safe to paste the output in public.

## Style

Plain ESM, no dependencies, no build step.
