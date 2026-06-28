# PrivacyLint

> **Catch the leak before your regulator does.**
> An automated audit linter that proves — on every pull request — whether your Meta Pixel, Google tags, or any other third-party script is exfiltrating passwords, emails, and other PII to advertising servers.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](#license)
[![Built with Playwright](https://img.shields.io/badge/engine-Playwright-2EAD33.svg)](https://playwright.dev)
[![TypeScript strict](https://img.shields.io/badge/TypeScript-strict-3178C6.svg)](#)

---

## Why this exists

In the last three years, a wave of regulatory actions and class-action lawsuits — under **GDPR**, **CCPA/CPRA**, the EU **ePrivacy Directive**, the US **Wiretap Act**, **VPPA**, and **HIPAA** — have targeted one specific, recurring failure:

> A marketing tag, dropped onto a login or checkout page, silently captured form input and forwarded it to an ad network — frequently as a "convenient" hashed email for *advanced matching* or *enhanced conversions*.

These leaks are almost never intentional. They are introduced by:

- **Auto-capture features** — Meta's *Automatic Advanced Matching* and Google's *enhanced conversions* will read labelled `email`/`phone` inputs unless explicitly disabled.
- **Session-replay tools** (Hotjar, FullStory) that record keystrokes in fields not correctly masked.
- **Tag Manager sprawl** — a marketer adds a tag in a web UI; no engineer reviews the diff.
- **Copy-paste pixel snippets** that ship straight to production.

The data is invisible in code review because the leak only manifests **at runtime, in the network layer**. PrivacyLint closes that gap by auditing the *actual outbound traffic* of a real browser session — and it runs in CI, so a regression fails the build instead of reaching production.

---

## What it does

PrivacyLint drives a headless Chromium browser (via Playwright) against a URL or local HTML file. It:

1. **Seeds known secrets.** It types attacker-style canary values into your form fields (`type="password"`, `name="email"`, …), each tagged with a PII category.
2. **Dismisses consent banners (optional).** With `--accept-consent`, it clicks a recognised "accept all" control for the major Consent Management Platforms (OneTrust, Cookiebot, Quantcast, Didomi, Usercentrics, TrustArc, Osano, and more) so the trackers that only fire *after* consent are actually exercised.
3. **Captures every outbound request** — query strings, POST bodies (form-encoded *and* JSON), cookies, and custom headers.
4. **Attributes traffic** to a built-in catalogue of 25+ advertising/analytics endpoints (Meta Pixel, Google Analytics, DoubleClick, TikTok, LinkedIn, Bing UET, Pinterest, Snapchat, Reddit, Criteo, Taboola, Outbrain, Amazon Ads, Adobe Analytics, Hotjar, FullStory, Segment, Mixpanel, Amplitude, Yandex Metrica, and more).
5. **Detects leaks** — not only plaintext, but **URL-encoded, Base64, MD5, and SHA-256** representations of each secret, including canonicalised (trimmed/lower-cased) variants. "We hashed it first" is still a leak, and PrivacyLint says so.
6. **Applies defence-in-depth pattern rules** that flag structurally-valid emails, Luhn-valid credit-card numbers, and SSNs in tracker payloads even when they were never seeded.
7. **Reports ESLint-style** (and as **JSON** or **SARIF**), with a non-zero exit code when any finding crosses your configured `--fail-on` threshold.

A `--file` target is additionally scanned **statically**, so hard-coded PII sitting next to an inline pixel snippet is caught even if the request never fires in the test harness.

---

## Installation

```bash
# As a dev dependency in your project
npm install --save-dev privacylint

# PrivacyLint drives a real Chromium via Playwright. Install it once
# (kept out of `postinstall` on purpose, so consumers control the download):
npx playwright install --with-deps chromium
# or, equivalently, the bundled script:
npm run install-browser
```

Requires **Node.js ≥ 18**.

### Build from source

```bash
git clone https://github.com/NagaYu/privacylint.git
cd privacylint
npm install
npm run build      # emits ./dist
node ./dist/cli.js --help
```

---

## Quick start

Audit a live signup page, seeding an email and a password, then submitting the form:

```bash
npx privacylint \
  --url https://example.com/signup \
  --input "input[name=email]=alice@example.com:email" \
  --input "input[type=password]=S3cr3t-Canary!:password" \
  --submit "button[type=submit]" \
  --settle 3000 \
  --fail-on error
```

Audit a local HTML file (loaded in the browser **and** statically scanned):

```bash
npx privacylint \
  --file ./dist/checkout.html \
  --input "#email=buyer@example.com:email" \
  --input "#card=4242424242424242:credit_card" \
  --submit "#pay-now"
```

### Example output

```
PrivacyLint audit report
target    https://example.com/signup
captured  41 requests, 6 to known trackers
duration  4182 ms

Third-party tracker endpoints contacted:
  • Meta Pixel × 3
  • Google Analytics × 2
  • Google Tag Manager × 1

Findings (2):

1. error  an email address (field "cd[em]") was sent to Meta Pixel as a SHA-256 hash.
     rule      no-email-in-tracker
     tracker   Meta Pixel (www.facebook.com)
     request   GET https://www.facebook.com/tr/?id=123&ev=PageView&cd[em]=2a3f…
     field     cd[em] [query_string]
     leaked    2a*************************…1c (sha256)
     fix       Do not transmit raw or hashed email to ad networks without explicit, documented consent…

2. error  a password (field "pw") was sent to Google Analytics in plaintext.
     rule      no-password-in-tracker
     tracker   Google Analytics (www.google-analytics.com)
     request   POST https://www.google-analytics.com/g/collect?v=2&tid=G-XXXX
     field     pw [form_body]
     leaked    S3***********! (plaintext)
     fix       A password must NEVER leave your origin in any form…

✖ 2 problems (2 errors)
```

---

## Command-line reference

| Flag | Description |
| --- | --- |
| `-u, --url <url>` | Live URL to audit (http/https). |
| `-f, --file <path>` | Local HTML file to audit (loaded **and** statically scanned). |
| `-c, --config <path>` | Load settings from a JSON config file. Auto-discovers `privacylint.config.json` in the cwd. |
| `-i, --input <selector=value:category>` | Fill a form field. Repeatable. |
| `-s, --submit <selector>` | CSS selector to click after filling inputs. |
| `--secret <label=value:category>` | Declare a known secret not typed into a form. Repeatable. |
| `--settle <ms>` | Wait after submit to collect trailing beacons (default `2500`). |
| `--accept-consent` | Click a recognised cookie/consent "accept all" banner before auditing. |
| `--consent-selector <css>` | Extra CSS selector for the consent button. Repeatable. |
| `--rule <id=error\|warning\|info\|off>` | Override a rule's severity. Repeatable. |
| `--fail-on <error\|warning\|info>` | Minimum severity that fails CI (default `error`). |
| `--tracker <Vendor=marker1,marker2>` | Register an extra tracker by URL markers. Repeatable. |
| `--list-rules` | Print all built-in rules and exit. |
| `--json` | Emit machine-readable JSON instead of the human report. |
| `--sarif <path>` | Write a SARIF 2.1.0 report (`-` = stdout) for GitHub code scanning. |
| `-q, --quiet` | Print only findings and the summary line. |
| `--no-color` | Disable ANSI colours (also honours `NO_COLOR`). |
| `--headed` | Run the browser with a visible window (debugging). |
| `-h, --help` / `-v, --version` | Help / version. |

### Configuration file

Instead of long flag lists, commit a `privacylint.config.json` to your repo. PrivacyLint auto-discovers it in the working directory (or pass `--config <path>`). **Any CLI flag overrides the file**; array settings (inputs, secrets, trackers, consent selectors, rule overrides) are merged.

```json
{
  "url": "https://example.com/signup",
  "acceptConsent": true,
  "inputs": [
    { "selector": "input[name=email]", "value": "canary@example.com", "category": "email" },
    { "selector": "input[type=password]", "value": "S3cr3t-Canary!", "category": "password" }
  ],
  "submit": "button[type=submit]",
  "settle": 4000,
  "failOn": "error",
  "rules": {
    "no-name-in-tracker": "error",
    "no-pii-pattern-in-tracker": "off"
  },
  "trackers": [
    { "vendor": "Internal CDP", "urlMarkers": ["cdp.mycorp.io/collect"], "category": "analytics" }
  ]
}
```

A relative `file` target inside the config is resolved relative to the config file's location. Unknown keys and wrong-typed values are rejected with a clear error rather than silently ignored. See [`privacylint.config.example.json`](privacylint.config.example.json).

**Supported PII categories:** `password`, `email`, `credit_card`, `ssn`, `phone`, `name`, `address`, `dob`, `ip`, `secret`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; no finding crossed `--fail-on`. |
| `1` | At least one finding crossed `--fail-on`. |
| `2` | Usage error or the scan could not run. |

---

## Built-in rules

Run `privacylint --list-rules` for the authoritative list. Defaults:

| Rule ID | Default severity | Catches |
| --- | --- | --- |
| `no-password-in-tracker` | **error** | Any password representation in a tracker payload. |
| `no-email-in-tracker` | **error** | Raw or hashed email sent to a tracker. |
| `no-credit-card-in-tracker` | **error** | Cardholder data in a tracker payload (PCI-DSS). |
| `no-ssn-in-tracker` | **error** | Social Security Numbers. |
| `no-phone-in-tracker` | **error** | Phone numbers (raw or hashed). |
| `no-name-in-tracker` | warning | User full names. |
| `no-address-in-tracker` | warning | Postal addresses. |
| `no-dob-in-tracker` | warning | Dates of birth. |
| `no-generic-secret-in-tracker` | **error** | Any operator-declared secret. |
| `no-pii-pattern-in-tracker` | warning | Structural email/credit-card/SSN patterns, seed-independent. |

Tune any rule without forking the engine:

```bash
# Treat name leaks as hard failures, silence the broad pattern rule.
privacylint --url https://example.com \
  --rule no-name-in-tracker=error \
  --rule no-pii-pattern-in-tracker=off
```

---

## Programmatic API

PrivacyLint ships full type declarations and can be embedded in your own tooling:

```ts
import { scan, DEFAULT_RULES } from 'privacylint';
import { PiiCategory, Severity } from 'privacylint/types';
import type { ScanConfig } from 'privacylint/types';

const config: ScanConfig = {
  target: { kind: 'url', url: 'https://example.com/signup' },
  mockInputs: [
    { selector: 'input[name=email]', value: 'alice@example.com', category: PiiCategory.Email },
    { selector: 'input[type=password]', value: 'S3cr3t-Canary!', category: PiiCategory.Password },
  ],
  extraSecrets: [],
  submitSelector: 'button[type=submit]',
  settleTimeoutMs: 3000,
  headless: true,
  acceptConsent: true,
  consentSelectors: [],
  severityOverrides: {},
  failOn: Severity.Error,
  extraTrackers: [],
};

const result = await scan(config, DEFAULT_RULES);
if (result.failed) {
  console.error(`${result.tally.error} leak(s) detected`);
  process.exit(1);
}
```

---

## GitHub Actions integration

Drop this workflow into `.github/workflows/privacy-audit.yml`. It fails the build the moment a tracker starts exfiltrating PII.

```yaml
name: Privacy Leak Audit

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    # Re-audit production nightly — tag changes are often made outside of CI.
    - cron: '0 3 * * *'

jobs:
  privacylint:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm

      - name: Install dependencies
        run: npm ci

      - name: Install Chromium for Playwright
        run: npx playwright install --with-deps chromium

      - name: Build PrivacyLint
        run: npm run build

      - name: Run privacy audit
        run: |
          node ./dist/cli.js \
            --url "${{ vars.AUDIT_TARGET_URL }}" \
            --accept-consent \
            --input "input[name=email]=ci-canary@example.com:email" \
            --input "input[type=password]=ci-Canary-9f3!:password" \
            --submit "button[type=submit]" \
            --settle 4000 \
            --fail-on error \
            --sarif privacy-results.sarif
        # The human report prints to the log; SARIF is written for the Security tab.
        # A non-zero exit code here fails the job.

      - name: Upload SARIF to GitHub code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: privacy-results.sarif
          category: privacylint

      - name: Archive SARIF artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: privacy-results
          path: privacy-results.sarif
          retention-days: 90
```

The `upload-sarif` step surfaces every leak directly in the repository's **Security → Code scanning** tab and as inline annotations on the pull request. Grant the job `permissions: { security-events: write }` if your default token is read-only.

> **Tip:** commit a `privacylint.config.json` so the workflow shrinks to `node ./dist/cli.js --sarif privacy-results.sarif`. Store the target URL in a repository variable (`vars.AUDIT_TARGET_URL`) and use synthetic canary values — never reuse real user data.

### Using it as a pre-merge gate

Mark the `privacylint` job as a **required status check** in your branch-protection rules. A leaked password or email will then block the merge automatically.

---

## How leak detection works

For every seeded secret, PrivacyLint precomputes a family of needles and searches each decoded payload field for them:

| Form | What it catches |
| --- | --- |
| Plaintext (case-insensitive) | The value sent as-is. |
| URL-encoded | `%40`-style encoded values in query strings/bodies. |
| Base64 | The classic "obfuscated, not secured" pattern. |
| MD5 / SHA-256 | "Hashed advanced matching" — computed over trimmed and lower-cased canonical variants, because that is exactly how Meta/Google normalise before hashing. |

A finding requires **both** a sensitive value **and** a known exfiltration destination, which keeps false positives low: first-party requests to your own origin are never flagged.

Every printed value is **redacted** (at most the first two and last one characters survive) so audit logs and CI output never re-leak the secret they are warning you about.

---

## Limitations & honest scope

- PrivacyLint observes the traffic that fires **during the test session**. Conversion events gated behind real authentication or payment may need a seeded session/cookie to reproduce.
- **Consent banners:** `--accept-consent` handles the common CMPs out of the box, but bespoke or shadow-DOM banners may need a `--consent-selector`/`consentSelectors` hint. If consent is never granted, dormant tags will not fire — and a clean result then proves nothing.
- Detection of *hashed* PII depends on the tracker using a standard hash over a canonical form. Proprietary or salted hashing will not match — absence of a finding is **not** a proof of compliance, only the absence of the patterns checked.
- It does not replace a Data Protection Impact Assessment or legal review. It is a **regression guard**, not a lawyer.

These limits are stated plainly so you can position the tool correctly: it makes the common, dangerous, *machine-detectable* leaks impossible to ship unnoticed.

---

## License

PrivacyLint is dual-licensed.

### Open-source license — AGPL-3.0-or-later

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU Affero General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

The AGPL's network-use clause (Section 13) is deliberate: if you offer PrivacyLint — or a derivative — as a hosted service, you must make your complete corresponding source available to the users of that service. This keeps privacy-auditing tooling itself transparent and auditable.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details. You should have received a copy of the license along with this program; if not, see <https://www.gnu.org/licenses/agpl-3.0.html>.

### Commercial license — Business Source License (BSL) option

For organisations that cannot meet the AGPL's source-disclosure obligations — for example, embedding PrivacyLint in a closed-source internal platform or a proprietary SaaS — a **Business Source License 1.1** is available. Under the BSL, production use is granted under a commercial agreement, with the grant converting to an open-source license (AGPL-3.0) on the **Change Date** (four years after each release). Contact the maintainers to obtain BSL terms.

> Choose **one** license that fits your deployment model. When in doubt, AGPL-3.0 governs.

---

## Contributing & security

- Found a tracker we don't recognise? Open a PR adding its signature to `DEFAULT_TRACKERS` in `src/scanner.ts`.
- **Never** commit real user data, production credentials, or `.env` files. Canary values must be synthetic. See `.gitignore`.
- Report security issues privately to the maintainers before public disclosure.

---

*PrivacyLint — because the cheapest privacy incident is the one your CI caught.*
