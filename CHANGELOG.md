# Changelog

All notable changes to PrivacyLint are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-27

### Added

- Core audit engine (`scan()`): drives headless Chromium via Playwright, captures
  every outbound request, and decodes query strings, form bodies, JSON bodies,
  cookies, and headers into scannable fields.
- Leak detection across **plaintext, URL-encoding, Base64, MD5, and SHA-256**,
  including trimmed/lower-cased canonical variants ("hashed advanced matching").
- Seed-independent structural PII rules (email, Luhn-valid credit card, SSN).
- Static co-location scanner for local files with a proximity window to suppress
  false positives.
- **Consent-banner handling** (`--accept-consent`, `--consent-selector`): clicks
  a recognised "accept all" control for the major CMPs (OneTrust, Cookiebot,
  Quantcast, Didomi, Usercentrics, TrustArc, Osano, and more) so consent-gated
  tags actually fire during the audit.
- **Configuration file** support (`--config`, auto-discovered
  `privacylint.config.json`) with strict validation; CLI flags override file
  values and array settings merge.
- **SARIF 2.1.0** output (`--sarif`) for GitHub code scanning, alongside the
  human-readable and `--json` reporters.
- Expanded built-in tracker catalogue to 25+ vendors (adds Pinterest, Snapchat,
  Reddit, Criteo, Taboola, Outbrain, Amazon Ads, Adobe Analytics, Quantcast,
  Yandex Metrica, Mixpanel, Amplitude, Heap, Klaviyo, Pardot, HubSpot).
- ESLint-style severities with per-rule overrides and a configurable `--fail-on`
  threshold; CI-meaningful exit codes (0 clean / 1 findings / 2 usage error).
- Redaction of every printed value so reports never re-leak secrets.
- Dual licensing: AGPL-3.0-or-later with a Business Source License 1.1 option.
- Unit test suite plus a browser end-to-end suite (`node:test`), strict
  TypeScript build, and GitHub Actions workflows (lint/test matrix on Node
  18/20/22, a Chromium e2e job, and the privacy audit itself).

[Unreleased]: https://github.com/NagaYu/privacylint/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/NagaYu/privacylint/releases/tag/v1.0.0
