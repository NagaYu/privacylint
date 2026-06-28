# Contributing to PrivacyLint

Thanks for helping make tracker privacy auditable. This guide covers the
mechanics; please also read [SECURITY.md](SECURITY.md).

## Development setup

```bash
git clone <your fork>
cd privacylint
npm install                 # installs deps; downloads Chromium via Playwright
npm run build               # compile TypeScript -> dist/
npm test                    # fast, browserless unit suite
npm run test:e2e            # browser end-to-end suite (needs Chromium installed)
npm run typecheck           # strict type-check the source
npm run test:typecheck      # type-check sources + tests together
```

Node.js **>= 18** is required. The project is ESM and written in strict
TypeScript (`exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`, and the
rest of `strict` are all on). CI runs the type-checks, build, and unit tests on
Node 18/20/22, plus a separate browser **e2e** job — keep them green.

The unit suite is deliberately browserless (it can run with
`npm ci --ignore-scripts`). Anything that needs a real page belongs in
`test/e2e.test.ts`, which launches Chromium via `scan()`.

## Project layout

| Path | Purpose |
| --- | --- |
| `src/types.ts` | All shared types — the single source of truth. |
| `src/scanner.ts` | Capture, decoding, leak detection, rule engine, `scan()`. |
| `src/cli.ts` | Argument/config parsing, reporters (human/JSON/SARIF), `main()`. |
| `test/` | `node:test` unit tests (no network/browser required). |

## Adding a tracker signature

Append an entry to `DEFAULT_TRACKERS` in `src/scanner.ts` with the vendor name,
the URL markers that uniquely identify its endpoints, and a `TrackerCategory`.
Add a case to the `attributeTracker recognises newly added vendors` test.

## Adding a detection rule

Rules implement the `AuditRule` interface and **must be pure and never throw**.
Use the `makeSeededCategoryRule` factory for category-based rules, or write a
bespoke `evaluate(context)` like `genericPatternRule`. Register it in
`DEFAULT_RULES` and add a test covering both a positive and a clean case.

## Pull request checklist

- [ ] `npm run typecheck && npm run test:typecheck` pass.
- [ ] `npm run build` succeeds.
- [ ] `npm test` passes, and new behaviour has tests.
- [ ] No real secrets, credentials, or user PII in code, tests, or fixtures.
- [ ] Public API or flag changes are reflected in `README.md` and `--help`.
- [ ] User-facing changes have a `CHANGELOG.md` entry under "Unreleased".

By contributing you agree your contributions are licensed under the project's
license (see [README — License](README.md#license)).
