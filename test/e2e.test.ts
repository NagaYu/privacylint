/**
 * End-to-end tests for PrivacyLint.
 *
 * Unlike the unit suites, these launch a REAL headless Chromium via `scan()`
 * against local HTML fixtures and assert on the captured network behaviour. They
 * therefore require a Playwright Chromium build to be installed
 * (`npx playwright install chromium`) and are run via the dedicated
 * `npm run test:e2e` script — they are intentionally excluded from the fast,
 * browserless `npm test` suite.
 *
 * Each fixture builds the tracker URL dynamically from a form value, so the
 * leaked email never appears in the page source. That isolates the BROWSER
 * capture path: any email finding here can only have come from a real outbound
 * request, not from the static source scanner.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan } from '../src/scanner.js';
import { PiiCategory, Severity } from '../src/types.js';
import type { MockInput, ScanConfig } from '../src/types.js';

/** Build a full file-target scan config with sensible E2E defaults. */
function fileConfig(
  path: string,
  opts: { inputs?: MockInput[]; submit?: string | null; acceptConsent?: boolean } = {},
): ScanConfig {
  return {
    target: { kind: 'file', path },
    mockInputs: opts.inputs ?? [],
    extraSecrets: [],
    submitSelector: opts.submit ?? null,
    settleTimeoutMs: 800,
    headless: true,
    acceptConsent: opts.acceptConsent ?? false,
    consentSelectors: [],
    severityOverrides: {},
    failOn: Severity.Error,
    extraTrackers: [],
  };
}

/** Write a fixture into a fresh temp dir and return its absolute path. */
async function writeFixture(name: string, html: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'privacylint-e2e-'));
  const path = join(dir, name);
  await writeFile(path, html, 'utf8');
  return path;
}

const emailInput: MockInput = {
  selector: '#email',
  value: 'victim@example.com',
  category: PiiCategory.Email,
  label: 'email',
};

/* -------------------------------------------------------------------------- */

test('E2E: a runtime beacon leaking an email to Meta Pixel is detected', async () => {
  // The email is read from the input at click time; it is NOT in the source.
  const path = await writeFixture(
    'leak.html',
    `<!doctype html><html><body>
      <input id="email" value="">
      <button id="submit">Sign up</button>
      <script>
        var base = "https://www.facebook.com/tr/?id=1&ev=Lead&cd[em]=";
        document.getElementById('submit').addEventListener('click', function () {
          navigator.sendBeacon(base + document.getElementById('email').value);
        });
      </script>
    </body></html>`,
  );

  const result = await scan(fileConfig(path, { inputs: [emailInput], submit: '#submit' }));

  const emailLeak = result.violations.find((v) => v.ruleId === 'no-email-in-tracker');
  assert.ok(emailLeak, 'expected a no-email-in-tracker violation');
  assert.equal(emailLeak.severity, Severity.Error);
  // The finding must come from a real outbound request to Meta, not the static scan.
  assert.match(emailLeak.request.url, /facebook\.com\/tr/);
  assert.equal(emailLeak.request.tracker?.vendor, 'Meta Pixel');
  assert.ok(result.trackerRequests.length > 0, 'expected at least one tracker request');
  assert.equal(result.failed, true);
});

test('E2E: a consent-gated tag is dormant without --accept-consent and fires with it', async () => {
  const html = `<!doctype html><html><body>
      <input id="email" value="">
      <button id="onetrust-accept-btn-handler">Accept all</button>
      <button id="submit">Sign up</button>
      <script>
        var consented = false;
        var base = "https://www.facebook.com/tr/?id=1&ev=Lead&cd[em]=";
        document.getElementById('onetrust-accept-btn-handler')
          .addEventListener('click', function () { consented = true; });
        document.getElementById('submit').addEventListener('click', function () {
          if (consented) { navigator.sendBeacon(base + document.getElementById('email').value); }
        });
      </script>
    </body></html>`;

  const pathA = await writeFixture('consent-a.html', html);
  const withoutConsent = await scan(
    fileConfig(pathA, { inputs: [emailInput], submit: '#submit', acceptConsent: false }),
  );
  assert.equal(
    withoutConsent.violations.some((v) => v.ruleId === 'no-email-in-tracker'),
    false,
    'tag should stay dormant when consent is not granted',
  );

  const pathB = await writeFixture('consent-b.html', html);
  const withConsent = await scan(
    fileConfig(pathB, { inputs: [emailInput], submit: '#submit', acceptConsent: true }),
  );
  assert.equal(
    withConsent.violations.some((v) => v.ruleId === 'no-email-in-tracker'),
    true,
    'tag should fire once consent is accepted',
  );
});

test('E2E: a tracker that carries no PII produces no violations (no false positive)', async () => {
  const path = await writeFixture(
    'clean.html',
    `<!doctype html><html><body>
      <script>
        // A bare PageView beacon — contacts Meta but carries no personal data.
        navigator.sendBeacon("https://www.facebook.com/tr/?id=1&ev=PageView");
      </script>
    </body></html>`,
  );

  const result = await scan(fileConfig(path));
  assert.equal(result.violations.length, 0, 'a PII-free tracker request must not be flagged');
  assert.ok(
    result.trackerRequests.some((r) => r.tracker?.vendor === 'Meta Pixel'),
    'the tracker should still be recorded as contacted',
  );
  assert.equal(result.failed, false);
});
