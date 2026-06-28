/**
 * Unit tests for the PrivacyLint CLI argument parser and configuration builder.
 *
 * Importing `../src/cli.js` is side-effect-free thanks to the `isInvokedDirectly`
 * guard, so these tests can call `parseArgs` / `buildConfig` directly without
 * launching a browser scan.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  buildConfig,
  loadConfigFile,
  parseArgs,
  parseConfigObject,
  renderSarif,
} from '../src/cli.js';
import { LeakEncoding, PayloadSource, PiiCategory, Severity, TrackerCategory } from '../src/types.js';
import type { ScanResult } from '../src/types.js';

test('parseArgs reads a URL target and a categorised input', () => {
  const parsed = parseArgs(['--url', 'https://example.com', '--input', 'input[name=email]=a@b.com:email']);
  assert.equal(parsed.url, 'https://example.com');
  assert.equal(parsed.inputs.length, 1);
  assert.equal(parsed.inputs[0]!.selector, 'input[name=email]');
  assert.equal(parsed.inputs[0]!.value, 'a@b.com');
  assert.equal(parsed.inputs[0]!.category, PiiCategory.Email);
  assert.equal(parsed.errors.length, 0);
});

test('parseArgs handles a CSS attribute selector that itself contains "=" (regression)', () => {
  const parsed = parseArgs([
    '--url',
    'https://example.com',
    '--input',
    'input[name=email][type=text]=alice@example.com:email',
  ]);
  assert.equal(parsed.errors.length, 0);
  assert.equal(parsed.inputs[0]!.selector, 'input[name=email][type=text]');
  assert.equal(parsed.inputs[0]!.value, 'alice@example.com');
  assert.equal(parsed.inputs[0]!.category, PiiCategory.Email);
});

test('parseArgs preserves "=" inside the value (e.g. base64 padding)', () => {
  const parsed = parseArgs(['--url', 'https://example.com', '--input', '#token=YWJjZA==:secret']);
  assert.equal(parsed.inputs[0]!.selector, '#token');
  assert.equal(parsed.inputs[0]!.value, 'YWJjZA==');
});

test('parseArgs defaults an input without a category suffix to generic_secret', () => {
  const parsed = parseArgs(['--url', 'https://example.com', '--input', '#token=abc123']);
  assert.equal(parsed.inputs[0]!.category, PiiCategory.GenericSecret);
  assert.equal(parsed.inputs[0]!.value, 'abc123');
});

test('parseArgs records an error for a malformed input spec', () => {
  const parsed = parseArgs(['--input', 'no-equals-sign']);
  assert.equal(parsed.errors.length >= 1, true);
});

test('parseArgs parses rule overrides including off', () => {
  const parsed = parseArgs([
    '--url',
    'https://example.com',
    '--rule',
    'no-name-in-tracker=error',
    '--rule',
    'no-pii-pattern-in-tracker=off',
  ]);
  assert.equal(parsed.severityOverrides['no-name-in-tracker'], Severity.Error);
  assert.equal(parsed.severityOverrides['no-pii-pattern-in-tracker'], 'off');
});

test('parseArgs parses a custom tracker definition', () => {
  const parsed = parseArgs(['--url', 'https://example.com', '--tracker', 'Acme=acme.io/collect,acme-cdn.net']);
  assert.equal(parsed.extraTrackers.length, 1);
  assert.equal(parsed.extraTrackers[0]!.vendor, 'Acme');
  assert.deepEqual(parsed.extraTrackers[0]!.urlMarkers, ['acme.io/collect', 'acme-cdn.net']);
});

test('parseArgs flags a missing value after a flag', () => {
  const parsed = parseArgs(['--url']);
  assert.equal(parsed.errors.some((e) => e.includes('requires a value')), true);
});

test('parseArgs reports unknown flags', () => {
  const parsed = parseArgs(['--definitely-not-a-flag']);
  assert.equal(parsed.errors.some((e) => e.includes('Unknown argument')), true);
});

test('parseArgs honours --settle and rejects a negative value', () => {
  assert.equal(parseArgs(['--url', 'https://x.com', '--settle', '5000']).settleTimeoutMs, 5000);
  assert.equal(parseArgs(['--url', 'https://x.com', '--settle', '-3']).errors.length >= 1, true);
});

test('buildConfig rejects when no target is given', async () => {
  const result = await buildConfig(parseArgs([]));
  assert.equal(Array.isArray(result), true);
  assert.equal((result as string[]).some((e) => e.includes('target is required')), true);
});

test('buildConfig rejects when both --url and --file are given', async () => {
  const result = await buildConfig(parseArgs(['--url', 'https://x.com', '--file', './nope.html']));
  assert.equal(Array.isArray(result), true);
  assert.equal((result as string[]).some((e) => e.includes('not both')), true);
});

test('buildConfig rejects a non-http(s) URL scheme', async () => {
  const result = await buildConfig(parseArgs(['--url', 'ftp://example.com']));
  assert.equal(Array.isArray(result), true);
  assert.equal((result as string[]).some((e) => e.includes('http or https')), true);
});

test('buildConfig rejects a --file that does not exist', async () => {
  const result = await buildConfig(parseArgs(['--file', '/path/that/does/not/exist-9f3a.html']));
  assert.equal(Array.isArray(result), true);
});

test('buildConfig produces a valid config for a well-formed URL invocation', async () => {
  const result = await buildConfig(
    parseArgs([
      '--url',
      'https://example.com/signup',
      '--input',
      'input[type=password]=p@ss:password',
      '--submit',
      'button[type=submit]',
      '--fail-on',
      'warning',
    ]),
  );
  assert.equal(Array.isArray(result), false);
  if (Array.isArray(result)) {
    return;
  }
  assert.equal(result.target.kind, 'url');
  assert.equal(result.submitSelector, 'button[type=submit]');
  assert.equal(result.failOn, Severity.Warning);
  assert.equal(result.mockInputs.length, 1);
});

/* -------------------------------------------------------------------------- */
/* Config file: parsing & validation                                           */
/* -------------------------------------------------------------------------- */

test('parseConfigObject accepts a well-formed config', () => {
  const result = parseConfigObject(
    {
      url: 'https://example.com/signup',
      inputs: [{ selector: '#email', value: 'a@b.com', category: 'email' }],
      secrets: [{ label: 'apikey', value: 'sk-123', category: 'secret' }],
      submit: 'button[type=submit]',
      settle: 4000,
      headless: true,
      failOn: 'warning',
      acceptConsent: true,
      consentSelectors: ['#my-accept'],
      rules: { 'no-name-in-tracker': 'error', 'no-pii-pattern-in-tracker': 'off' },
      trackers: [{ vendor: 'Acme', urlMarkers: ['acme.io/c'], category: 'analytics' }],
    },
    '/tmp',
  );
  assert.equal(Array.isArray(result), false);
  if (Array.isArray(result)) {
    return;
  }
  assert.equal(result.url, 'https://example.com/signup');
  assert.equal(result.inputs[0]!.category, PiiCategory.Email);
  assert.equal(result.secrets[0]!.plaintext, 'sk-123');
  assert.equal(result.settle, 4000);
  assert.equal(result.acceptConsent, true);
  assert.deepEqual(result.consentSelectors, ['#my-accept']);
  assert.equal(result.failOn, Severity.Warning);
  assert.equal(result.rules['no-pii-pattern-in-tracker'], 'off');
  assert.equal(result.trackers[0]!.vendor, 'Acme');
});

test('parseConfigObject rejects an unknown top-level key', () => {
  const result = parseConfigObject({ url: 'https://x.com', wat: 1 }, '/tmp');
  assert.equal(Array.isArray(result), true);
  assert.equal((result as string[]).some((e) => e.includes('unknown key')), true);
});

test('parseConfigObject rejects a wrong-typed scalar', () => {
  const result = parseConfigObject({ settle: 'soon' }, '/tmp');
  assert.equal(Array.isArray(result), true);
  assert.equal((result as string[]).some((e) => e.includes('settle')), true);
});

test('loadConfigFile returns errors for an explicit missing path', async () => {
  const result = await loadConfigFile('/does/not/exist-privacylint-7f3.json');
  assert.equal(Array.isArray(result), true);
});

/* -------------------------------------------------------------------------- */
/* Config file: merge precedence with CLI                                      */
/* -------------------------------------------------------------------------- */

test('buildConfig merges a config file and lets CLI flags override scalars', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'privacylint-'));
  const cfgPath = join(dir, 'privacylint.config.json');
  await writeFile(
    cfgPath,
    JSON.stringify({
      url: 'https://example.com/signup',
      inputs: [{ selector: '#email', value: 'a@b.com', category: 'email' }],
      failOn: 'warning',
      acceptConsent: true,
    }),
    'utf8',
  );

  // Config alone: failOn = warning, acceptConsent = true, one input from file.
  const fromFile = await buildConfig(parseArgs(['--config', cfgPath]));
  assert.equal(Array.isArray(fromFile), false);
  if (Array.isArray(fromFile)) {
    return;
  }
  assert.equal(fromFile.target.kind, 'url');
  assert.equal(fromFile.failOn, Severity.Warning);
  assert.equal(fromFile.acceptConsent, true);
  assert.equal(fromFile.mockInputs.length, 1);

  // CLI override wins for the scalar, and arrays merge (file input + CLI input).
  const overridden = await buildConfig(
    parseArgs(['--config', cfgPath, '--fail-on', 'error', '--input', '#pw=secret:password']),
  );
  assert.equal(Array.isArray(overridden), false);
  if (Array.isArray(overridden)) {
    return;
  }
  assert.equal(overridden.failOn, Severity.Error);
  assert.equal(overridden.mockInputs.length, 2);
});

/* -------------------------------------------------------------------------- */
/* SARIF output                                                                */
/* -------------------------------------------------------------------------- */

function sampleResult(): ScanResult {
  return {
    config: {
      target: { kind: 'url', url: 'https://example.com/signup' },
      mockInputs: [],
      extraSecrets: [],
      submitSelector: null,
      settleTimeoutMs: 2500,
      headless: true,
      acceptConsent: false,
      consentSelectors: [],
      severityOverrides: {},
      failOn: Severity.Error,
      extraTrackers: [],
    },
    requests: [],
    trackerRequests: [],
    violations: [
      {
        ruleId: 'no-email-in-tracker',
        severity: Severity.Error,
        message: 'an email address (field "cd[em]") was sent to Meta Pixel as a SHA-256 hash.',
        request: {
          id: 1,
          url: 'https://www.facebook.com/tr/?id=1&cd[em]=2a',
          host: 'www.facebook.com',
          method: 'GET',
          resourceType: 'image',
          timestamp: 0,
          headers: {},
          postData: null,
          fields: [],
          tracker: { vendor: 'Meta Pixel', urlMarkers: ['facebook.com/tr'], category: TrackerCategory.Advertising },
        },
        evidence: {
          field: { path: 'cd[em]', value: '2a', source: PayloadSource.QueryString },
          category: PiiCategory.Email,
          encoding: LeakEncoding.Sha256,
          redactedPreview: '2a***1c',
          matchedSecretLabel: 'email',
        },
        remediation: 'Do not transmit raw or hashed email to ad networks.',
      },
    ],
    tally: { info: 0, warning: 0, error: 1, total: 1 },
    durationMs: 10,
    failed: true,
    diagnostics: [],
  };
}

test('renderSarif produces a valid SARIF 2.1.0 document with mapped results', () => {
  const sarif = JSON.parse(renderSarif(sampleResult())) as {
    version: string;
    runs: Array<{
      tool: { driver: { name: string; rules: unknown[] } };
      results: Array<{ ruleId: string; level: string; message: { text: string } }>;
    }>;
  };
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0]!.tool.driver.name, 'PrivacyLint');
  assert.equal(sarif.runs[0]!.tool.driver.rules.length > 0, true);
  assert.equal(sarif.runs[0]!.results.length, 1);
  assert.equal(sarif.runs[0]!.results[0]!.ruleId, 'no-email-in-tracker');
  assert.equal(sarif.runs[0]!.results[0]!.level, 'error');
});

test('renderSarif maps severities to SARIF levels (warning->warning, info->note)', () => {
  const base = sampleResult();
  const warned: ScanResult = {
    ...base,
    violations: [
      { ...base.violations[0]!, severity: Severity.Warning },
      { ...base.violations[0]!, severity: Severity.Info },
    ],
  };
  const sarif = JSON.parse(renderSarif(warned)) as {
    runs: Array<{ results: Array<{ level: string }> }>;
  };
  const levels = sarif.runs[0]!.results.map((r) => r.level);
  assert.deepEqual(levels, ['warning', 'note']);
});
