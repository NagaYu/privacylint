/**
 * Unit tests for the PrivacyLint core engine.
 *
 * These tests exercise the pure, browser-independent logic: secret compilation
 * and matching across every encoding, the redaction helper, tracker
 * attribution, the static co-location scanner (false-positive resistance), and
 * the rule engine itself. They run with the built-in `node:test` runner and
 * require no network or browser.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  DEFAULT_CONSENT_SELECTORS,
  DEFAULT_RULES,
  DEFAULT_TRACKERS,
  STATIC_PROXIMITY_WINDOW,
  analyzeStaticSource,
  attributeTracker,
  compileSecret,
  findColocatedLeaks,
  redact,
  representationFor,
  matchSecretInValue,
} from '../src/scanner.js';
import { LeakEncoding, PayloadSource, PiiCategory, Severity } from '../src/types.js';
import type {
  AuditRule,
  CapturedRequest,
  PayloadField,
  RuleContext,
  SeededSecret,
  TrackerSignature,
} from '../src/types.js';

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

function md5Hex(input: string): string {
  return createHash('md5').update(input, 'utf8').digest('hex');
}

/** Build a captured request from a flat field list for rule-engine tests. */
function makeRequest(params: {
  fields: PayloadField[];
  tracker: TrackerSignature | null;
  url?: string;
}): CapturedRequest {
  return {
    id: 1,
    url: params.url ?? 'https://www.facebook.com/tr/',
    host: 'www.facebook.com',
    method: 'POST',
    resourceType: 'xhr',
    timestamp: 0,
    headers: {},
    postData: null,
    fields: params.fields,
    tracker: params.tracker,
  };
}

function field(path: string, value: string): PayloadField {
  return { path, value, source: PayloadSource.FormBody };
}

function ruleById(id: string): AuditRule {
  const rule = DEFAULT_RULES.find((candidate) => candidate.id === id);
  assert.ok(rule, `expected rule ${id} to exist`);
  return rule;
}

const metaPixel = attributeTracker('https://www.facebook.com/tr/', DEFAULT_TRACKERS);

/* -------------------------------------------------------------------------- */
/* redact()                                                                    */
/* -------------------------------------------------------------------------- */

test('redact masks the middle of a value, keeping head and tail', () => {
  const out = redact('S3cr3t-Canary!');
  assert.equal(out.startsWith('S3'), true);
  assert.equal(out.endsWith('!'), true);
  assert.equal(out.includes('cr3t'), false);
});

test('redact fully masks very short values', () => {
  assert.equal(redact('abcd'), '****');
  assert.equal(redact('xy'), '**');
});

test('redact truncates very long values before masking', () => {
  const out = redact('a'.repeat(500));
  assert.ok(out.length < 120);
});

/* -------------------------------------------------------------------------- */
/* attributeTracker()                                                          */
/* -------------------------------------------------------------------------- */

test('attributeTracker recognises Meta Pixel and Google Analytics', () => {
  assert.equal(attributeTracker('https://www.facebook.com/tr/?id=1', DEFAULT_TRACKERS)?.vendor, 'Meta Pixel');
  assert.equal(
    attributeTracker('https://www.google-analytics.com/g/collect', DEFAULT_TRACKERS)?.vendor,
    'Google Analytics',
  );
});

test('attributeTracker returns null for first-party origins', () => {
  assert.equal(attributeTracker('https://example.com/api/login', DEFAULT_TRACKERS), null);
});

test('attributeTracker prefers operator-supplied trackers (precedence order)', () => {
  const extra: TrackerSignature[] = [
    { vendor: 'Custom CDP', urlMarkers: ['cdp.internal'], category: DEFAULT_TRACKERS[0]!.category },
  ];
  const all = [...extra, ...DEFAULT_TRACKERS];
  assert.equal(attributeTracker('https://cdp.internal/collect', all)?.vendor, 'Custom CDP');
});

/* -------------------------------------------------------------------------- */
/* compileSecret() + matchSecretInValue()                                      */
/* -------------------------------------------------------------------------- */

test('matchSecretInValue detects a plaintext leak (case-insensitive)', () => {
  const secret = compileSecret({ category: PiiCategory.Email, label: 'email', plaintext: 'alice@example.com' });
  assert.equal(matchSecretInValue('em=ALICE@EXAMPLE.COM&x=1', secret), LeakEncoding.Plaintext);
});

test('matchSecretInValue detects a URL-encoded leak', () => {
  const secret = compileSecret({ category: PiiCategory.Email, label: 'email', plaintext: 'a b@example.com' });
  const encoded = encodeURIComponent('a b@example.com'); // a%20b%40example.com
  assert.equal(matchSecretInValue(`q=${encoded}`, secret), LeakEncoding.UrlEncoded);
});

test('matchSecretInValue detects a Base64 leak', () => {
  const secret = compileSecret({ category: PiiCategory.Password, label: 'pw', plaintext: 'S3cr3t-Canary!' });
  const b64 = Buffer.from('S3cr3t-Canary!', 'utf8').toString('base64');
  assert.equal(matchSecretInValue(`blob=${b64}`, secret), LeakEncoding.Base64);
});

test('matchSecretInValue detects an MD5-hashed leak', () => {
  const secret = compileSecret({ category: PiiCategory.Email, label: 'email', plaintext: 'alice@example.com' });
  assert.equal(matchSecretInValue(`h=${md5Hex('alice@example.com')}`, secret), LeakEncoding.Md5);
});

test('matchSecretInValue detects a SHA-256 leak of a canonicalised variant', () => {
  // The plaintext is mixed-case, but trackers hash the trimmed/lower-cased form.
  const secret = compileSecret({ category: PiiCategory.Email, label: 'email', plaintext: '  Alice@Example.com ' });
  const canonicalDigest = sha256Hex('alice@example.com');
  assert.equal(matchSecretInValue(`em=${canonicalDigest}`, secret), LeakEncoding.Sha256);
});

test('matchSecretInValue returns null when the secret is absent', () => {
  const secret = compileSecret({ category: PiiCategory.Email, label: 'email', plaintext: 'alice@example.com' });
  assert.equal(matchSecretInValue('utm_source=newsletter&page=home', secret), null);
});

test('representationFor round-trips every supported encoding into a matchable form', () => {
  const secret = compileSecret({ category: PiiCategory.Email, label: 'email', plaintext: 'alice@example.com' });
  for (const encoding of [
    LeakEncoding.Plaintext,
    LeakEncoding.UrlEncoded,
    LeakEncoding.Base64,
    LeakEncoding.Md5,
    LeakEncoding.Sha256,
  ]) {
    const representation = representationFor(secret, encoding);
    assert.ok(representation, `expected a representation for ${encoding}`);
    assert.equal(matchSecretInValue(representation, secret), encoding);
  }
});

/* -------------------------------------------------------------------------- */
/* Rule engine                                                                 */
/* -------------------------------------------------------------------------- */

function evaluate(_ruleId: string, request: CapturedRequest, secrets: SeededSecret[]): RuleContext {
  return { request, seededSecrets: secrets, originHost: 'example.com' };
}

test('no-password-in-tracker fires (error) when a password reaches a tracker', () => {
  const rule = ruleById('no-password-in-tracker');
  const secrets: SeededSecret[] = [{ category: PiiCategory.Password, label: 'pw', plaintext: 'S3cr3t-Canary!' }];
  const request = makeRequest({ fields: [field('pw', 'S3cr3t-Canary!')], tracker: metaPixel });
  const result = rule.evaluate(evaluate('no-password-in-tracker', request, secrets));
  assert.equal(result.violations.length, 1);
  assert.equal(result.violations[0]!.severity, Severity.Error);
  assert.equal(result.violations[0]!.evidence.encoding, LeakEncoding.Plaintext);
});

test('no-password-in-tracker does NOT fire for first-party requests', () => {
  const rule = ruleById('no-password-in-tracker');
  const secrets: SeededSecret[] = [{ category: PiiCategory.Password, label: 'pw', plaintext: 'S3cr3t-Canary!' }];
  const request = makeRequest({ fields: [field('pw', 'S3cr3t-Canary!')], tracker: null });
  const result = rule.evaluate(evaluate('no-password-in-tracker', request, secrets));
  assert.equal(result.violations.length, 0);
});

test('no-email-in-tracker flags a SHA-256 hashed email', () => {
  const rule = ruleById('no-email-in-tracker');
  const secrets: SeededSecret[] = [{ category: PiiCategory.Email, label: 'email', plaintext: 'alice@example.com' }];
  const request = makeRequest({ fields: [field('cd[em]', sha256Hex('alice@example.com'))], tracker: metaPixel });
  const result = rule.evaluate(evaluate('no-email-in-tracker', request, secrets));
  assert.equal(result.violations.length, 1);
  assert.equal(result.violations[0]!.evidence.encoding, LeakEncoding.Sha256);
});

test('no-pii-pattern-in-tracker flags a Luhn-valid card but not an invalid one', () => {
  const rule = ruleById('no-pii-pattern-in-tracker');
  const validCard = makeRequest({ fields: [field('value', '4242 4242 4242 4242')], tracker: metaPixel });
  const invalidCard = makeRequest({ fields: [field('value', '1234 5678 9012 3456')], tracker: metaPixel });
  assert.equal(rule.evaluate(evaluate('x', validCard, [])).violations.length >= 1, true);
  const invalidFindings = rule
    .evaluate(evaluate('x', invalidCard, []))
    .violations.filter((v) => v.evidence.category === PiiCategory.CreditCard);
  assert.equal(invalidFindings.length, 0);
});

test('no-pii-pattern-in-tracker flags an email pattern with no seeding', () => {
  const rule = ruleById('no-pii-pattern-in-tracker');
  const request = makeRequest({ fields: [field('payload', 'user=bob@contoso.com')], tracker: metaPixel });
  const emails = rule
    .evaluate(evaluate('x', request, []))
    .violations.filter((v) => v.evidence.category === PiiCategory.Email);
  assert.equal(emails.length, 1);
});

test('every rule is a no-op on a clean tracker payload', () => {
  const request = makeRequest({ fields: [field('utm_source', 'newsletter')], tracker: metaPixel });
  for (const rule of DEFAULT_RULES) {
    const result = rule.evaluate(evaluate(rule.id, request, []));
    assert.equal(result.violations.length, 0, `${rule.id} produced a false positive`);
  }
});

/* -------------------------------------------------------------------------- */
/* Static co-location scanner (precision)                                       */
/* -------------------------------------------------------------------------- */

test('findColocatedLeaks flags a secret adjacent to a tracker marker', () => {
  const source = `<script>fbq('track','Lead',{em:'alice@example.com'});var s='facebook.com/tr';</script>`;
  const secrets = [compileSecret({ category: PiiCategory.Email, label: 'email', plaintext: 'alice@example.com' })];
  const leaks = findColocatedLeaks(source, secrets, DEFAULT_TRACKERS);
  assert.equal(leaks.length, 1);
  assert.equal(leaks[0]!.tracker.vendor, 'Meta Pixel');
  assert.equal(leaks[0]!.encoding, LeakEncoding.Plaintext);
});

test('findColocatedLeaks does NOT flag a secret far from any marker (no false positive)', () => {
  const filler = ' '.repeat(STATIC_PROXIMITY_WINDOW + 200);
  // Email at the very top, tracker marker far below — they are unrelated.
  const source = `<meta name="author" content="alice@example.com">${filler}<img src="https://www.facebook.com/tr?id=1">`;
  const secrets = [compileSecret({ category: PiiCategory.Email, label: 'email', plaintext: 'alice@example.com' })];
  const leaks = findColocatedLeaks(source, secrets, DEFAULT_TRACKERS);
  assert.equal(leaks.length, 0);
});

test('findColocatedLeaks returns nothing when there is no tracker marker at all', () => {
  const source = `<form><input value="alice@example.com"></form>`;
  const secrets = [compileSecret({ category: PiiCategory.Email, label: 'email', plaintext: 'alice@example.com' })];
  assert.equal(findColocatedLeaks(source, secrets, DEFAULT_TRACKERS).length, 0);
});

test('analyzeStaticSource produces one synthetic request per vendor, encoding preserved', () => {
  const digest = sha256Hex('alice@example.com');
  const source = `<script>var px='facebook.com/tr';var em='${digest}';</script>`;
  const requests = analyzeStaticSource(source, '/tmp/page.html', DEFAULT_TRACKERS, [
    { category: PiiCategory.Email, label: 'email', plaintext: 'alice@example.com' },
  ]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0]!.tracker?.vendor, 'Meta Pixel');
  assert.equal(requests[0]!.fields[0]!.value, digest);
  // And the rule engine should then classify it as a SHA-256 leak.
  const rule = ruleById('no-email-in-tracker');
  const result = rule.evaluate({
    request: requests[0]!,
    seededSecrets: [{ category: PiiCategory.Email, label: 'email', plaintext: 'alice@example.com' }],
    originHost: 'example.com',
  });
  assert.equal(result.violations[0]!.evidence.encoding, LeakEncoding.Sha256);
});

/* -------------------------------------------------------------------------- */
/* Expanded tracker catalogue                                                  */
/* -------------------------------------------------------------------------- */

test('attributeTracker recognises newly added vendors', () => {
  const cases: ReadonlyArray<[string, string]> = [
    ['https://ct.pinterest.com/v3/?tid=1', 'Pinterest Tag'],
    ['https://tr.snapchat.com/p', 'Snapchat Pixel'],
    ['https://static.criteo.net/js/ld/ld.js', 'Criteo'],
    ['https://trc.taboola.com/log', 'Taboola'],
    ['https://api.mixpanel.com/track', 'Mixpanel'],
    ['https://mc.yandex.ru/watch/123', 'Yandex Metrica'],
    ['https://heapanalytics.com/h', 'Heap'],
  ];
  for (const [url, vendor] of cases) {
    const tracker = attributeTracker(url, DEFAULT_TRACKERS);
    assert.equal(tracker?.vendor, vendor, `expected ${url} -> ${vendor}`);
  }
});

test('attributeTracker still returns null for first-party traffic', () => {
  assert.equal(attributeTracker('https://example.com/api/login', DEFAULT_TRACKERS), null);
});

/* -------------------------------------------------------------------------- */
/* Consent selector catalogue                                                  */
/* -------------------------------------------------------------------------- */

test('DEFAULT_CONSENT_SELECTORS is a non-empty, de-duplicated list', () => {
  assert.equal(DEFAULT_CONSENT_SELECTORS.length > 0, true);
  assert.equal(new Set(DEFAULT_CONSENT_SELECTORS).size, DEFAULT_CONSENT_SELECTORS.length);
  // Sanity: includes the most common CMP (OneTrust).
  assert.equal(DEFAULT_CONSENT_SELECTORS.includes('#onetrust-accept-btn-handler'), true);
});
