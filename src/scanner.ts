/**
 * PrivacyLint — Core audit engine.
 *
 * Responsibilities of this module:
 *
 *  1. Drive a headless Chromium instance (via Playwright) to load the target,
 *     emulate form input with seeded "known secrets", and capture every
 *     outbound network request.
 *  2. Statically inspect local HTML/JS sources for the same seeded secrets.
 *  3. Decode each captured request's payload (query string, form body, JSON
 *     body, headers) into a flat list of fields.
 *  4. Run a pluggable rule engine over those fields to detect PII that has
 *     leaked to third-party advertising / analytics endpoints — in plaintext
 *     OR in common encoded/hashed forms (URL-encoding, Base64, MD5, SHA-256).
 *  5. Aggregate the findings into a fully-typed {@link ScanResult}.
 *
 * The engine has zero side effects beyond the browser it launches: it never
 * writes files and never mutates its inputs.
 *
 * @packageDocumentation
 */

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import type { Browser, BrowserContext, Page, Request as PlaywrightRequest } from 'playwright';

import {
  LeakEncoding,
  PayloadSource,
  PiiCategory,
  SEVERITY_RANK,
  Severity,
  TrackerCategory,
} from './types.js';
import type {
  AuditRule,
  CapturedRequest,
  MockInput,
  PayloadField,
  RuleContext,
  RuleResult,
  ScanConfig,
  ScanResult,
  ScanTarget,
  SeededSecret,
  SeverityOverrides,
  TrackerSignature,
  Violation,
  ViolationEvidence,
  ViolationTally,
} from './types.js';

/* -------------------------------------------------------------------------- */
/* Default tracker signatures                                                  */
/* -------------------------------------------------------------------------- */

/**
 * The built-in catalogue of advertising / analytics endpoints PrivacyLint
 * recognises out of the box. Operators may extend this list via
 * {@link ScanConfig.extraTrackers} without modifying the engine.
 */
export const DEFAULT_TRACKERS: readonly TrackerSignature[] = Object.freeze([
  {
    vendor: 'Meta Pixel',
    category: TrackerCategory.Advertising,
    urlMarkers: ['facebook.com/tr', 'connect.facebook.net', 'fbevents.js'],
  },
  {
    vendor: 'Google Analytics',
    category: TrackerCategory.Analytics,
    urlMarkers: [
      'google-analytics.com',
      'analytics.google.com',
      'www.google-analytics.com/g/collect',
      'region1.google-analytics.com',
    ],
  },
  {
    vendor: 'Google Ads / DoubleClick',
    category: TrackerCategory.Advertising,
    urlMarkers: ['googleadservices.com', 'doubleclick.net', 'googlesyndication.com'],
  },
  {
    vendor: 'Google Tag Manager',
    category: TrackerCategory.TagManager,
    urlMarkers: ['googletagmanager.com'],
  },
  {
    vendor: 'TikTok Pixel',
    category: TrackerCategory.Advertising,
    urlMarkers: ['analytics.tiktok.com', 'business-api.tiktok.com'],
  },
  {
    vendor: 'LinkedIn Insight',
    category: TrackerCategory.Advertising,
    urlMarkers: ['px.ads.linkedin.com', 'snap.licdn.com'],
  },
  {
    vendor: 'Twitter / X Pixel',
    category: TrackerCategory.Advertising,
    urlMarkers: ['analytics.twitter.com', 't.co/i/adsct', 'ads-twitter.com'],
  },
  {
    vendor: 'Microsoft Bing / UET',
    category: TrackerCategory.Advertising,
    urlMarkers: ['bat.bing.com'],
  },
  {
    vendor: 'Hotjar (session replay)',
    category: TrackerCategory.SessionReplay,
    urlMarkers: ['hotjar.com', 'hotjar.io'],
  },
  {
    vendor: 'FullStory (session replay)',
    category: TrackerCategory.SessionReplay,
    urlMarkers: ['fullstory.com', 'fs.js'],
  },
  {
    vendor: 'Segment',
    category: TrackerCategory.Analytics,
    urlMarkers: ['api.segment.io', 'cdn.segment.com'],
  },
  {
    vendor: 'Pinterest Tag',
    category: TrackerCategory.Advertising,
    urlMarkers: ['ct.pinterest.com', 's.pinimg.com/ct'],
  },
  {
    vendor: 'Snapchat Pixel',
    category: TrackerCategory.Advertising,
    urlMarkers: ['tr.snapchat.com', 'sc-static.net'],
  },
  {
    vendor: 'Reddit Pixel',
    category: TrackerCategory.Advertising,
    urlMarkers: ['alb.reddit.com', 'pixel.reddit.com', 'events.reddit.com'],
  },
  {
    vendor: 'Criteo',
    category: TrackerCategory.Advertising,
    urlMarkers: ['static.criteo.net', 'bidder.criteo.com', 'sslwidget.criteo.com'],
  },
  {
    vendor: 'Taboola',
    category: TrackerCategory.Advertising,
    urlMarkers: ['trc.taboola.com', 'cdn.taboola.com'],
  },
  {
    vendor: 'Outbrain',
    category: TrackerCategory.Advertising,
    urlMarkers: ['tr.outbrain.com', 'amplify.outbrain.com'],
  },
  {
    vendor: 'Amazon Ads',
    category: TrackerCategory.Advertising,
    urlMarkers: ['s.amazon-adsystem.com', 'aax.amazon-adsystem.com'],
  },
  {
    vendor: 'Adobe Analytics (Omniture)',
    category: TrackerCategory.Analytics,
    urlMarkers: ['.sc.omtrdc.net', '2o7.net', 'demdex.net'],
  },
  {
    vendor: 'Quantcast',
    category: TrackerCategory.Analytics,
    urlMarkers: ['pixel.quantserve.com', 'secure.quantserve.com'],
  },
  {
    vendor: 'Yandex Metrica',
    category: TrackerCategory.Analytics,
    urlMarkers: ['mc.yandex.ru', 'mc.yandex.com'],
  },
  {
    vendor: 'Mixpanel',
    category: TrackerCategory.Analytics,
    urlMarkers: ['api.mixpanel.com', 'cdn.mxpnl.com'],
  },
  {
    vendor: 'Amplitude',
    category: TrackerCategory.Analytics,
    urlMarkers: ['api.amplitude.com', 'api2.amplitude.com', 'cdn.amplitude.com'],
  },
  {
    vendor: 'Heap',
    category: TrackerCategory.Analytics,
    urlMarkers: ['heapanalytics.com'],
  },
  {
    vendor: 'Klaviyo',
    category: TrackerCategory.Advertising,
    urlMarkers: ['a.klaviyo.com', 'static.klaviyo.com'],
  },
  {
    vendor: 'Salesforce Pardot',
    category: TrackerCategory.Advertising,
    urlMarkers: ['pi.pardot.com', '.pardot.com'],
  },
  {
    vendor: 'HubSpot',
    category: TrackerCategory.Analytics,
    urlMarkers: ['track.hubspot.com', 'js.hs-analytics.net', 'js.hs-scripts.com'],
  },
]);

/* -------------------------------------------------------------------------- */
/* Encoding / hashing helpers                                                  */
/* -------------------------------------------------------------------------- */

/** Compute the lowercase hex MD5 digest of a UTF-8 string. */
function md5Hex(input: string): string {
  return createHash('md5').update(input, 'utf8').digest('hex');
}

/** Compute the lowercase hex SHA-256 digest of a UTF-8 string. */
function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/** Standard Base64 encoding of a UTF-8 string. */
function base64(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64');
}

/** URL-encoded form of a string. */
function urlEncoded(input: string): string {
  return encodeURIComponent(input);
}

/**
 * A precomputed set of every representation of a single secret that the scanner
 * will hunt for inside payloads. Keeping all forms precomputed makes per-field
 * matching a cheap set of substring tests rather than repeated hashing.
 */
export interface CompiledSecret {
  readonly category: PiiCategory;
  readonly label: string;
  readonly plaintext: string;
  /** Lower-cased plaintext needle. */
  readonly plaintextNeedle: string;
  /** Lower-cased URL-encoded needle. */
  readonly urlNeedle: string;
  /** Case-sensitive Base64 needle. */
  readonly base64Needle: string;
  /** Lower-cased hex MD5 digests of every canonical variant. */
  readonly md5Set: readonly string[];
  /** Lower-cased hex SHA-256 digests of every canonical variant. */
  readonly sha256Set: readonly string[];
}

/**
 * Trackers frequently lower-case or trim values (especially emails) before
 * hashing. To avoid false negatives we hash a few canonical variants of the
 * plaintext and search for all of them.
 */
function canonicalVariants(plaintext: string, category: PiiCategory): string[] {
  const variants = new Set<string>();
  variants.add(plaintext);
  variants.add(plaintext.trim());
  variants.add(plaintext.toLowerCase());
  variants.add(plaintext.trim().toLowerCase());
  if (category === PiiCategory.PhoneNumber) {
    // Trackers often strip non-digits from phone numbers before hashing.
    variants.add(plaintext.replace(/[^0-9]/g, ''));
  }
  if (category === PiiCategory.CreditCard) {
    variants.add(plaintext.replace(/[^0-9]/g, ''));
  }
  return [...variants].filter((value) => value.length > 0);
}

/**
 * Compile a {@link CompiledSecret} for a seeded secret. We index plaintext and
 * encoded forms; for hashed forms we index every canonical variant so that
 * "lower-cased then hashed" exfiltration is still caught.
 */
export function compileSecret(secret: SeededSecret): CompiledSecret {
  const variants = canonicalVariants(secret.plaintext, secret.category);
  return {
    category: secret.category,
    label: secret.label,
    plaintext: secret.plaintext,
    // Plaintext / URL-encoded / Base64 are matched against the exact plaintext to
    // avoid pathological false positives on very short normalised variants.
    plaintextNeedle: secret.plaintext.toLowerCase(),
    urlNeedle: urlEncoded(secret.plaintext).toLowerCase(),
    base64Needle: base64(secret.plaintext),
    md5Set: variants.map(md5Hex),
    sha256Set: variants.map(sha256Hex),
  };
}

/**
 * Return the concrete string representation of a secret in a given encoding, or
 * `null` when no representation is available. Used by the static scanner to
 * synthesise a payload field whose value faithfully reflects how the leak was
 * encoded, so the downstream rules report the correct {@link LeakEncoding}.
 */
export function representationFor(secret: CompiledSecret, encoding: LeakEncoding): string | null {
  switch (encoding) {
    case LeakEncoding.Plaintext:
      return secret.plaintext;
    case LeakEncoding.UrlEncoded:
      return urlEncoded(secret.plaintext);
    case LeakEncoding.Base64:
      return secret.base64Needle;
    case LeakEncoding.Md5:
      return secret.md5Set[0] ?? null;
    case LeakEncoding.Sha256:
      return secret.sha256Set[0] ?? null;
    case LeakEncoding.PatternMatch:
      return secret.plaintext;
    default:
      return null;
  }
}

/**
 * Test whether a single payload field value contains any representation of a
 * secret. Returns the {@link LeakEncoding} that matched, or `null`. The order of
 * checks is from the most specific/least ambiguous encoding outward.
 */
export function matchSecretInValue(value: string, secret: CompiledSecret): LeakEncoding | null {
  if (value.length === 0) {
    return null;
  }
  const lowered = value.toLowerCase();

  // 1. Plaintext (case-insensitive). Require >= 3 chars to avoid trivial hits.
  if (secret.plaintextNeedle.length >= 3 && lowered.includes(secret.plaintextNeedle)) {
    return LeakEncoding.Plaintext;
  }

  // 2. URL-encoded (only meaningful when it differs from the plaintext form).
  if (
    secret.urlNeedle.length >= 3 &&
    secret.urlNeedle !== secret.plaintextNeedle &&
    lowered.includes(secret.urlNeedle)
  ) {
    return LeakEncoding.UrlEncoded;
  }

  // 3. Base64 (case-sensitive — the Base64 alphabet is case-significant).
  if (secret.base64Needle.length >= 8 && value.includes(secret.base64Needle)) {
    return LeakEncoding.Base64;
  }

  // 4. MD5 — check every canonical variant digest.
  for (const digest of secret.md5Set) {
    if (lowered.includes(digest)) {
      return LeakEncoding.Md5;
    }
  }

  // 5. SHA-256 — check every canonical variant digest.
  for (const digest of secret.sha256Set) {
    if (lowered.includes(digest)) {
      return LeakEncoding.Sha256;
    }
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/* Redaction                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Produce a preview of a sensitive value that is safe to print to a terminal or
 * CI log. We reveal at most the first two and last one characters and mask the
 * remainder, never revealing more than 30% of the string.
 */
export function redact(value: string): string {
  const trimmed = value.length > 80 ? `${value.slice(0, 80)}…` : value;
  if (trimmed.length <= 4) {
    return '*'.repeat(trimmed.length);
  }
  const head = trimmed.slice(0, 2);
  const tail = trimmed.slice(-1);
  const maskedLength = Math.max(1, trimmed.length - 3);
  return `${head}${'*'.repeat(maskedLength)}${tail}`;
}

/* -------------------------------------------------------------------------- */
/* Payload decoding                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Recursively flatten a parsed JSON value into path/value pairs. Objects use
 * bracket notation (`a.b[c]`), arrays use numeric indices.
 */
function flattenJson(prefix: string, node: unknown, out: Array<{ path: string; value: string }>): void {
  if (node === null || node === undefined) {
    return;
  }
  if (typeof node === 'string') {
    out.push({ path: prefix, value: node });
    return;
  }
  if (typeof node === 'number' || typeof node === 'boolean') {
    out.push({ path: prefix, value: String(node) });
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((child, index) => {
      flattenJson(prefix.length > 0 ? `${prefix}[${index}]` : String(index), child, out);
    });
    return;
  }
  if (typeof node === 'object') {
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      const nextPrefix = prefix.length > 0 ? `${prefix}.${key}` : key;
      flattenJson(nextPrefix, child, out);
    }
  }
}

/**
 * Decode the query string of a URL into payload fields.
 */
function decodeQueryString(rawUrl: string): PayloadField[] {
  const fields: PayloadField[] = [];
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return fields;
  }
  for (const [key, value] of parsed.searchParams.entries()) {
    fields.push({ path: key, value, source: PayloadSource.QueryString });
  }
  return fields;
}

/**
 * Decode a POST body into payload fields. Supports JSON, URL-encoded form data,
 * and falls back to treating the body as an opaque raw string (so secrets can
 * still be substring-matched even when the encoding is unknown).
 */
function decodePostData(postData: string | null, contentType: string): PayloadField[] {
  const fields: PayloadField[] = [];
  if (postData === null || postData.length === 0) {
    return fields;
  }

  const normalisedType = contentType.toLowerCase();

  // JSON body.
  if (normalisedType.includes('application/json') || looksLikeJson(postData)) {
    try {
      const parsed: unknown = JSON.parse(postData);
      const leaves: Array<{ path: string; value: string }> = [];
      flattenJson('', parsed, leaves);
      for (const leaf of leaves) {
        fields.push({ path: leaf.path, value: leaf.value, source: PayloadSource.JsonBody });
      }
      // Also keep the raw body so opaque/nested-encoded secrets are still caught.
      fields.push({ path: '<raw-json-body>', value: postData, source: PayloadSource.RawBody });
      return fields;
    } catch {
      // fall through to form / raw handling
    }
  }

  // URL-encoded form body.
  if (
    normalisedType.includes('application/x-www-form-urlencoded') ||
    (postData.includes('=') && !postData.includes('\n'))
  ) {
    try {
      const params = new URLSearchParams(postData);
      let any = false;
      for (const [key, value] of params.entries()) {
        fields.push({ path: key, value, source: PayloadSource.FormBody });
        any = true;
      }
      if (any) {
        fields.push({ path: '<raw-form-body>', value: postData, source: PayloadSource.RawBody });
        return fields;
      }
    } catch {
      // fall through to raw handling
    }
  }

  // Unknown encoding — keep the whole body as a single raw field.
  fields.push({ path: '<raw-body>', value: postData, source: PayloadSource.RawBody });
  return fields;
}

/** Heuristic: does this string look like a JSON object/array literal? */
function looksLikeJson(text: string): boolean {
  const trimmed = text.trimStart();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

/**
 * Decode headers that commonly carry leaked data (cookies, custom headers).
 */
function decodeHeaders(headers: Readonly<Record<string, string>>): PayloadField[] {
  const fields: PayloadField[] = [];
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (lowerKey === 'cookie') {
      fields.push({ path: 'cookie', value, source: PayloadSource.Cookie });
    } else if (lowerKey.startsWith('x-') || lowerKey === 'referer') {
      fields.push({ path: lowerKey, value, source: PayloadSource.Header });
    }
  }
  return fields;
}

/* -------------------------------------------------------------------------- */
/* Tracker attribution                                                         */
/* -------------------------------------------------------------------------- */

/** Lower-cased host extraction that never throws. */
function hostOf(rawUrl: string): string {
  try {
    return new URL(rawUrl).host.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * Attribute a URL to a known tracker signature, or `null` if it matches none.
 * The operator's extra trackers take precedence over the built-ins.
 */
export function attributeTracker(
  rawUrl: string,
  trackers: readonly TrackerSignature[],
): TrackerSignature | null {
  const lowerUrl = rawUrl.toLowerCase();
  for (const tracker of trackers) {
    for (const marker of tracker.urlMarkers) {
      if (lowerUrl.includes(marker.toLowerCase())) {
        return tracker;
      }
    }
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* Generic PII pattern detectors (seed-independent defence in depth)           */
/* -------------------------------------------------------------------------- */

interface PiiPattern {
  readonly category: PiiCategory;
  readonly regex: RegExp;
  /** Optional extra validation (e.g. Luhn for credit cards). */
  readonly validate?: (match: string) => boolean;
}

/** Luhn checksum validation for candidate credit-card numbers. */
function passesLuhn(candidate: string): boolean {
  const digits = candidate.replace(/[^0-9]/g, '');
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    const char = digits[i];
    if (char === undefined) {
      return false;
    }
    let digit = char.charCodeAt(0) - 48;
    if (digit < 0 || digit > 9) {
      return false;
    }
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * The built-in catalogue of structural PII patterns. These fire even when no
 * secret was seeded, providing defence in depth against values the operator did
 * not explicitly type into the form.
 */
const PII_PATTERNS: readonly PiiPattern[] = Object.freeze([
  {
    category: PiiCategory.Email,
    regex: /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi,
  },
  {
    category: PiiCategory.CreditCard,
    regex: /\b(?:\d[ -]?){13,19}\b/g,
    validate: passesLuhn,
  },
  {
    category: PiiCategory.Ssn,
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
]);

/* -------------------------------------------------------------------------- */
/* Severity resolution                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Resolve a rule's effective severity given the operator's overrides. Returns
 * `null` when the rule has been switched off.
 */
function resolveSeverity(
  ruleId: string,
  defaultSeverity: Severity,
  overrides: SeverityOverrides,
): Severity | null {
  const override = overrides[ruleId];
  if (override === undefined) {
    return defaultSeverity;
  }
  if (override === 'off') {
    return null;
  }
  return override;
}

/* -------------------------------------------------------------------------- */
/* Rules                                                                       */
/* -------------------------------------------------------------------------- */

/** Friendly noun for each PII category, used in violation messages. */
const CATEGORY_LABEL: Readonly<Record<PiiCategory, string>> = Object.freeze({
  [PiiCategory.Password]: 'a password',
  [PiiCategory.Email]: 'an email address',
  [PiiCategory.CreditCard]: 'a credit-card number',
  [PiiCategory.Ssn]: 'a Social Security Number',
  [PiiCategory.PhoneNumber]: 'a phone number',
  [PiiCategory.FullName]: 'a full name',
  [PiiCategory.PostalAddress]: 'a postal address',
  [PiiCategory.DateOfBirth]: 'a date of birth',
  [PiiCategory.IpAddress]: 'an IP address',
  [PiiCategory.GenericSecret]: 'a sensitive secret',
});

/** Human description of an encoding, used in messages. */
const ENCODING_LABEL: Readonly<Record<LeakEncoding, string>> = Object.freeze({
  [LeakEncoding.Plaintext]: 'in plaintext',
  [LeakEncoding.UrlEncoded]: 'URL-encoded',
  [LeakEncoding.Base64]: 'Base64-encoded',
  [LeakEncoding.Md5]: 'as an MD5 hash',
  [LeakEncoding.Sha256]: 'as a SHA-256 hash',
  [LeakEncoding.PatternMatch]: 'matching a PII pattern',
});

/**
 * Compile the {@link CompiledSecret} objects once per scan and reuse across rules.
 */
function buildMatchers(secrets: readonly SeededSecret[]): readonly CompiledSecret[] {
  return secrets.map(compileSecret);
}

/**
 * Shared helper: scan every field of a request against the seeded-secret
 * matchers and produce evidence for each hit.
 */
function findSeededLeaks(
  context: RuleContext,
  matchers: readonly CompiledSecret[],
  categoryFilter: (category: PiiCategory) => boolean,
): ViolationEvidence[] {
  const evidence: ViolationEvidence[] = [];
  for (const field of context.request.fields) {
    for (const matcher of matchers) {
      if (!categoryFilter(matcher.category)) {
        continue;
      }
      const encoding = matchSecretInValue(field.value, matcher);
      if (encoding !== null) {
        evidence.push({
          field,
          category: matcher.category,
          encoding,
          redactedPreview: redact(field.value),
          matchedSecretLabel: matcher.label,
        });
      }
    }
  }
  return evidence;
}

/**
 * Factory that produces a rule targeting a single PII category among the seeded
 * secrets. Only requests attributed to a tracker are flagged.
 */
function makeSeededCategoryRule(params: {
  readonly id: string;
  readonly category: PiiCategory;
  readonly defaultSeverity: Severity;
  readonly remediation: string;
}): AuditRule {
  return {
    id: params.id,
    description: `Detects ${CATEGORY_LABEL[params.category]} leaking to a third-party tracker.`,
    defaultSeverity: params.defaultSeverity,
    evaluate(context: RuleContext): RuleResult {
      // Only third-party tracker traffic is in scope for exfiltration.
      if (context.request.tracker === null) {
        return { ruleId: params.id, violations: [] };
      }
      const matchers = buildMatchers(context.seededSecrets);
      const hits = findSeededLeaks(context, matchers, (c) => c === params.category);
      const violations: Violation[] = hits.map((evidence) => ({
        ruleId: params.id,
        severity: params.defaultSeverity,
        message: `${CATEGORY_LABEL[params.category]} (field "${evidence.field.path}") was sent to ${
          context.request.tracker?.vendor ?? 'a tracker'
        } ${ENCODING_LABEL[evidence.encoding]}.`,
        request: context.request,
        evidence,
        remediation: params.remediation,
      }));
      return { ruleId: params.id, violations };
    },
  };
}

/**
 * A seed-independent rule that flags structural PII patterns (emails, credit
 * cards, SSNs) found in tracker payloads even when those exact values were not
 * seeded — catching leaks that originate from app state rather than the form.
 */
const genericPatternRule: AuditRule = {
  id: 'no-pii-pattern-in-tracker',
  description: 'Detects structural PII patterns (email, credit card, SSN) in third-party tracker payloads.',
  defaultSeverity: Severity.Warning,
  evaluate(context: RuleContext): RuleResult {
    if (context.request.tracker === null) {
      return { ruleId: 'no-pii-pattern-in-tracker', violations: [] };
    }
    const violations: Violation[] = [];
    const seenKeys = new Set<string>();
    for (const field of context.request.fields) {
      for (const pattern of PII_PATTERNS) {
        // RegExp with the global flag is stateful; clone to keep this pure.
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        let match: RegExpExecArray | null = regex.exec(field.value);
        while (match !== null) {
          const candidate = match[0];
          if (pattern.validate === undefined || pattern.validate(candidate)) {
            const dedupeKey = `${field.path}::${pattern.category}::${candidate}`;
            if (!seenKeys.has(dedupeKey)) {
              seenKeys.add(dedupeKey);
              const evidence: ViolationEvidence = {
                field,
                category: pattern.category,
                encoding: LeakEncoding.PatternMatch,
                redactedPreview: redact(candidate),
                matchedSecretLabel: null,
              };
              violations.push({
                ruleId: 'no-pii-pattern-in-tracker',
                severity: Severity.Warning,
                message: `A value matching ${CATEGORY_LABEL[pattern.category]} pattern (field "${
                  field.path
                }") was sent to ${context.request.tracker?.vendor ?? 'a tracker'}.`,
                request: context.request,
                evidence,
                remediation:
                  'Confirm whether this value is real user PII. If so, strip or hash it server-side before any tag fires, and prefer Conversions API / server-side tagging with explicit consent.',
              });
            }
          }
          if (match.index === regex.lastIndex) {
            regex.lastIndex += 1; // guard against zero-width matches
          }
          match = regex.exec(field.value);
        }
      }
    }
    return { ruleId: 'no-pii-pattern-in-tracker', violations };
  },
};

/**
 * The default rule set. Passwords are always an ERROR (there is no compliant
 * reason to send a password to an ad network, even hashed). Emails and other
 * directly-identifying categories are ERRORs as well; structural pattern hits
 * are WARNINGs because they may be false positives.
 */
export const DEFAULT_RULES: readonly AuditRule[] = Object.freeze([
  makeSeededCategoryRule({
    id: 'no-password-in-tracker',
    category: PiiCategory.Password,
    defaultSeverity: Severity.Error,
    remediation:
      'A password must NEVER leave your origin in any form. Remove the field from the tag payload, ensure trackers are not auto-capturing input values, and audit any "advanced matching" / "automatic configuration" tracker setting.',
  }),
  makeSeededCategoryRule({
    id: 'no-email-in-tracker',
    category: PiiCategory.Email,
    defaultSeverity: Severity.Error,
    remediation:
      'Do not transmit raw or hashed email to ad networks without explicit, documented consent. Disable Meta "Automatic Advanced Matching" and Google "enhanced conversions" auto-collection, or gate them behind a consent-management platform.',
  }),
  makeSeededCategoryRule({
    id: 'no-credit-card-in-tracker',
    category: PiiCategory.CreditCard,
    defaultSeverity: Severity.Error,
    remediation:
      'Cardholder data sent to a tracker is a PCI-DSS violation. Remove it immediately and review your tag configuration and any session-replay tooling for input capture.',
  }),
  makeSeededCategoryRule({
    id: 'no-ssn-in-tracker',
    category: PiiCategory.Ssn,
    defaultSeverity: Severity.Error,
    remediation:
      'Government identifiers must never be shared with advertising vendors. Remove the field and audit form-autocapture settings.',
  }),
  makeSeededCategoryRule({
    id: 'no-phone-in-tracker',
    category: PiiCategory.PhoneNumber,
    defaultSeverity: Severity.Error,
    remediation:
      'Phone numbers are regulated PII. Strip them from tag payloads or hash server-side under a documented lawful basis with consent.',
  }),
  makeSeededCategoryRule({
    id: 'no-name-in-tracker',
    category: PiiCategory.FullName,
    defaultSeverity: Severity.Warning,
    remediation:
      'Avoid sending user names to third parties. Verify whether the tracker is auto-capturing labelled form fields.',
  }),
  makeSeededCategoryRule({
    id: 'no-address-in-tracker',
    category: PiiCategory.PostalAddress,
    defaultSeverity: Severity.Warning,
    remediation: 'Postal addresses should not be shared with ad networks without consent.',
  }),
  makeSeededCategoryRule({
    id: 'no-dob-in-tracker',
    category: PiiCategory.DateOfBirth,
    defaultSeverity: Severity.Warning,
    remediation: 'Dates of birth are sensitive PII; remove them from tracker payloads.',
  }),
  makeSeededCategoryRule({
    id: 'no-generic-secret-in-tracker',
    category: PiiCategory.GenericSecret,
    defaultSeverity: Severity.Error,
    remediation: 'A declared secret leaked to a third party. Remove it and rotate the secret if it was a credential.',
  }),
  genericPatternRule,
]);

/* -------------------------------------------------------------------------- */
/* Capture orchestration                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Convert a Playwright request into the engine's normalised
 * {@link CapturedRequest}, decoding every payload surface.
 */
function normaliseRequest(
  request: PlaywrightRequest,
  id: number,
  trackers: readonly TrackerSignature[],
): CapturedRequest {
  const url = request.url();
  const rawHeaders = request.headers();
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(rawHeaders)) {
    headers[key.toLowerCase()] = value;
  }
  const postData = request.postData();
  const contentType = headers['content-type'] ?? '';

  const fields: PayloadField[] = [
    ...decodeQueryString(url),
    ...decodePostData(postData, contentType),
    ...decodeHeaders(headers),
  ];

  return {
    id,
    url,
    host: hostOf(url),
    method: request.method(),
    resourceType: request.resourceType(),
    timestamp: Date.now(),
    headers,
    postData: postData ?? null,
    fields,
    tracker: attributeTracker(url, trackers),
  };
}

/* -------------------------------------------------------------------------- */
/* Consent banner handling                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Built-in catalogue of "accept all" controls for the most common Consent
 * Management Platforms (CMPs). Without dismissing the banner, most trackers do
 * not fire — so auditing a real site usually requires accepting consent first.
 *
 * These are CSS selectors matched against the live DOM. The operator can append
 * more via {@link ScanConfig.consentSelectors}.
 */
export const DEFAULT_CONSENT_SELECTORS: readonly string[] = Object.freeze([
  // OneTrust
  '#onetrust-accept-btn-handler',
  '.onetrust-close-btn-handler.accept-cookies',
  // Cookiebot
  '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
  '#CybotCookiebotDialogBodyButtonAccept',
  // Quantcast Choice
  '.qc-cmp2-summary-buttons button[mode="primary"]',
  // Didomi
  '#didomi-notice-agree-button',
  'button.didomi-components-button--color',
  // Usercentrics
  'button[data-testid="uc-accept-all-button"]',
  '#uc-btn-accept-banner',
  // TrustArc
  '#truste-consent-button',
  // Osano
  '.osano-cm-accept-all',
  // CookieYes
  '.cky-btn-accept',
  // Termly
  '#termly-code-snippet-support button[data-tid="banner-accept"]',
  // Complianz
  '.cmplz-accept',
  // Generic id/class fallbacks commonly used by bespoke banners
  '#accept-cookies',
  '#acceptCookies',
  '.accept-cookies',
  '.cookie-accept',
  'button#gdpr-accept',
]);

/**
 * Text patterns (case-insensitive) used as a last-resort fallback to find an
 * "accept" button when no known selector matches. Kept deliberately tight to
 * avoid clicking unrelated controls (e.g. plain "Submit").
 */
const CONSENT_TEXT_PATTERNS: readonly RegExp[] = Object.freeze([
  /^\s*accept all( cookies)?\s*$/i,
  /^\s*allow all( cookies)?\s*$/i,
  /^\s*accept( cookies| all)?\s*$/i,
  /^\s*agree( and close)?\s*$/i,
  /^\s*i agree\s*$/i,
  /^\s*got it\s*$/i,
]);

/**
 * Attempt to dismiss a cookie/consent banner by clicking the first recognised
 * "accept all" control. Uses instantaneous visibility checks (no auto-waiting)
 * so a page with no banner costs almost nothing. Returns the selector/pattern
 * that was clicked, or `null` when nothing matched.
 *
 * This is best-effort and never throws: any failure is recorded as a diagnostic.
 */
export async function acceptConsentBanners(
  page: Page,
  extraSelectors: readonly string[],
  diagnostics: string[],
): Promise<string | null> {
  // Give a just-loaded CMP a brief moment to inject its banner into the DOM.
  await page.waitForTimeout(600).catch(() => undefined);

  const selectors = [...extraSelectors, ...DEFAULT_CONSENT_SELECTORS];
  for (const selector of selectors) {
    try {
      const locator = page.locator(selector).first();
      if (await locator.isVisible()) {
        await locator.click({ timeout: 3_000 });
        diagnostics.push(`Accepted consent banner via selector "${selector}".`);
        // Allow tags that fire on consent to dispatch before we continue.
        await page.waitForTimeout(800).catch(() => undefined);
        return selector;
      }
    } catch {
      // Selector invalid or click intercepted — try the next candidate.
      continue;
    }
  }

  // Text-based fallback across button-like elements.
  for (const pattern of CONSENT_TEXT_PATTERNS) {
    try {
      const locator = page
        .locator('button, [role="button"], a')
        .filter({ hasText: pattern })
        .first();
      if (await locator.isVisible()) {
        await locator.click({ timeout: 3_000 });
        diagnostics.push(`Accepted consent banner via text pattern ${pattern.toString()}.`);
        await page.waitForTimeout(800).catch(() => undefined);
        return pattern.toString();
      }
    } catch {
      continue;
    }
  }

  diagnostics.push('Consent acceptance requested, but no recognised banner control was found.');
  return null;
}

/**
 * Fill the configured mock inputs into the page. Missing selectors are recorded
 * as non-fatal diagnostics rather than aborting the scan.
 */
async function fillMockInputs(
  page: Page,
  mockInputs: readonly MockInput[],
  diagnostics: string[],
): Promise<void> {
  for (const input of mockInputs) {
    try {
      const locator = page.locator(input.selector).first();
      await locator.waitFor({ state: 'visible', timeout: 5_000 });
      await locator.fill(input.value);
    } catch {
      diagnostics.push(
        `Could not fill selector "${input.selector}" — the control was not found or not editable. Skipping.`,
      );
    }
  }
}

/**
 * Translate the configured mock inputs (plus any extra declared secrets) into
 * the flat list of seeded secrets the rule engine searches for.
 */
function deriveSeededSecrets(config: ScanConfig): SeededSecret[] {
  const secrets: SeededSecret[] = [];
  for (const input of config.mockInputs) {
    secrets.push({
      category: input.category,
      label: input.label ?? input.selector,
      plaintext: input.value,
    });
  }
  for (const extra of config.extraSecrets) {
    secrets.push(extra);
  }
  return secrets;
}

/**
 * Resolve the navigable URL for a scan target. Local files are converted to a
 * `file://` URL so the browser executes their inline scripts faithfully.
 */
function targetToNavigableUrl(target: ScanTarget): string {
  if (target.kind === 'url') {
    return target.url;
  }
  return pathToFileURL(target.path).toString();
}

/**
 * Number of characters on each side of a tracker marker that the static scanner
 * treats as "co-located" with that marker. A leak is only reported when a secret
 * representation appears inside this window AROUND a tracker reference, not
 * merely somewhere else in the file. This is what keeps the static pass precise:
 * an email in a `<meta>` tag and an unrelated pixel in the footer no longer
 * collide into a false positive.
 */
export const STATIC_PROXIMITY_WINDOW = 600;

/** A single occurrence of a tracker URL marker within source text. */
interface MarkerHit {
  readonly index: number;
  readonly length: number;
  readonly tracker: TrackerSignature;
}

/**
 * Find every occurrence of every tracker URL marker within the source text.
 */
function collectMarkerHits(sourceText: string, trackers: readonly TrackerSignature[]): MarkerHit[] {
  const lower = sourceText.toLowerCase();
  const hits: MarkerHit[] = [];
  for (const tracker of trackers) {
    for (const marker of tracker.urlMarkers) {
      const needle = marker.toLowerCase();
      if (needle.length === 0) {
        continue;
      }
      let from = 0;
      let idx = lower.indexOf(needle, from);
      while (idx !== -1) {
        hits.push({ index: idx, length: needle.length, tracker });
        from = idx + needle.length;
        idx = lower.indexOf(needle, from);
      }
    }
  }
  return hits;
}

/** A secret representation found co-located with a specific tracker marker. */
interface ColocatedLeak {
  readonly secret: CompiledSecret;
  readonly encoding: LeakEncoding;
  readonly tracker: TrackerSignature;
}

/**
 * Detect secret representations that sit within {@link STATIC_PROXIMITY_WINDOW}
 * characters of a tracker marker. Each (secret, encoding, vendor) tuple is
 * reported at most once. Exported for direct unit testing.
 */
export function findColocatedLeaks(
  sourceText: string,
  secrets: readonly CompiledSecret[],
  trackers: readonly TrackerSignature[],
): ColocatedLeak[] {
  const markerHits = collectMarkerHits(sourceText, trackers);
  if (markerHits.length === 0 || secrets.length === 0) {
    return [];
  }
  const seen = new Set<string>();
  const leaks: ColocatedLeak[] = [];
  for (const hit of markerHits) {
    const start = Math.max(0, hit.index - STATIC_PROXIMITY_WINDOW);
    const end = Math.min(sourceText.length, hit.index + hit.length + STATIC_PROXIMITY_WINDOW);
    const window = sourceText.slice(start, end);
    for (const secret of secrets) {
      const encoding = matchSecretInValue(window, secret);
      if (encoding === null) {
        continue;
      }
      const key = `${secret.label}::${encoding}::${hit.tracker.vendor}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      leaks.push({ secret, encoding, tracker: hit.tracker });
    }
  }
  return leaks;
}

/**
 * Statically scan raw source text (an HTML/JS file) for seeded secrets that are
 * hard-coded NEAR a tracker reference. Produces one synthetic
 * {@link CapturedRequest} per implicated vendor so the same rule engine can
 * evaluate the findings, preserving the encoding in which each secret appeared.
 *
 * Returns an empty array when no secret is co-located with a tracker marker,
 * since a leak requires both a sensitive value and an exfiltration destination
 * in the same neighbourhood.
 */
export function analyzeStaticSource(
  sourceText: string,
  sourceLabel: string,
  trackers: readonly TrackerSignature[],
  seededSecrets: readonly SeededSecret[],
): CapturedRequest[] {
  const secrets = buildMatchers(seededSecrets);
  const leaks = findColocatedLeaks(sourceText, secrets, trackers);
  if (leaks.length === 0) {
    return [];
  }

  // Group co-located leaks by vendor so each synthetic request maps to exactly
  // one tracker, matching the shape of a real captured request.
  const byVendor = new Map<string, { tracker: TrackerSignature; fields: PayloadField[] }>();
  for (const leak of leaks) {
    const representation = representationFor(leak.secret, leak.encoding) ?? leak.secret.plaintext;
    const bucket = byVendor.get(leak.tracker.vendor) ?? { tracker: leak.tracker, fields: [] };
    bucket.fields.push({
      path: `inline-source:${leak.secret.label}`,
      value: representation,
      source: PayloadSource.RawBody,
    });
    byVendor.set(leak.tracker.vendor, bucket);
  }

  const requests: CapturedRequest[] = [];
  let syntheticId = -1;
  for (const { tracker, fields } of byVendor.values()) {
    requests.push({
      id: syntheticId,
      url: `static://${sourceLabel}#${tracker.vendor.toLowerCase().replace(/\s+/g, '-')}`,
      host: tracker.vendor.toLowerCase().replace(/\s+/g, '-'),
      method: 'STATIC',
      resourceType: 'document',
      timestamp: Date.now(),
      headers: {},
      postData: null,
      fields,
      tracker,
    });
    syntheticId -= 1;
  }
  return requests;
}

/* -------------------------------------------------------------------------- */
/* Tally & sorting                                                             */
/* -------------------------------------------------------------------------- */

/** Count violations by severity. */
function tallyViolations(violations: readonly Violation[]): ViolationTally {
  let info = 0;
  let warning = 0;
  let error = 0;
  for (const violation of violations) {
    switch (violation.severity) {
      case Severity.Info:
        info += 1;
        break;
      case Severity.Warning:
        warning += 1;
        break;
      case Severity.Error:
        error += 1;
        break;
      default:
        break;
    }
  }
  return { info, warning, error, total: violations.length };
}

/** Stable sort: most severe first, then by rule id, then by request id. */
function sortViolations(violations: readonly Violation[]): Violation[] {
  return [...violations].sort((a, b) => {
    const sevDelta = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sevDelta !== 0) {
      return sevDelta;
    }
    if (a.ruleId !== b.ruleId) {
      return a.ruleId < b.ruleId ? -1 : 1;
    }
    return a.request.id - b.request.id;
  });
}

/** Whether the result should fail CI given the configured threshold. */
function computeFailure(tally: ViolationTally, failOn: Severity): boolean {
  const threshold = SEVERITY_RANK[failOn];
  if (threshold <= SEVERITY_RANK[Severity.Info] && tally.total > 0) {
    return true;
  }
  if (threshold <= SEVERITY_RANK[Severity.Warning] && tally.warning + tally.error > 0) {
    return true;
  }
  if (threshold <= SEVERITY_RANK[Severity.Error] && tally.error > 0) {
    return true;
  }
  return false;
}

/* -------------------------------------------------------------------------- */
/* Public entry point                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Run a full privacy-leak audit against the configured target and return a
 * structured {@link ScanResult}. This function owns the browser lifecycle and
 * always tears it down, even on error.
 *
 * @param config   Fully-resolved scan configuration.
 * @param rules    The rule set to evaluate (defaults to {@link DEFAULT_RULES}).
 */
export async function scan(
  config: ScanConfig,
  rules: readonly AuditRule[] = DEFAULT_RULES,
): Promise<ScanResult> {
  const startedAt = Date.now();
  const diagnostics: string[] = [];
  const trackers: readonly TrackerSignature[] = [...config.extraTrackers, ...DEFAULT_TRACKERS];
  const seededSecrets = deriveSeededSecrets(config);
  const originHost = hostOf(targetToNavigableUrl(config.target));

  const captured: CapturedRequest[] = [];
  let nextId = 0;

  let browser: Browser | null = null;
  let context: BrowserContext | null = null;

  try {
    browser = await chromium.launch({ headless: config.headless });
    context = await browser.newContext({
      // A realistic, stable user agent improves fidelity of tracker behaviour.
      userAgent:
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();

    // Capture EVERY outbound request the moment it is issued.
    page.on('request', (request: PlaywrightRequest) => {
      try {
        captured.push(normaliseRequest(request, nextId, trackers));
        nextId += 1;
      } catch {
        diagnostics.push('Failed to normalise a captured request; it was skipped.');
      }
    });

    const navigateUrl = targetToNavigableUrl(config.target);
    await page.goto(navigateUrl, { waitUntil: 'load', timeout: 30_000 }).catch((error: unknown) => {
      diagnostics.push(
        `Navigation to ${navigateUrl} did not fully complete: ${error instanceof Error ? error.message : String(error)}`,
      );
    });

    // Dismiss any cookie/consent banner first — most trackers stay dormant
    // until consent is granted, so this is essential for real-world fidelity.
    if (config.acceptConsent) {
      await acceptConsentBanners(page, config.consentSelectors, diagnostics);
    }

    // Seed the form with the known secrets.
    await fillMockInputs(page, config.mockInputs, diagnostics);

    // Trigger submission if configured.
    if (config.submitSelector !== null) {
      try {
        const submit = page.locator(config.submitSelector).first();
        await submit.waitFor({ state: 'visible', timeout: 5_000 });
        await submit.click({ timeout: 5_000 });
      } catch {
        diagnostics.push(
          `Could not click submit selector "${config.submitSelector}"; collecting any beacons fired so far.`,
        );
      }
    }

    // Let trailing beacons (often fired on submit / unload) settle.
    await page.waitForTimeout(config.settleTimeoutMs);
  } catch (error: unknown) {
    diagnostics.push(
      `Browser-driven capture failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  } finally {
    if (context !== null) {
      await context.close().catch(() => undefined);
    }
    if (browser !== null) {
      await browser.close().catch(() => undefined);
    }
  }

  // For local files, additionally run a static source scan as defence in depth.
  if (config.target.kind === 'file') {
    try {
      const sourceText = await readFile(config.target.path, 'utf8');
      const staticRequests = analyzeStaticSource(
        sourceText,
        config.target.path,
        trackers,
        seededSecrets,
      );
      for (const staticRequest of staticRequests) {
        captured.push(staticRequest);
      }
    } catch (error: unknown) {
      diagnostics.push(
        `Static source scan failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  // Evaluate every rule against every captured request.
  const allViolations: Violation[] = [];
  for (const request of captured) {
    const baseContext: RuleContext = {
      request,
      seededSecrets,
      originHost,
    };
    for (const rule of rules) {
      const effectiveSeverity = resolveSeverity(rule.id, rule.defaultSeverity, config.severityOverrides);
      if (effectiveSeverity === null) {
        continue; // rule switched off
      }
      let result: RuleResult;
      try {
        result = rule.evaluate(baseContext);
      } catch (error: unknown) {
        diagnostics.push(
          `Rule "${rule.id}" threw and was skipped for request #${request.id}: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        continue;
      }
      for (const violation of result.violations) {
        // Apply the override severity if it differs from the rule default.
        allViolations.push(
          effectiveSeverity === violation.severity
            ? violation
            : { ...violation, severity: effectiveSeverity },
        );
      }
    }
  }

  const sorted = sortViolations(allViolations);
  const tally = tallyViolations(sorted);
  const trackerRequests = captured.filter((request) => request.tracker !== null);
  const failed = computeFailure(tally, config.failOn);

  return {
    config,
    requests: captured,
    trackerRequests,
    violations: sorted,
    tally,
    durationMs: Date.now() - startedAt,
    failed,
    diagnostics,
  };
}
