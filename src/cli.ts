#!/usr/bin/env node
/**
 * PrivacyLint — Command-line interface.
 *
 * Parses arguments, builds a {@link ScanConfig}, runs the audit engine, and
 * renders an ESLint-style, colourised report to the terminal. The process exit
 * code is meaningful for CI:
 *
 *   0  → scan completed and no finding crossed the configured `--fail-on`.
 *   1  → at least one finding crossed the `--fail-on` threshold.
 *   2  → the scan could not run (bad arguments, unreadable file, etc.).
 *
 * @packageDocumentation
 */

import { readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve as resolvePath } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  bold,
  cyan,
  dim,
  gray,
  green,
  isColorSupported,
  magenta,
  red,
  underline,
  white,
  yellow,
} from 'colorette';

import { DEFAULT_RULES, scan } from './scanner.js';
import { PiiCategory, Severity, TrackerCategory } from './types.js';
import type {
  MockInput,
  ScanConfig,
  ScanResult,
  ScanTarget,
  SeededSecret,
  SeverityOverrides,
  TrackerSignature,
  Violation,
} from './types.js';

/* -------------------------------------------------------------------------- */
/* Exit codes                                                                  */
/* -------------------------------------------------------------------------- */

const EXIT_OK = 0;
const EXIT_VIOLATIONS = 1;
const EXIT_USAGE = 2;

/* -------------------------------------------------------------------------- */
/* Argument parsing                                                            */
/* -------------------------------------------------------------------------- */

/** The shape produced by {@link parseArgs} before validation. */
export interface ParsedArgs {
  url: string | null;
  file: string | null;
  inputs: MockInput[];
  secrets: SeededSecret[];
  submitSelector: string | null;
  settleTimeoutMs: number;
  headless: boolean;
  failOn: Severity;
  acceptConsent: boolean;
  consentSelectors: string[];
  json: boolean;
  quiet: boolean;
  noColor: boolean;
  listRules: boolean;
  showHelp: boolean;
  showVersion: boolean;
  severityOverrides: Record<string, Severity | 'off'>;
  extraTrackers: TrackerSignature[];
  /** Explicit config file path (`--config`), or `null` to auto-discover. */
  configPath: string | null;
  /** SARIF output path (`--sarif`); `-` means stdout, `null` means disabled. */
  sarifPath: string | null;
  /**
   * The set of scalar flags the user explicitly passed. Used so a config file
   * can supply defaults that an explicit CLI flag always overrides.
   */
  seenFlags: Set<string>;
  errors: string[];
}

/** Map a user-supplied category string to a {@link PiiCategory}. */
function parseCategory(raw: string): PiiCategory | null {
  const normalised = raw.trim().toLowerCase();
  switch (normalised) {
    case 'password':
    case 'pwd':
    case 'pass':
      return PiiCategory.Password;
    case 'email':
    case 'mail':
      return PiiCategory.Email;
    case 'credit_card':
    case 'creditcard':
    case 'cc':
    case 'card':
      return PiiCategory.CreditCard;
    case 'ssn':
      return PiiCategory.Ssn;
    case 'phone':
    case 'phone_number':
    case 'tel':
      return PiiCategory.PhoneNumber;
    case 'name':
    case 'full_name':
    case 'fullname':
      return PiiCategory.FullName;
    case 'address':
    case 'postal_address':
      return PiiCategory.PostalAddress;
    case 'dob':
    case 'date_of_birth':
      return PiiCategory.DateOfBirth;
    case 'ip':
    case 'ip_address':
      return PiiCategory.IpAddress;
    case 'secret':
    case 'generic':
    case 'generic_secret':
      return PiiCategory.GenericSecret;
    default:
      return null;
  }
}

/** Map a severity string to {@link Severity}. */
function parseSeverity(raw: string): Severity | null {
  switch (raw.trim().toLowerCase()) {
    case 'info':
      return Severity.Info;
    case 'warn':
    case 'warning':
      return Severity.Warning;
    case 'error':
      return Severity.Error;
    default:
      return null;
  }
}

/**
 * Find the index of the first `=` that separates the selector/label from the
 * value, ignoring any `=` that sits inside a CSS attribute selector (`[...]`).
 * This is what lets `input[name=email]=alice@example.com` parse correctly: the
 * `=` inside `[name=email]` is at bracket depth 1 and is skipped, so the split
 * happens at the top-level `=` after the closing bracket. Returns `-1` when no
 * top-level `=` exists.
 */
function findTopLevelEquals(spec: string): number {
  let depth = 0;
  for (let i = 0; i < spec.length; i += 1) {
    const ch = spec[i];
    if (ch === '[') {
      depth += 1;
    } else if (ch === ']') {
      depth = Math.max(0, depth - 1);
    } else if (ch === '=' && depth === 0) {
      return i;
    }
  }
  return -1;
}

/**
 * Strip a trailing `:category` suffix from a spec, but only when the suffix is a
 * recognised category. CSS pseudo-classes (`:hover`) and values containing `:`
 * are therefore left untouched. Returns the remaining core plus the category.
 */
function splitTrailingCategory(spec: string): { core: string; category: PiiCategory } {
  const lastColon = spec.lastIndexOf(':');
  if (lastColon !== -1) {
    const maybeCategory = parseCategory(spec.slice(lastColon + 1));
    if (maybeCategory !== null) {
      return { core: spec.slice(0, lastColon), category: maybeCategory };
    }
  }
  return { core: spec, category: PiiCategory.GenericSecret };
}

/**
 * Parse `--input selector=value:category` into a {@link MockInput}. The category
 * suffix is optional and defaults to generic-secret. The selector may itself
 * contain `=` inside an attribute selector, e.g. `input[name=email]`.
 */
function parseInputSpec(spec: string): MockInput | string {
  const { core, category } = splitTrailingCategory(spec);
  const eq = findTopLevelEquals(core);
  if (eq === -1) {
    return `Invalid --input "${spec}". Expected form selector=value[:category].`;
  }
  const selector = core.slice(0, eq).trim();
  const value = core.slice(eq + 1);
  if (selector.length === 0) {
    return `Invalid --input "${spec}". The selector is empty.`;
  }
  return { selector, value, category, label: selector };
}

/** Parse `--secret label=value:category` into a {@link SeededSecret}. */
function parseSecretSpec(spec: string): SeededSecret | string {
  const { core, category } = splitTrailingCategory(spec);
  const eq = findTopLevelEquals(core);
  if (eq === -1) {
    return `Invalid --secret "${spec}". Expected form label=value[:category].`;
  }
  const label = core.slice(0, eq).trim();
  const plaintext = core.slice(eq + 1);
  if (label.length === 0 || plaintext.length === 0) {
    return `Invalid --secret "${spec}". Both label and value are required.`;
  }
  return { label, plaintext, category };
}

/** Parse `--rule rule-id=severity|off` into a single override entry. */
function parseRuleOverride(spec: string): { id: string; value: Severity | 'off' } | string {
  const eq = spec.indexOf('=');
  if (eq === -1) {
    return `Invalid --rule "${spec}". Expected form rule-id=error|warning|info|off.`;
  }
  const id = spec.slice(0, eq).trim();
  const valueRaw = spec.slice(eq + 1).trim().toLowerCase();
  if (id.length === 0) {
    return `Invalid --rule "${spec}". The rule id is empty.`;
  }
  if (valueRaw === 'off') {
    return { id, value: 'off' };
  }
  const severity = parseSeverity(valueRaw);
  if (severity === null) {
    return `Invalid --rule "${spec}". Severity must be one of error|warning|info|off.`;
  }
  return { id, value: severity };
}

/**
 * Parse `--tracker Vendor=marker1,marker2` into a {@link TrackerSignature}.
 */
function parseTrackerSpec(spec: string): TrackerSignature | string {
  const eq = spec.indexOf('=');
  if (eq === -1) {
    return `Invalid --tracker "${spec}". Expected form Vendor=marker1,marker2.`;
  }
  const vendor = spec.slice(0, eq).trim();
  const markers = spec
    .slice(eq + 1)
    .split(',')
    .map((marker) => marker.trim())
    .filter((marker) => marker.length > 0);
  if (vendor.length === 0 || markers.length === 0) {
    return `Invalid --tracker "${spec}". Provide a vendor name and at least one URL marker.`;
  }
  return {
    vendor,
    urlMarkers: markers,
    // Operator-defined trackers are categorised as advertising by default.
    category: 'advertising' as TrackerSignature['category'],
  };
}

/**
 * Parse the full argv into a {@link ParsedArgs}. Unknown flags and malformed
 * values are accumulated into `errors` rather than thrown, so the CLI can report
 * them all at once.
 */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const parsed: ParsedArgs = {
    url: null,
    file: null,
    inputs: [],
    secrets: [],
    submitSelector: null,
    settleTimeoutMs: 2_500,
    headless: true,
    failOn: Severity.Error,
    acceptConsent: false,
    consentSelectors: [],
    json: false,
    quiet: false,
    noColor: false,
    listRules: false,
    showHelp: false,
    showVersion: false,
    severityOverrides: {},
    extraTrackers: [],
    configPath: null,
    sarifPath: null,
    seenFlags: new Set<string>(),
    errors: [],
  };

  /** Pull the value that follows a flag, recording an error if it is missing. */
  const requireValue = (flag: string, index: number): string | null => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) {
      parsed.errors.push(`Flag ${flag} requires a value.`);
      return null;
    }
    return value;
  };

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === undefined) {
      break;
    }
    switch (arg) {
      case '--url':
      case '-u': {
        const value = requireValue(arg, i);
        if (value !== null) {
          parsed.url = value;
          parsed.seenFlags.add('url');
        }
        i += 2;
        break;
      }
      case '--file':
      case '-f': {
        const value = requireValue(arg, i);
        if (value !== null) {
          parsed.file = value;
          parsed.seenFlags.add('file');
        }
        i += 2;
        break;
      }
      case '--config':
      case '-c': {
        const value = requireValue(arg, i);
        if (value !== null) {
          parsed.configPath = value;
        }
        i += 2;
        break;
      }
      case '--input':
      case '-i': {
        const value = requireValue(arg, i);
        if (value !== null) {
          const result = parseInputSpec(value);
          if (typeof result === 'string') {
            parsed.errors.push(result);
          } else {
            parsed.inputs.push(result);
          }
        }
        i += 2;
        break;
      }
      case '--secret': {
        const value = requireValue(arg, i);
        if (value !== null) {
          const result = parseSecretSpec(value);
          if (typeof result === 'string') {
            parsed.errors.push(result);
          } else {
            parsed.secrets.push(result);
          }
        }
        i += 2;
        break;
      }
      case '--submit':
      case '-s': {
        const value = requireValue(arg, i);
        if (value !== null) {
          parsed.submitSelector = value;
          parsed.seenFlags.add('submit');
        }
        i += 2;
        break;
      }
      case '--settle': {
        const value = requireValue(arg, i);
        if (value !== null) {
          const ms = Number.parseInt(value, 10);
          if (Number.isNaN(ms) || ms < 0) {
            parsed.errors.push(`--settle must be a non-negative integer (got "${value}").`);
          } else {
            parsed.settleTimeoutMs = ms;
            parsed.seenFlags.add('settle');
          }
        }
        i += 2;
        break;
      }
      case '--fail-on': {
        const value = requireValue(arg, i);
        if (value !== null) {
          const severity = parseSeverity(value);
          if (severity === null) {
            parsed.errors.push(`--fail-on must be one of error|warning|info (got "${value}").`);
          } else {
            parsed.failOn = severity;
            parsed.seenFlags.add('fail-on');
          }
        }
        i += 2;
        break;
      }
      case '--accept-consent': {
        parsed.acceptConsent = true;
        parsed.seenFlags.add('accept-consent');
        i += 1;
        break;
      }
      case '--consent-selector': {
        const value = requireValue(arg, i);
        if (value !== null) {
          parsed.consentSelectors.push(value);
        }
        i += 2;
        break;
      }
      case '--sarif': {
        const value = requireValue(arg, i);
        if (value !== null) {
          parsed.sarifPath = value;
        }
        i += 2;
        break;
      }
      case '--rule': {
        const value = requireValue(arg, i);
        if (value !== null) {
          const result = parseRuleOverride(value);
          if (typeof result === 'string') {
            parsed.errors.push(result);
          } else {
            parsed.severityOverrides[result.id] = result.value;
          }
        }
        i += 2;
        break;
      }
      case '--tracker': {
        const value = requireValue(arg, i);
        if (value !== null) {
          const result = parseTrackerSpec(value);
          if (typeof result === 'string') {
            parsed.errors.push(result);
          } else {
            parsed.extraTrackers.push(result);
          }
        }
        i += 2;
        break;
      }
      case '--headed': {
        parsed.headless = false;
        parsed.seenFlags.add('headless');
        i += 1;
        break;
      }
      case '--headless': {
        parsed.headless = true;
        parsed.seenFlags.add('headless');
        i += 1;
        break;
      }
      case '--json': {
        parsed.json = true;
        i += 1;
        break;
      }
      case '--quiet':
      case '-q': {
        parsed.quiet = true;
        i += 1;
        break;
      }
      case '--no-color': {
        parsed.noColor = true;
        i += 1;
        break;
      }
      case '--list-rules': {
        parsed.listRules = true;
        i += 1;
        break;
      }
      case '--help':
      case '-h': {
        parsed.showHelp = true;
        i += 1;
        break;
      }
      case '--version':
      case '-v': {
        parsed.showVersion = true;
        i += 1;
        break;
      }
      default: {
        parsed.errors.push(`Unknown argument: ${arg}`);
        i += 1;
        break;
      }
    }
  }

  return parsed;
}

/* -------------------------------------------------------------------------- */
/* Help & version                                                              */
/* -------------------------------------------------------------------------- */

const VERSION = '1.0.0';

function printHelp(): void {
  const lines = [
    bold(cyan('PrivacyLint')) + dim(' — privacy-leak audit linter for web trackers'),
    '',
    bold('USAGE'),
    '  privacylint (--url <url> | --file <path>) [options]',
    '',
    bold('TARGET (one required, may come from --config)'),
    `  ${green('-u, --url <url>')}          Live URL to audit (loads in headless Chromium).`,
    `  ${green('-f, --file <path>')}        Local HTML file to audit (loaded + statically scanned).`,
    `  ${green('-c, --config <path>')}      Load settings from a JSON config file. CLI flags override it.`,
    `                            Auto-discovers ${cyan('privacylint.config.json')} in the cwd.`,
    '',
    bold('FORM EMULATION'),
    `  ${green('-i, --input <spec>')}       Fill a form field. Repeatable.`,
    `                            Form: ${cyan('selector=value:category')}`,
    `                            e.g. ${dim('--input "#password=Hunter2!:password"')}`,
    `  ${green('-s, --submit <selector>')}  CSS selector to click after filling inputs.`,
    `  ${green('--secret <spec>')}          Declare a known secret not typed into a form.`,
    `                            Form: ${cyan('label=value:category')}`,
    `  ${green('--settle <ms>')}            Wait after submit to collect trailing beacons (default 2500).`,
    `  ${green('--accept-consent')}         Click a recognised cookie/consent "accept all" banner first.`,
    `  ${green('--consent-selector <sel>')} Extra CSS selector for the consent button. Repeatable.`,
    '',
    bold('CATEGORIES'),
    '  password, email, credit_card, ssn, phone, name, address, dob, ip, secret',
    '',
    bold('RULES & SEVERITY'),
    `  ${green('--rule <id=severity>')}     Override a rule severity: error|warning|info|off. Repeatable.`,
    `  ${green('--fail-on <severity>')}     Minimum severity that fails CI (default error).`,
    `  ${green('--tracker <Vendor=m1,m2>')} Register an extra tracker by URL markers. Repeatable.`,
    `  ${green('--list-rules')}             Print all built-in rules and exit.`,
    '',
    bold('OUTPUT & RUNTIME'),
    `  ${green('--json')}                   Emit machine-readable JSON instead of the human report.`,
    `  ${green('--sarif <path>')}           Write a SARIF 2.1.0 report (use ${cyan('-')} for stdout) for GitHub code scanning.`,
    `  ${green('-q, --quiet')}              Only print findings and the summary line.`,
    `  ${green('--no-color')}               Disable ANSI colours.`,
    `  ${green('--headed')}                 Run the browser with a visible window (debugging).`,
    `  ${green('-h, --help')}               Show this help.`,
    `  ${green('-v, --version')}            Show the version.`,
    '',
    bold('EXIT CODES'),
    '  0  no finding crossed --fail-on      1  findings crossed --fail-on      2  usage/runtime error',
    '',
    bold('EXAMPLE'),
    dim('  privacylint \\'),
    dim('    --url https://example.com/signup \\'),
    dim('    --input "input[name=email]=alice@example.com:email" \\'),
    dim('    --input "input[type=password]=S3cr3t!:password" \\'),
    dim('    --submit "button[type=submit]" \\'),
    dim('    --fail-on error'),
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}

function printVersion(): void {
  process.stdout.write(`privacylint ${VERSION}\n`);
}

function printRules(): void {
  process.stdout.write(`${bold('Built-in rules:')}\n`);
  for (const rule of DEFAULT_RULES) {
    const sev =
      rule.defaultSeverity === Severity.Error
        ? red('error  ')
        : rule.defaultSeverity === Severity.Warning
          ? yellow('warning')
          : cyan('info   ');
    process.stdout.write(`  ${sev}  ${bold(rule.id)}\n          ${dim(rule.description)}\n`);
  }
}

/* -------------------------------------------------------------------------- */
/* Reporting                                                                   */
/* -------------------------------------------------------------------------- */

/** Colourise a severity token for the report. */
function severityToken(severity: Severity): string {
  switch (severity) {
    case Severity.Error:
      return red(bold('error'));
    case Severity.Warning:
      return yellow(bold('warning'));
    case Severity.Info:
      return cyan(bold('info'));
    default:
      return white(severity);
  }
}

/** Render a single violation in an ESLint-like block. */
function renderViolation(violation: Violation, index: number): string {
  const header = `${dim(`${index}.`)} ${severityToken(violation.severity)}  ${bold(white(violation.message))}`;
  const vendor = violation.request.tracker?.vendor ?? 'unknown tracker';
  const lines = [
    header,
    `     ${gray('rule')}      ${magenta(violation.ruleId)}`,
    `     ${gray('tracker')}   ${vendor} ${dim(`(${violation.request.host})`)}`,
    `     ${gray('request')}   ${violation.request.method} ${dim(truncateUrl(violation.request.url))}`,
    `     ${gray('field')}     ${cyan(violation.evidence.field.path)} ${dim(`[${violation.evidence.field.source}]`)}`,
    `     ${gray('leaked')}    ${red(violation.evidence.redactedPreview)} ${dim(`(${violation.evidence.encoding})`)}`,
    `     ${gray('fix')}       ${dim(violation.remediation)}`,
  ];
  return lines.join('\n');
}

/** Truncate a long URL for display while keeping the host and path head. */
function truncateUrl(url: string): string {
  if (url.length <= 100) {
    return url;
  }
  return `${url.slice(0, 100)}…`;
}

/** Render the full human-readable report. */
function renderReport(result: ScanResult, quiet: boolean): string {
  const sections: string[] = [];

  if (!quiet) {
    const target =
      result.config.target.kind === 'url' ? result.config.target.url : result.config.target.path;
    sections.push(bold(underline(cyan('PrivacyLint audit report'))));
    sections.push(`${gray('target')}    ${white(target)}`);
    sections.push(
      `${gray('captured')}  ${white(String(result.requests.length))} requests, ${white(
        String(result.trackerRequests.length),
      )} to known trackers`,
    );
    sections.push(`${gray('duration')}  ${white(`${result.durationMs} ms`)}`);
    sections.push('');

    if (result.trackerRequests.length > 0) {
      sections.push(bold('Third-party tracker endpoints contacted:'));
      const vendors = new Map<string, number>();
      for (const request of result.trackerRequests) {
        const vendor = request.tracker?.vendor ?? 'unknown';
        vendors.set(vendor, (vendors.get(vendor) ?? 0) + 1);
      }
      for (const [vendor, count] of vendors.entries()) {
        sections.push(`  ${dim('•')} ${white(vendor)} ${dim(`× ${count}`)}`);
      }
      sections.push('');
    }
  }

  if (result.violations.length === 0) {
    sections.push(green(bold('✓ No PII leaks detected. ')) + dim('All audited tracker payloads were clean.'));
  } else {
    sections.push(bold(red(`Findings (${result.violations.length}):`)));
    sections.push('');
    result.violations.forEach((violation, idx) => {
      sections.push(renderViolation(violation, idx + 1));
      sections.push('');
    });
  }

  if (!quiet && result.diagnostics.length > 0) {
    sections.push(dim(bold('Diagnostics:')));
    for (const note of result.diagnostics) {
      sections.push(dim(`  - ${note}`));
    }
    sections.push('');
  }

  sections.push(renderSummaryLine(result));
  return sections.join('\n');
}

/** The final ESLint-style summary line. */
function renderSummaryLine(result: ScanResult): string {
  const { error, warning, info, total } = result.tally;
  if (total === 0) {
    return green(bold('✓ 0 problems'));
  }
  const parts: string[] = [];
  if (error > 0) {
    parts.push(red(`${error} error${error === 1 ? '' : 's'}`));
  }
  if (warning > 0) {
    parts.push(yellow(`${warning} warning${warning === 1 ? '' : 's'}`));
  }
  if (info > 0) {
    parts.push(cyan(`${info} info`));
  }
  const symbol = result.failed ? red(bold('✖')) : yellow(bold('⚠'));
  return `${symbol} ${bold(`${total} problem${total === 1 ? '' : 's'}`)} (${parts.join(', ')})`;
}

/* -------------------------------------------------------------------------- */
/* JSON serialisation                                                          */
/* -------------------------------------------------------------------------- */

/** Produce a stable, machine-readable JSON view of the result. */
function renderJson(result: ScanResult): string {
  const target =
    result.config.target.kind === 'url'
      ? { kind: 'url', value: result.config.target.url }
      : { kind: 'file', value: result.config.target.path };

  const payload = {
    tool: 'privacylint',
    version: VERSION,
    target,
    durationMs: result.durationMs,
    failed: result.failed,
    tally: result.tally,
    requestsCaptured: result.requests.length,
    trackerRequests: result.trackerRequests.map((request) => ({
      url: request.url,
      host: request.host,
      method: request.method,
      vendor: request.tracker?.vendor ?? null,
    })),
    violations: result.violations.map((violation) => ({
      ruleId: violation.ruleId,
      severity: violation.severity,
      message: violation.message,
      category: violation.evidence.category,
      encoding: violation.evidence.encoding,
      fieldPath: violation.evidence.field.path,
      fieldSource: violation.evidence.field.source,
      redactedPreview: violation.evidence.redactedPreview,
      matchedSecretLabel: violation.evidence.matchedSecretLabel,
      request: {
        url: violation.request.url,
        host: violation.request.host,
        method: violation.request.method,
        vendor: violation.request.tracker?.vendor ?? null,
      },
      remediation: violation.remediation,
    })),
    diagnostics: result.diagnostics,
  };
  return JSON.stringify(payload, null, 2);
}

/* -------------------------------------------------------------------------- */
/* SARIF serialisation (GitHub code scanning)                                  */
/* -------------------------------------------------------------------------- */

/** Map a PrivacyLint severity onto a SARIF result level. */
function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case Severity.Error:
      return 'error';
    case Severity.Warning:
      return 'warning';
    case Severity.Info:
      return 'note';
    default:
      return 'warning';
  }
}

/**
 * Render the scan result as a SARIF 2.1.0 log. This is the format GitHub's
 * `github/codeql-action/upload-sarif` action ingests, surfacing each PII leak in
 * the repository's Security tab and inline on the pull request.
 */
export function renderSarif(result: ScanResult): string {
  const targetUri =
    result.config.target.kind === 'url' ? result.config.target.url : result.config.target.path;

  // Advertise every built-in rule so GitHub can render rule metadata even for
  // rules that produced no findings this run.
  const rules = DEFAULT_RULES.map((rule) => ({
    id: rule.id,
    name: rule.id,
    shortDescription: { text: rule.description },
    defaultConfiguration: { level: sarifLevel(rule.defaultSeverity) },
    properties: { category: 'privacy', tags: ['privacy', 'security', 'pii-leak'] },
  }));
  const ruleIndex = new Map(DEFAULT_RULES.map((rule, index) => [rule.id, index]));

  const results = result.violations.map((violation) => {
    const indexEntry = ruleIndex.get(violation.ruleId);
    return {
      ruleId: violation.ruleId,
      ...(indexEntry !== undefined ? { ruleIndex: indexEntry } : {}),
      level: sarifLevel(violation.severity),
      message: { text: violation.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: targetUri },
          },
          logicalLocations: [
            {
              name: violation.evidence.field.path,
              fullyQualifiedName: `${violation.request.host}/${violation.evidence.field.path}`,
              kind: 'member',
            },
          ],
        },
      ],
      partialFingerprints: {
        privacylintLeak: `${violation.ruleId}:${violation.request.host}:${violation.evidence.field.path}:${violation.evidence.encoding}`,
      },
      properties: {
        vendor: violation.request.tracker?.vendor ?? null,
        host: violation.request.host,
        category: violation.evidence.category,
        encoding: violation.evidence.encoding,
        redactedPreview: violation.evidence.redactedPreview,
        remediation: violation.remediation,
      },
    };
  });

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'PrivacyLint',
            informationUri: 'https://github.com/NagaYu/privacylint',
            version: VERSION,
            rules,
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

/* -------------------------------------------------------------------------- */
/* Config file loading                                                         */
/* -------------------------------------------------------------------------- */

/** The default config filename auto-discovered in the current directory. */
const DEFAULT_CONFIG_FILENAME = 'privacylint.config.json';

/**
 * A normalised, validated view of a `privacylint.config.json` file. Scalars are
 * `undefined` when the file did not specify them, so the merge step can tell
 * "absent" apart from "explicitly set".
 */
export interface FileConfig {
  url: string | undefined;
  file: string | undefined;
  inputs: MockInput[];
  secrets: SeededSecret[];
  submit: string | undefined;
  settle: number | undefined;
  headless: boolean | undefined;
  failOn: Severity | undefined;
  acceptConsent: boolean | undefined;
  consentSelectors: string[];
  rules: Record<string, Severity | 'off'>;
  trackers: TrackerSignature[];
  /** Directory containing the config file, used to resolve relative `file`. */
  baseDir: string;
}

/** Type guard for a plain JSON object. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Parse and validate the contents of a config file. Returns the normalised
 * {@link FileConfig} or a list of human-readable error strings.
 */
export function parseConfigObject(raw: unknown, baseDir: string): FileConfig | string[] {
  const errors: string[] = [];
  if (!isRecord(raw)) {
    return ['Config file must contain a JSON object at the top level.'];
  }

  const config: FileConfig = {
    url: undefined,
    file: undefined,
    inputs: [],
    secrets: [],
    submit: undefined,
    settle: undefined,
    headless: undefined,
    failOn: undefined,
    acceptConsent: undefined,
    consentSelectors: [],
    rules: {},
    trackers: [],
    baseDir,
  };

  if (raw['url'] !== undefined) {
    if (typeof raw['url'] === 'string') {
      config.url = raw['url'];
    } else {
      errors.push('Config "url" must be a string.');
    }
  }
  if (raw['file'] !== undefined) {
    if (typeof raw['file'] === 'string') {
      config.file = raw['file'];
    } else {
      errors.push('Config "file" must be a string.');
    }
  }
  if (raw['submit'] !== undefined) {
    if (typeof raw['submit'] === 'string') {
      config.submit = raw['submit'];
    } else {
      errors.push('Config "submit" must be a string.');
    }
  }
  if (raw['settle'] !== undefined) {
    if (typeof raw['settle'] === 'number' && Number.isFinite(raw['settle']) && raw['settle'] >= 0) {
      config.settle = raw['settle'];
    } else {
      errors.push('Config "settle" must be a non-negative number.');
    }
  }
  if (raw['headless'] !== undefined) {
    if (typeof raw['headless'] === 'boolean') {
      config.headless = raw['headless'];
    } else {
      errors.push('Config "headless" must be a boolean.');
    }
  }
  if (raw['acceptConsent'] !== undefined) {
    if (typeof raw['acceptConsent'] === 'boolean') {
      config.acceptConsent = raw['acceptConsent'];
    } else {
      errors.push('Config "acceptConsent" must be a boolean.');
    }
  }
  if (raw['failOn'] !== undefined) {
    const severity = typeof raw['failOn'] === 'string' ? parseSeverity(raw['failOn']) : null;
    if (severity === null) {
      errors.push('Config "failOn" must be one of error|warning|info.');
    } else {
      config.failOn = severity;
    }
  }

  if (raw['consentSelectors'] !== undefined) {
    if (Array.isArray(raw['consentSelectors']) && raw['consentSelectors'].every((s) => typeof s === 'string')) {
      config.consentSelectors = raw['consentSelectors'] as string[];
    } else {
      errors.push('Config "consentSelectors" must be an array of strings.');
    }
  }

  if (raw['inputs'] !== undefined) {
    if (Array.isArray(raw['inputs'])) {
      raw['inputs'].forEach((entry, index) => {
        if (!isRecord(entry) || typeof entry['selector'] !== 'string' || typeof entry['value'] !== 'string') {
          errors.push(`Config "inputs[${index}]" must have string "selector" and "value".`);
          return;
        }
        const category =
          typeof entry['category'] === 'string' ? parseCategory(entry['category']) : PiiCategory.GenericSecret;
        if (category === null) {
          errors.push(`Config "inputs[${index}].category" is not a recognised PII category.`);
          return;
        }
        const label = typeof entry['label'] === 'string' ? entry['label'] : entry['selector'];
        config.inputs.push({ selector: entry['selector'], value: entry['value'], category, label });
      });
    } else {
      errors.push('Config "inputs" must be an array.');
    }
  }

  if (raw['secrets'] !== undefined) {
    if (Array.isArray(raw['secrets'])) {
      raw['secrets'].forEach((entry, index) => {
        if (!isRecord(entry) || typeof entry['label'] !== 'string' || typeof entry['value'] !== 'string') {
          errors.push(`Config "secrets[${index}]" must have string "label" and "value".`);
          return;
        }
        const category =
          typeof entry['category'] === 'string' ? parseCategory(entry['category']) : PiiCategory.GenericSecret;
        if (category === null) {
          errors.push(`Config "secrets[${index}].category" is not a recognised PII category.`);
          return;
        }
        config.secrets.push({ label: entry['label'], plaintext: entry['value'], category });
      });
    } else {
      errors.push('Config "secrets" must be an array.');
    }
  }

  if (raw['rules'] !== undefined) {
    if (isRecord(raw['rules'])) {
      for (const [ruleId, value] of Object.entries(raw['rules'])) {
        if (value === 'off') {
          config.rules[ruleId] = 'off';
          continue;
        }
        const severity = typeof value === 'string' ? parseSeverity(value) : null;
        if (severity === null) {
          errors.push(`Config "rules.${ruleId}" must be one of error|warning|info|off.`);
        } else {
          config.rules[ruleId] = severity;
        }
      }
    } else {
      errors.push('Config "rules" must be an object mapping rule id to severity.');
    }
  }

  if (raw['trackers'] !== undefined) {
    if (Array.isArray(raw['trackers'])) {
      raw['trackers'].forEach((entry, index) => {
        if (
          !isRecord(entry) ||
          typeof entry['vendor'] !== 'string' ||
          !Array.isArray(entry['urlMarkers']) ||
          !entry['urlMarkers'].every((m) => typeof m === 'string') ||
          entry['urlMarkers'].length === 0
        ) {
          errors.push(`Config "trackers[${index}]" must have a "vendor" string and non-empty "urlMarkers" string array.`);
          return;
        }
        const categoryRaw = typeof entry['category'] === 'string' ? entry['category'] : 'advertising';
        const category = (Object.values(TrackerCategory) as string[]).includes(categoryRaw)
          ? (categoryRaw as TrackerCategory)
          : TrackerCategory.Advertising;
        config.trackers.push({
          vendor: entry['vendor'],
          urlMarkers: entry['urlMarkers'] as string[],
          category,
        });
      });
    } else {
      errors.push('Config "trackers" must be an array.');
    }
  }

  // Reject unknown top-level keys so typos are caught rather than silently ignored.
  const known = new Set([
    'url',
    'file',
    'inputs',
    'secrets',
    'submit',
    'settle',
    'headless',
    'failOn',
    'acceptConsent',
    'consentSelectors',
    'rules',
    'trackers',
  ]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      errors.push(`Config contains an unknown key "${key}".`);
    }
  }

  return errors.length > 0 ? errors : config;
}

/**
 * Load and parse a config file from disk. When `explicitPath` is given the file
 * must exist (a missing file is an error). When auto-discovering, a missing
 * default file is NOT an error — `null` is returned so the CLI proceeds with
 * flags alone.
 */
export async function loadConfigFile(
  explicitPath: string | null,
): Promise<FileConfig | null | string[]> {
  const path = explicitPath !== null ? resolvePath(explicitPath) : resolvePath(DEFAULT_CONFIG_FILENAME);
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    if (explicitPath !== null) {
      return [`Config file not found or unreadable: ${path}`];
    }
    return null; // auto-discovery: absence is fine
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error: unknown) {
    return [`Config file is not valid JSON (${path}): ${error instanceof Error ? error.message : String(error)}`];
  }
  return parseConfigObject(raw, dirname(path));
}

/* -------------------------------------------------------------------------- */
/* Validation                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Build a validated {@link ScanConfig} or return an array of error strings.
 *
 * Precedence: an explicit CLI flag always wins over a config-file value, which
 * in turn wins over the built-in default. Array-valued settings (inputs,
 * secrets, trackers, consent selectors, rule overrides) are MERGED — config-file
 * entries first, then CLI entries (CLI rule overrides win per rule id).
 */
export async function buildConfig(parsed: ParsedArgs): Promise<ScanConfig | string[]> {
  const errors: string[] = [...parsed.errors];

  const fileResult = await loadConfigFile(parsed.configPath);
  if (Array.isArray(fileResult)) {
    errors.push(...fileResult);
  }
  const fileConfig: FileConfig | null = Array.isArray(fileResult) ? null : fileResult;

  // Resolve the target with correct precedence.
  const cliUrl = parsed.seenFlags.has('url') ? parsed.url : null;
  const cliFile = parsed.seenFlags.has('file') ? parsed.file : null;
  const effectiveUrl = cliUrl ?? fileConfig?.url ?? null;
  const effectiveFile = cliFile ?? fileConfig?.file ?? null;

  if (effectiveUrl !== null && effectiveFile !== null) {
    errors.push('Provide either a URL or a file target, not both (check CLI flags and config file).');
  }
  if (effectiveUrl === null && effectiveFile === null) {
    errors.push('A target is required: pass --url <url>, --file <path>, or set one in the config file.');
  }

  let target: ScanTarget | null = null;
  if (effectiveFile !== null) {
    // A file from the config is resolved relative to the config's directory;
    // a file from the CLI is resolved relative to the current directory.
    const fromCli = cliFile !== null;
    const absolute =
      fromCli || isAbsolute(effectiveFile)
        ? resolvePath(effectiveFile)
        : resolvePath(fileConfig?.baseDir ?? '.', effectiveFile);
    try {
      const info = await stat(absolute);
      if (!info.isFile()) {
        errors.push(`File target is not a regular file: ${absolute}`);
      } else {
        target = { kind: 'file', path: absolute };
      }
    } catch {
      errors.push(`File target does not exist or is unreadable: ${absolute}`);
    }
  } else if (effectiveUrl !== null) {
    try {
      const u = new URL(effectiveUrl);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        errors.push(`URL target must use http or https (got "${u.protocol}").`);
      } else {
        target = { kind: 'url', url: effectiveUrl };
      }
    } catch {
      errors.push(`URL target is not a valid URL: ${effectiveUrl}`);
    }
  }

  if (errors.length > 0 || target === null) {
    return errors.length > 0 ? errors : ['Could not resolve a scan target.'];
  }

  // Merge scalars with CLI > file > default precedence.
  const submitSelector = parsed.seenFlags.has('submit')
    ? parsed.submitSelector
    : (fileConfig?.submit ?? null);
  const settleTimeoutMs = parsed.seenFlags.has('settle')
    ? parsed.settleTimeoutMs
    : (fileConfig?.settle ?? 2_500);
  const headless = parsed.seenFlags.has('headless')
    ? parsed.headless
    : (fileConfig?.headless ?? true);
  const failOn = parsed.seenFlags.has('fail-on') ? parsed.failOn : (fileConfig?.failOn ?? Severity.Error);
  const acceptConsent = parsed.seenFlags.has('accept-consent')
    ? parsed.acceptConsent
    : (fileConfig?.acceptConsent ?? false);

  // Merge array/map settings: config first, then CLI (CLI rule keys win).
  const mockInputs: MockInput[] = [...(fileConfig?.inputs ?? []), ...parsed.inputs];
  const extraSecrets: SeededSecret[] = [...(fileConfig?.secrets ?? []), ...parsed.secrets];
  const extraTrackers: TrackerSignature[] = [...(fileConfig?.trackers ?? []), ...parsed.extraTrackers];
  const consentSelectors: string[] = [...(fileConfig?.consentSelectors ?? []), ...parsed.consentSelectors];
  const severityOverrides: SeverityOverrides = {
    ...(fileConfig?.rules ?? {}),
    ...parsed.severityOverrides,
  };

  const config: ScanConfig = {
    target,
    mockInputs,
    extraSecrets,
    submitSelector,
    settleTimeoutMs,
    headless,
    acceptConsent,
    consentSelectors,
    severityOverrides,
    failOn,
    extraTrackers,
  };
  return config;
}

/* -------------------------------------------------------------------------- */
/* Main                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * The CLI entry point. Resolves arguments, runs the scan, prints the report and
 * returns the process exit code.
 */
export async function main(argv: readonly string[]): Promise<number> {
  const parsed = parseArgs(argv);

  // Honour --no-color by short-circuiting colorette. colorette already respects
  // NO_COLOR / non-TTY, but an explicit flag should always win.
  if (parsed.noColor || !isColorSupported) {
    process.env['NO_COLOR'] = '1';
    process.env['FORCE_COLOR'] = '0';
  }

  if (parsed.showHelp) {
    printHelp();
    return EXIT_OK;
  }
  if (parsed.showVersion) {
    printVersion();
    return EXIT_OK;
  }
  if (parsed.listRules) {
    printRules();
    return EXIT_OK;
  }

  const configOrErrors = await buildConfig(parsed);
  if (Array.isArray(configOrErrors)) {
    process.stderr.write(`${red(bold('PrivacyLint: invalid invocation'))}\n`);
    for (const error of configOrErrors) {
      process.stderr.write(`  ${red('•')} ${error}\n`);
    }
    process.stderr.write(`\nRun ${cyan('privacylint --help')} for usage.\n`);
    return EXIT_USAGE;
  }

  let result: ScanResult;
  try {
    result = await scan(configOrErrors);
  } catch (error: unknown) {
    process.stderr.write(
      `${red(bold('PrivacyLint: scan failed'))}\n  ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return EXIT_USAGE;
  }

  // SARIF to stdout suppresses the human/JSON report so the stream stays valid.
  if (parsed.sarifPath === '-') {
    process.stdout.write(`${renderSarif(result)}\n`);
    return result.failed ? EXIT_VIOLATIONS : EXIT_OK;
  }

  // SARIF to a file is written alongside the normal console report (the GitHub
  // pattern: a readable log plus an artifact for `upload-sarif`).
  if (parsed.sarifPath !== null) {
    try {
      await writeFile(parsed.sarifPath, `${renderSarif(result)}\n`, 'utf8');
      if (!parsed.quiet) {
        process.stderr.write(dim(`SARIF report written to ${parsed.sarifPath}\n`));
      }
    } catch (error: unknown) {
      process.stderr.write(
        `${red(bold('PrivacyLint: failed to write SARIF'))}\n  ${error instanceof Error ? error.message : String(error)}\n`,
      );
      return EXIT_USAGE;
    }
  }

  if (parsed.json) {
    process.stdout.write(`${renderJson(result)}\n`);
  } else {
    process.stdout.write(`${renderReport(result, parsed.quiet)}\n`);
  }

  return result.failed ? EXIT_VIOLATIONS : EXIT_OK;
}

/**
 * Detect whether this module is being executed directly (`node cli.js …` /
 * `privacylint …`) as opposed to being imported by a test or another module.
 * When imported, we must NOT auto-run `main`, otherwise simply importing the CLI
 * would launch a browser scan.
 */
function isInvokedDirectly(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) {
    return false;
  }
  try {
    return fileURLToPath(import.meta.url) === resolvePath(entry);
  } catch {
    return false;
  }
}

// Invoke main with argv (skipping `node` and the script path) and map the
// resolved exit code onto the process. Any unexpected rejection is treated as a
// usage/runtime error so CI never hangs.
if (isInvokedDirectly()) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      process.stderr.write(
        `${red(bold('PrivacyLint: fatal error'))}\n  ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`,
      );
      process.exitCode = EXIT_USAGE;
    });
}
