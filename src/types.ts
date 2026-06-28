/**
 * PrivacyLint — Core type definitions.
 *
 * This module is the single source of truth for every data structure that flows
 * through the auditing pipeline: the captured network requests, the rules that
 * inspect them, and the violations they emit. Everything is declared explicitly
 * so that the strict TypeScript compiler can guarantee end-to-end type safety
 * from capture through reporting.
 *
 * @packageDocumentation
 */

/* -------------------------------------------------------------------------- */
/* Severity                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Severity levels, modelled after ESLint. The numeric weights are used for
 * deterministic sorting and for deciding the process exit code in CI.
 */
export enum Severity {
  /** Informational — no compliance impact, surfaced for transparency. */
  Info = 'info',
  /** A risky pattern that should be reviewed but does not fail the build. */
  Warning = 'warning',
  /** A confirmed PII leak. Fails the build in CI by default. */
  Error = 'error',
}

/**
 * Numeric ranking for each severity, highest = most severe. Used for sorting
 * and threshold comparisons.
 */
export const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  [Severity.Info]: 0,
  [Severity.Warning]: 1,
  [Severity.Error]: 2,
});

/* -------------------------------------------------------------------------- */
/* Personally Identifiable Information (PII) taxonomy                          */
/* -------------------------------------------------------------------------- */

/**
 * The categories of sensitive data PrivacyLint knows how to recognise. Each
 * category maps to one or more detection strategies inside the scanner.
 */
export enum PiiCategory {
  Password = 'password',
  Email = 'email',
  CreditCard = 'credit_card',
  Ssn = 'ssn',
  PhoneNumber = 'phone_number',
  FullName = 'full_name',
  PostalAddress = 'postal_address',
  DateOfBirth = 'date_of_birth',
  IpAddress = 'ip_address',
  GenericSecret = 'generic_secret',
}

/* -------------------------------------------------------------------------- */
/* Tracker / destination taxonomy                                             */
/* -------------------------------------------------------------------------- */

/**
 * Known third-party advertising / analytics endpoints that PrivacyLint treats
 * as "exfiltration destinations". A request leaving the first-party origin and
 * landing on one of these hosts is in scope for auditing.
 */
export interface TrackerSignature {
  /** Human-friendly vendor name, e.g. "Meta Pixel". */
  readonly vendor: string;
  /**
   * Case-insensitive substrings matched against the request URL. If any one of
   * these appears in the URL, the request is attributed to this vendor.
   */
  readonly urlMarkers: readonly string[];
  /**
   * Optional category for grouping in the report (advertising, analytics,
   * session-replay, etc.).
   */
  readonly category: TrackerCategory;
}

export enum TrackerCategory {
  Advertising = 'advertising',
  Analytics = 'analytics',
  SessionReplay = 'session_replay',
  TagManager = 'tag_manager',
  Unknown = 'unknown',
}

/* -------------------------------------------------------------------------- */
/* Network request log                                                         */
/* -------------------------------------------------------------------------- */

/**
 * A single key/value pair decoded from a request payload (query string, form
 * body, or JSON leaf). The `path` preserves where the value was found so the
 * report can point the auditor at the exact location.
 */
export interface PayloadField {
  /** Dotted/bracketed path to the value, e.g. `cd[email]` or `body.user.pw`. */
  readonly path: string;
  /** The raw, decoded string value. */
  readonly value: string;
  /** Where in the request this field originated. */
  readonly source: PayloadSource;
}

export enum PayloadSource {
  QueryString = 'query_string',
  FormBody = 'form_body',
  JsonBody = 'json_body',
  Header = 'header',
  Cookie = 'cookie',
  RawBody = 'raw_body',
}

/**
 * A normalised representation of a single outbound network request captured by
 * the scanner. This is the unit of work that every rule inspects.
 */
export interface CapturedRequest {
  /** Monotonic id assigned at capture time, useful for cross-referencing. */
  readonly id: number;
  /** Fully-qualified request URL. */
  readonly url: string;
  /** Host portion of {@link url}, lower-cased. */
  readonly host: string;
  /** HTTP method (GET, POST, …). */
  readonly method: string;
  /** Resource type as reported by the browser (xhr, image, fetch, …). */
  readonly resourceType: string;
  /** Epoch milliseconds at which the request was observed. */
  readonly timestamp: number;
  /** Request headers, keys lower-cased. */
  readonly headers: Readonly<Record<string, string>>;
  /** The raw POST body if present, otherwise `null`. */
  readonly postData: string | null;
  /**
   * Every key/value field PrivacyLint managed to decode from the URL query,
   * the POST body and the headers. This flattened view is what rules scan.
   */
  readonly fields: readonly PayloadField[];
  /** The tracker this request was attributed to, or `null` if first-party. */
  readonly tracker: TrackerSignature | null;
}

/* -------------------------------------------------------------------------- */
/* Seeded sensitive values (the "known secrets" injected during emulation)     */
/* -------------------------------------------------------------------------- */

/**
 * A sensitive value that PrivacyLint deliberately typed into the page (or that
 * the operator declared) so the scanner can look for it verbatim — and in
 * common encoded/hashed forms — inside outbound payloads.
 */
export interface SeededSecret {
  /** Which PII category this value represents. */
  readonly category: PiiCategory;
  /** A label used in reports, e.g. the form field name. */
  readonly label: string;
  /** The plaintext value that was entered into the form. */
  readonly plaintext: string;
}

/* -------------------------------------------------------------------------- */
/* Rules                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Context handed to every rule's {@link AuditRule.evaluate} function. It bundles
 * the request under inspection together with the secrets that were seeded and a
 * few precomputed helpers shared across rules.
 */
export interface RuleContext {
  /** The request currently being evaluated. */
  readonly request: CapturedRequest;
  /** All sensitive values that were seeded for this scan. */
  readonly seededSecrets: readonly SeededSecret[];
  /** The first-party origin host the scan started from. */
  readonly originHost: string;
}

/**
 * The verdict a rule returns for a single request. A rule may emit zero or more
 * violations.
 */
export interface RuleResult {
  /** The id of the rule that produced these violations. */
  readonly ruleId: string;
  /** Zero or more violations discovered by the rule. */
  readonly violations: readonly Violation[];
}

/**
 * A pluggable audit rule. Rules are pure functions over a {@link RuleContext}:
 * given a request and the seeded secrets, they decide whether a leak occurred.
 */
export interface AuditRule {
  /** Stable machine identifier, e.g. `no-password-in-tracker`. */
  readonly id: string;
  /** One-line human description shown in `--list-rules`. */
  readonly description: string;
  /** Default severity emitted by this rule (may be overridden by config). */
  readonly defaultSeverity: Severity;
  /**
   * Inspect a single request. Implementations MUST be side-effect free and MUST
   * tolerate any shape of input without throwing.
   */
  evaluate(context: RuleContext): RuleResult;
}

/* -------------------------------------------------------------------------- */
/* Violations & evidence                                                       */
/* -------------------------------------------------------------------------- */

/**
 * The concrete evidence backing a violation — the field where the leak was
 * found and how it was encoded — so that a human auditor can reproduce and
 * confirm the finding.
 */
export interface ViolationEvidence {
  /** The payload field that contained the leaked value. */
  readonly field: PayloadField;
  /** Which PII category was leaked. */
  readonly category: PiiCategory;
  /** How the value appeared in the payload (plaintext, base64, md5, …). */
  readonly encoding: LeakEncoding;
  /**
   * A redacted preview of the offending value, safe to print to a terminal or
   * CI log without re-leaking the secret.
   */
  readonly redactedPreview: string;
  /** The label of the seeded secret this matched, if applicable. */
  readonly matchedSecretLabel: string | null;
}

/**
 * The form in which a sensitive value was found inside a payload. Detecting
 * hashed/encoded forms matters because "we hash the email before sending" is a
 * common — and still non-compliant — exfiltration pattern.
 */
export enum LeakEncoding {
  Plaintext = 'plaintext',
  UrlEncoded = 'url_encoded',
  Base64 = 'base64',
  Md5 = 'md5',
  Sha256 = 'sha256',
  PatternMatch = 'pattern_match',
}

/**
 * A single finding produced by a rule for a single request.
 */
export interface Violation {
  /** The rule that produced this finding. */
  readonly ruleId: string;
  /** Effective severity (after config overrides are applied). */
  readonly severity: Severity;
  /** Human-readable, single-sentence summary of the problem. */
  readonly message: string;
  /** The request in which the leak was observed. */
  readonly request: CapturedRequest;
  /** Concrete evidence backing the finding. */
  readonly evidence: ViolationEvidence;
  /** Optional remediation advice shown beneath the finding. */
  readonly remediation: string;
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Mock form input used during Playwright emulation. Each entry tells the
 * scanner which selector to fill, with what value, and which PII category the
 * value represents so it can be seeded as a known secret.
 */
export interface MockInput {
  /** A CSS selector identifying the form control to fill. */
  readonly selector: string;
  /** The value to type into the control. */
  readonly value: string;
  /** The PII category this value represents. */
  readonly category: PiiCategory;
  /** Optional human label; defaults to the selector. */
  readonly label?: string;
}

/**
 * Optional severity override map: rule id → severity. Lets teams downgrade a
 * rule to a warning or silence it entirely without forking the engine.
 */
export type SeverityOverrides = Readonly<Record<string, Severity | 'off'>>;

/**
 * Full configuration for a single scan run.
 */
export interface ScanConfig {
  /** Target to scan: either a live URL or a path to a local HTML file. */
  readonly target: ScanTarget;
  /**
   * Mock inputs to type into the page before triggering submission. When the
   * target is a static HTML file these still seed "known secrets" so the static
   * analyser can search inlined scripts for them.
   */
  readonly mockInputs: readonly MockInput[];
  /**
   * Additional sensitive values to treat as secrets even though they are not
   * typed into a form (e.g. an API key present in app state).
   */
  readonly extraSecrets: readonly SeededSecret[];
  /** CSS selector to click to submit the form, if any. */
  readonly submitSelector: string | null;
  /** Milliseconds to wait after submission to collect trailing beacons. */
  readonly settleTimeoutMs: number;
  /** Run the browser headless (default true). */
  readonly headless: boolean;
  /**
   * When true, the scanner attempts to dismiss cookie/consent banners by
   * clicking a recognised "accept all" control after navigation. This matters
   * for real-world fidelity: most trackers do not fire until consent is granted,
   * so without this the audit can produce a false "all clean" result.
   */
  readonly acceptConsent: boolean;
  /**
   * Extra CSS selectors to try when accepting a consent banner, in addition to
   * the built-in catalogue. Tried in order; the first visible match is clicked.
   */
  readonly consentSelectors: readonly string[];
  /** Per-rule severity overrides. */
  readonly severityOverrides: SeverityOverrides;
  /** Minimum severity that should cause a non-zero exit code. */
  readonly failOn: Severity;
  /** Extra tracker signatures supplied by the operator. */
  readonly extraTrackers: readonly TrackerSignature[];
}

/**
 * A scan target is a discriminated union so the scanner can branch safely
 * between live-browser auditing and static file auditing.
 */
export type ScanTarget =
  | { readonly kind: 'url'; readonly url: string }
  | { readonly kind: 'file'; readonly path: string };

/* -------------------------------------------------------------------------- */
/* Scan results                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Aggregate counts of findings by severity, precomputed for the reporter and
 * the exit-code logic.
 */
export interface ViolationTally {
  readonly info: number;
  readonly warning: number;
  readonly error: number;
  readonly total: number;
}

/**
 * The complete outcome of a scan: every captured request, every violation, and
 * summary metadata. This object is what the CLI renders and what a programmatic
 * consumer would inspect.
 */
export interface ScanResult {
  /** The configuration that produced this result. */
  readonly config: ScanConfig;
  /** Every outbound request captured during the scan. */
  readonly requests: readonly CapturedRequest[];
  /** Only the requests that were attributed to a known tracker. */
  readonly trackerRequests: readonly CapturedRequest[];
  /** Every violation discovered, sorted by severity then rule id. */
  readonly violations: readonly Violation[];
  /** Counts by severity. */
  readonly tally: ViolationTally;
  /** Wall-clock duration of the scan in milliseconds. */
  readonly durationMs: number;
  /** Whether the scan should be considered a CI failure. */
  readonly failed: boolean;
  /** Non-fatal diagnostics emitted while scanning (e.g. selector not found). */
  readonly diagnostics: readonly string[];
}
