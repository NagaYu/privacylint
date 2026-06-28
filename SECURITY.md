# Security Policy

PrivacyLint is a security tool, and we hold its own code to the standard it
enforces on others.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub Security Advisories ("Report a vulnerability" on the
repository's **Security** tab), or email the maintainers at the address listed in
`package.json`. Include:

- a description of the issue and its impact,
- steps to reproduce (a minimal HTML/JS fixture is ideal),
- the PrivacyLint version and Node.js version.

We aim to acknowledge reports within **3 business days** and to ship a fix or
mitigation for confirmed, high-severity issues within **30 days**. We will credit
reporters who wish to be named once a fix is released.

## Handling sensitive data safely

PrivacyLint deliberately handles secrets (the canary values you seed). To keep
those secrets safe:

- **Never commit real credentials or real user PII** as canaries. Use synthetic
  values. See [`.gitignore`](.gitignore), which excludes `.env`, audit logs, and
  `*.sarif`/`*.har` artifacts that may contain payloads.
- All values PrivacyLint prints are **redacted** (at most the first two and last
  one characters survive) so reports never re-leak the secret they warn about.
- Treat generated `*.sarif` / `*.json` reports as potentially sensitive and scope
  their retention accordingly in CI.

## Scope

In-scope: the PrivacyLint engine, CLI, and rule logic. Out-of-scope: third-party
dependencies (report those upstream) and the behaviour of the sites you audit.
