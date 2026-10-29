# Implementation status — honest capability ledger

This file is the single source of truth for what works. Nothing below is aspirational.

## Implemented (code + tests in this repository)

- Application registration, scope management, authorization records (API + UI wizard)
- Scope enforcement at API and transport layers: host allowlist, path include/exclude, DNS
  resolution with per-address private/link-local/metadata checks, per-hop redirect validation
- Kill switch, per-scan pause/cancel, request budget, token-bucket rate limiting
- HTTP crawler: links, forms, script harvesting; JS route/API endpoint extraction
- Playwright browser crawler: **auto-detected**; absent dependency is reported as
  "unconfigured integration", HTTP crawl continues
- Authentication: anonymous, bearer, cookie, form-login; multi-role sessions; expiration probe
- Passive analysis: security headers, CSP, cookie flags, CORS, cache-control on sensitive
  content, server/version disclosure, verbose errors observed, mixed content, source-map
  references, directory listing observed
- Active modules (bounded, non-destructive): reflected XSS reflection evidence (execution check
  only when Playwright is configured), SQLi error + boolean differential indicators, path
  traversal, verbose error injection, directory listing probing, CORS reflection, open redirect,
  unauthenticated replay of authenticated endpoints
- Cross-role differential access-control checks (requires ≥2 configured roles)
- Differential analysis with noise normalization; independent confirmation signals
- Finding model: OWASP Top 10:2025 mapping, CWE, CVSS vector/score, confidence, verification
  status, evidence, remediation, retest status, deduplication by root cause
- Evidence capture with redaction; SSE live scan status; error log streaming (redacted)
- Reports: technical + executive in HTML and JSON, generated from persisted findings;
  portfolio (organization) report
- Dashboard aggregations from real data; empty states when no data exists
- Audit logging of all mutations; RBAC (admin/analyst/viewer); login rate limiting
- Retest workflow: re-run scan against same app compares findings (fixed/regressed/new)
- Automated tests: scope guard, redaction, dedup, differential, passive checks, API auth,
  scan cancellation, tenant isolation, end-to-end demo scan

## Partially implemented

- **PDF reports** — HTML print-to-PDF from the UI; server-side PDF generation unimplemented
- **DOM XSS execution proof** — implemented only when Playwright is configured; otherwise
  reflection-level evidence with `evidence_observed` status (honestly labeled)
- **Session renewal/rotation** — expiration detection implemented; automated renewal pending
- **OpenAPI import** — JSON specs parsed for seed paths; YAML and $ref resolution pending
- **Sitemap import** — XML sitemap URLs parsed; sitemap index recursion pending
- **GraphQL discovery** — endpoint detection implemented; introspection-driven testing pending
- **Pause/resume** — functional via Redis coordination; no UI-level phase-precise resume point

## Unimplemented (explicitly, not silently)

- **OWASP ZAP integration** — adapter interface exists; no functional integration yet. The UI
  shows "not configured" and native-engine results are labeled `engine: sentinel-native`.
- **OAuth 2.0 / OIDC login workflows** — configuration surface only; no token-exchange flow
- **Out-of-band (callback) verification service** — no payload; OOB-dependent checks are skipped
  and labeled inconclusive
- **AI-assisted test selection/correlation** — not present; AI is never used to confirm findings
- **Stored-XSS execution proof, LDAP/XXE/EL/template-injection, command injection, NoSQLi,
  SSRF active probing, HTTP request smuggling, TLS deep configuration grading** — detector
  interfaces exist in the module registry; detection logic not implemented. They are listed as
  "requires supplementary assessment" and never produce findings.
- **Logging/SIEM integration (A09)** — no SIEM interface configured; A09 checks are limited and
  labeled inconclusive rather than guessed
- **Worker egress enforcement** — infrastructure-level control, outside the application

## Verification-status model

`suspected → evidence_observed → validated`, plus `inconclusive`, `false_positive`,
`requires_manual_review`. A finding is `validated` only with recorded confirmation evidence;
reflection alone never yields `validated` without execution proof.