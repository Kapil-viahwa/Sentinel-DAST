# Threat Model (the DAST platform itself)

Sentinel is a security-sensitive application: it is authorized to send crafted requests to
other systems. Its own abuse would be high-impact. This model drives the controls below.

## Assets

- Stored credentials / session tokens for scanned applications (encrypted at rest)
- Scan configurations (who may scan what, where)
- Findings and evidence (redacted but sensitive)
- The platform's egress path (an uncontrolled proxy would be an SSRF weapon)

## STRIDE summary

| Threat | Control |
|---|---|
| **Spoofing** | JWT bearer auth, PBKDF2 password hashing, rate-limited login |
| **Tampering** | Server-side validation of all scan configuration; findings/status overrides require rationale + audit trail |
| **Repudiation** | Audit events for every mutating action (actor, action, target, detail, timestamp) |
| **Information disclosure** | Secret redaction module applied to logs, evidence, reports; credential encryption (Fernet); tenant isolation enforced in every query |
| **Denial of service** | Request budgets, rate limits, max-duration, bounded crawl, bounded response sizes, worker timeouts; login rate limiting |
| **Elevation of privilege** | Role model admin/analyst/viewer enforced server-side; no arbitrary command execution surface; uploads validated (OpenAPI/sitemap JSON only) |

## Critical abuse cases and mitigations

1. **Platform as SSRF proxy / internal scanner.** `scope_guard.py` validates scheme, host
   allowlist and path rules, then resolves DNS and checks *every resolved address* against
   private/loopback/link-local/multicast/metadata policies. `SafeHttpClient` re-validates each
   redirect hop independently. `ALLOW_PRIVATE_TARGETS` is opt-in for isolated labs only.
2. **DNS rebinding.** The resolved-IP check runs immediately before each request; rebinding is
   bounded by re-resolution per request (fully pinned connections are listed as a residual risk
   in IMPLEMENTATION_STATUS.md).
3. **Scope escape via redirects or cross-origin links.** Redirect targets are validated against
   the allowlist; out-of-scope links are never followed.
4. **Secret leakage into reports/logs.** `redaction.py` scrubs Authorization/Cookie/Set-Cookie
   headers, token-like query parameters and body fields; credentials never appear in logs.
5. **Scan data confusion across tenants.** All queries filter by `organization_id` taken from
   the authenticated user, never from client input.
6. **Platform used for credential stuffing.** Active modules refuse password-guessing classes
   by design; authentication modules only use provisioned test credentials.

## Residual risks (documented, not hidden)

- TOCTOU window between DNS validation and connection (pinned connections pending)
- Playwright-based execution checks expand attack surface of the worker; disabled by default
- PDF rendering is print-based; server-side PDF generation is unimplemented