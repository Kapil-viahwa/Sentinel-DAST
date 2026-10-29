# Platform security controls

## Authentication & authorization
- JWT bearer tokens (HS256, expiry), PBKDF2-SHA256 (200k iterations) password hashing
- Roles: `admin`, `analyst`, `viewer` — enforced server-side per route
- Tenant isolation: every data query is scoped to the authenticated user's organization
- Login rate limiting via Redis

## Data protection
- Credentials/tokens encrypted with Fernet (key derived from `SECRET_KEY` env var)
- Redaction of secrets in logs, evidence, API responses and reports
- Reports stored in a private object-storage directory, served only after authorization checks

## Scan safety
- Scope validation in the API **and** inside the transport layer (defense in depth)
- Re-validation of every redirect; re-resolution of DNS per request
- Private/loopback/metadata targets refused unless `ALLOW_PRIVATE_TARGETS=true`
- Rate limiting (default 1 rps), request budget (default 500), max duration
- Global kill switch + per-scan pause/cancel, checked between every request
- No form submission during discovery (login only, via the auth module)

## Hardening defaults
- Secure headers (HSTS when TLS terminates at the deployment layer)
- `.env`-driven secrets; no secret ever committed
- Worker runs without privileged permissions; egress should be network-restricted at the
  infrastructure layer (documented; not enforced by the app itself)

## Dependency & release hygiene
- Pinned requirement ranges; run `pip-audit` / `npm audit` in CI (file an issue if absent)
- Backups: dump PostgreSQL volume (`pg_dump`) and the object-storage volume regularly

## What Sentinel will never do
- Execute commands supplied through the web interface
- Act as a general-purpose HTTP proxy
- Store plaintext credentials or leak them into logs
- Attack third-party infrastructure or perform destructive operations (bulk deletes, DoS,
  persistence, webshells, credential theft)