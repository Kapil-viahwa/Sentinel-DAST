# Architecture

## Components

```
┌────────────┐   HTTPS    ┌──────────────┐   enqueue   ┌────────────────┐
│  Frontend  │──────────▶│  Backend API │────────────▶│ Redis (broker) │
│ React/TS   │◀──SSE─────│  FastAPI     │             └───────┬────────┘
└────────────┘            └──────┬───────┘                     │ tasks
                                 │ SQLAlchemy                  ▼
                                 ▼                      ┌────────────────┐
                          ┌──────────────┐              │ Scan worker    │
                          │  PostgreSQL  │              │ Celery + engine│
                          └──────────────┘              └───────┬────────┘
                                                                │ scoped HTTP
                                                                ▼
                                                        ┌────────────────┐
                                                        │ Target (in     │
                                                        │ approved scope)│
                                                        └────────────────┘
```

## Modules

**Backend (`backend/app/`)**

- `main.py` — FastAPI application, router mounting, CORS, startup
- `config.py` — environment-driven settings (secure defaults)
- `db.py`, `models.py` — normalized data model (users, organizations, applications, scopes,
  authorization records, scan configs, scans, endpoints, HTTP exchanges, test executions,
  findings, evidence, reports, audit events)
- `auth.py`, `deps.py` — PBKDF2 password hashing, JWT sessions, role dependencies (admin /
  analyst / viewer), tenant-scoped queries
- `scope_guard.py` — scope & target validation: scheme checks, host allowlist, path
  include/exclude, DNS resolution with per-address private/link-local/metadata checks
- `crypto.py` — Fernet encryption for credential-at-rest, key derived from `SECRET_KEY`
- `redaction.py` — secret redaction for logs, evidence, reports
- `audit.py` — audit event writer (all state mutations are audited)
- `api/` — documented REST API (auth, applications, scans, findings, reports, dashboard,
  health), server-side validation, pagination, rate limiting
- `services/orchestrator.py` — Celery enqueue with graceful background-thread fallback
- `services/reporting.py` — HTML/JSON report generation from persisted findings

**Scan engine (`backend/app/engine/`)**

1. `scope_guard` (shared) — validated before every request
2. `transport.py` — `SafeHttpClient`: token-bucket rate limiting, request budget, pause/cancel
   checks, manual redirect handling with scope re-validation per hop, exchange recording
3. `crawler.py` — HTTP crawler (links, forms, scripts) + optional Playwright browser crawler
   for SPA/XHR discovery (auto-detected; reported as unconfigured when Playwright is absent)
4. `discovery.py` — JS route/API endpoint extraction, query-parameter harvesting
5. `authn.py` — anonymous, form, cookie, bearer session builders; multi-role sessions;
   expiration detection
6. `passive.py` — traffic-only analysis (headers, cookies, CORS, CSP, caching, info disclosure,
   source maps, directory listings)
7. `modules/active.py` — bounded active modules (XSS reflection, SQLi indicators, path
   traversal, verbose errors, directory listing, CORS reflection, open redirect,
   unauthenticated replay)
8. `modules/access_control.py` — cross-role differential authorization checks
9. `differential.py` — noise-normalized response comparison
10. `dedup.py` — root-cause keyed finding deduplication
11. `base.py` — plugin interface (id, OWASP category, CWE, safety level, profile gate,
    `applies()`, `run()`), verification-status model
12. `pipeline.py` — stage orchestration: baseline → context → selection → mutation →
    differential → confirmation → correlation → prioritization → evidence
13. `worker.py` — Celery app, scan task, pause/cancel/kill-switch coordination via Redis

## Scan lifecycle

`pending → queued → running (crawl → passive → active → finalize) → completed | failed | cancelled`

Every phase transition is persisted and streamed to the UI over SSE.

## Pluggability

External engines integrate through the same `TestModule` interface; an OWASP ZAP adapter
surface exists in `engine/integrations/zap.py` and is explicitly marked **unconfigured** until
implemented and tested — the UI shows an honest "integration not configured" state.