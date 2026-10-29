# Sentinel DAST — Enterprise Dynamic Application Security Testing Platform

Sentinel DAST is a production-oriented, evidence-driven DAST platform for **authorized** web
application security assessments. It combines an HTTP/browser hybrid crawler, a plugin-based
detection framework, differential response analysis, controlled proof-of-exploit verification,
finding management with deduplication and retesting, and enterprise reporting.

## What this is (and is not)

This platform runs **real** scans against targets you are authorized to test. It does not
simulate results. Every capability is labeled in
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) as **implemented**,
**partially implemented**, or **unimplemented**. Nothing is presented as functional unless its
implementation and tests are in this repository.

## Architecture

- **Frontend** — React + TypeScript + Tailwind (shadcn-style primitives), SSE live scan status
- **Backend** — Python FastAPI, PostgreSQL, Redis, audit logging, RBAC, tenant isolation
- **Scanning worker** — Celery worker running the modular scan engine (transport, crawler,
  discovery, authentication, passive + active modules, differential analysis, confirmation,
  deduplication, reporting)

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Safety model (read before scanning anything)

- Scans require an **explicit authorization record** and a scope allowlist enforced
  **server-side**, at both the API and inside the HTTP transport (every request and every
  redirect hop is re-validated, with DNS re-resolution — not URL string matching).
- Loopback, private, link-local, multicast and cloud-metadata addresses are refused unless
  `ALLOW_PRIVATE_TARGETS=true` is explicitly set for an isolated lab.
- Conservative defaults: 1 request/second, bounded request budget, bounded duration.
- A global **kill switch** and per-scan cancel/pause are enforced by the worker between every
  request.
- Secrets, tokens, cookies and credentials are encrypted at rest and redacted from all logs,
  evidence and reports.

## Quick start (Docker Compose)

See the full [Installation & Setup Guide](docs/SETUP.md) for prerequisites, manual
(dev) installation, configuration reference, the first-scan walkthrough and
troubleshooting.

```bash
cp .env.example .env        # set SECRET_KEY and DB password
docker compose up --build
# backend  http://localhost:8000  (API docs at /docs)
# frontend http://localhost:4173
```

Create the first administrator:

```bash
docker compose exec backend python -m scripts.create_admin --email you@example.com
```

Then sign in on the frontend, register an application with its approved scope and authorization
record, and launch a scan.

## Running the intentionally vulnerable demo target

The repository ships an isolated demo application for testing Sentinel itself:

```bash
cd backend
pip install -r requirements.txt
uvicorn demo.app:app --port 8001 &            # demo target on :8001
python -m scripts.create_admin --email admin@lab.local
ALLOW_PRIVATE_TARGETS=true uvicorn app.main:app --port 8000
```

Then, on the frontend, register the demo target with `http://127.0.0.1:8001`
(loopback is only accepted when `ALLOW_PRIVATE_TARGETS=true` — for isolated labs only).

## Tests

```bash
cd backend && pytest -v
```

Tests cover scope enforcement, private-address/redirect blocking, secret redaction, dedup,
differential analysis, passive checks, scan cancellation, tenant isolation, and an end-to-end
scan of the demo target.

## License / authorization disclaimer

Use Sentinel only against applications you own or have **written authorization** to test.
Unauthorized scanning is illegal in most jurisdictions.