# Sentinel DAST — Installation & Setup Guide

This guide covers installing Sentinel DAST, creating your first administrator,
registering your first application, and launching your first authorized scan.

> **Before you begin:** only scan applications you own or have written authorization
> to test. Every scan requires a recorded authorization statement that must be
> re-entered verbatim to launch.

---

## 1. Prerequisites

### Option A — Docker (recommended)

- Docker Engine 24+ and Docker Compose v2 (`docker compose version` to check)
- 4 GB RAM free (PostgreSQL, Redis, API, worker and frontend)
- Ports free: **8000** (API), **4173** (frontend), 5432/6379 optional

### Option B — Manual / development

- Python 3.11 or 3.12 (`python3 --version`)
- Node.js 18+ and npm (`node -v`)
- PostgreSQL 14+ and Redis 6+ running locally (or in Docker:
  `docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=sentinel postgres:16-alpine` and
  `docker run -d -p 6379:6379 redis:7-alpine`)

---

## 2. Get the code

```bash
git clone https://github.com/Kapil-viahwa/Sentinel-DAST.git
cd Sentinel-DAST
```

---

## 3. Install — Option A: Docker Compose

### Step 1 — Configure the environment

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```ini
SECRET_KEY=<long random string>          # python3 -c "import secrets; print(secrets.token_urlsafe(48))"
POSTGRES_PASSWORD=<strong password>
```

Keep `ALLOW_PRIVATE_TARGETS=false` unless you are scanning an **isolated lab**
(loopback/private networks are refused otherwise — this is a safety feature).

### Step 2 — Build and start

```bash
docker compose up --build -d
```

This starts:

| Service  | Address               | Role                          |
|----------|-----------------------|-------------------------------|
| backend  | http://localhost:8000 | FastAPI (API docs at `/docs`) |
| worker   | —                     | Celery scan engine            |
| frontend | http://localhost:4173 | React UI                      |
| db       | internal              | PostgreSQL 16                 |
| redis    | internal              | queues + scan coordination    |

Check health: `curl http://localhost:8000/api/health/ready` → `{"status": "ok", ...}`

### Step 3 — Create the first administrator

The first user of an organization becomes its **admin**:

```bash
docker compose exec backend python -m scripts.create_admin --email you@example.com
# you will be prompted for a password (minimum 10 characters)
```

### Step 4 — Sign in

Open http://localhost:4173, sign in, and you're done — continue at section 5.

> **Note:** the frontend bakes `VITE_API_BASE` in at build time. It defaults to
> `http://localhost:8000`, which works for local use. If you host the API elsewhere,
> set `VITE_API_BASE` in `.env` and rebuild: `docker compose up --build frontend`.

---

## 4. Install — Option B: manual (development)

```bash
# 1. Environment
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
cd backend
pip install -r requirements.txt

# 2. Configuration (from the repo root)
cp ../.env.example ../.env    # edit SECRET_KEY, DATABASE_URL, REDIS_URL

# 3. Database tables (auto-created at startup, so this is optional)
python -c "from app.db import init_db; init_db()"

# 4. Admin user (run from backend/)
python -m scripts.create_admin --email you@example.com

# 5. Start the API (from backend/)
uvicorn app.main:app --reload --port 8000

# 6. Start the scan worker (from backend/, in a second terminal)
celery -A app.engine.worker.celery_app worker -Q scans -c 2 --loglevel=info
# Without a reachable Redis the API falls back to running scans in a
# background thread — fine for a quick evaluation, not for production.

# 7. Frontend (from frontend/, in a third terminal)
cd ../frontend
npm install
VITE_API_BASE=http://localhost:8000 npm run dev
# open http://localhost:5173
```

### Optional: enable the browser crawler + DOM XSS execution checks

```bash
pip install playwright
playwright install chromium
```

Until installed, the Settings page will honestly show the Playwright integration as
**unconfigured** and HTTP-only crawling continues.

### Optional: run the test suite

```bash
cd backend && pytest -v
# Redis-dependent tests (scan cancellation) auto-skip if Redis is unreachable.
```

---

## 5. First scan walkthrough

### 5.1 Register the application

In the UI: **Applications → Register application / new scan → Step 1 (Target)**

- **Application name** — anything descriptive
- **Base URL** — e.g. `https://staging.example.com` (http/https only)
- **Environment** — development / qa / uat / staging / production
- **Additional approved hosts** — comma-separated; only these (plus the base-URL
  host) will ever be contacted. Use `*.example.com` for a subdomain wildcard.
- **Excluded paths** — e.g. `/logout, /admin/users/delete`
- **Authorization confirmation statement** — paste the exact written authorization
  (authorizer, reference, scope). You will re-enter it verbatim to launch scans;
  a mismatch is refused with 403.

### 5.2 Authentication (Step 2)

Choose anonymous, form-login, a pasted session cookie, or a bearer token.
Credentials are encrypted at rest and redacted from all logs, evidence and reports.
To test role-based access control, configure additional roles via the API
(`auth_config.roles` list) — the wizard supports one role per session.

### 5.3 Crawl configuration (Step 3)

Defaults are conservative: depth 3, 200 URLs, 500 requests, 1 request/second.
The server caps anything you enter (max 10 rps, 5000 requests, depth 8, 2000 URLs).

### 5.4 Profile (Step 4)

| Profile | What runs | Risk |
|---|---|---|
| passive | traffic analysis only, no payloads | minimal |
| baseline | passive + safe read-only active probes | low |
| standard | + CORS, redirect, replay probes | moderate |
| comprehensive | + all module safety levels | higher request volume |

No profile guarantees full OWASP Top 10 coverage; only tests that actually run
appear in results.

### 5.5 Review & launch (Step 5)

Confirm the effective scope, exclusions, auth config, limits and profile, re-enter
the authorization statement exactly, and launch. Watch it live on the scan page
(SSE), or cancel/pause at any time. Admins also have a global kill switch under
**Settings**.

---

## 6. Trying it safely with the demo target

The repo ships an intentionally vulnerable demo app (synthetic data only):

```bash
# Docker Compose users — run the demo target on your host:
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn demo.app:app --port 8001
```

Set `ALLOW_PRIVATE_TARGETS=true` in `.env` (isolated lab only) and restart the stack,
then register the app in the UI with base URL `http://127.0.0.1:8001`. The demo
exposes reflected XSS, SQL-error disclosure, path traversal, an open redirect,
exposed `/.git`/`/.env`/backup listing, verbose errors and missing security headers.

---

## 7. Configuration reference (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | insecure dev default | JWT signing + credential encryption key — **must change** |
| `DATABASE_URL` | postgres local | SQLAlchemy URL (`postgresql+psycopg2://…`) |
| `REDIS_URL` | localhost:6379 | broker, queue, kill switch, rate limits |
| `ALLOW_PRIVATE_TARGETS` | `false` | permits loopback/private targets — isolated labs only |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | JWT session lifetime |
| `OBJECT_STORAGE_DIR` | `/data/reports` | where generated reports are stored |
| `CORS_ORIGINS` | localhost UIs | allowed browser origins for the API |
| `MAX_RATE_LIMIT_RPS` / `MAX_MAX_REQUESTS` / `MAX_MAX_DEPTH` / `MAX_MAX_URLS` / `MAX_SCAN_DURATION_SECONDS` | 10 / 5000 / 8 / 2000 / 3600 | server-side hard caps on scan configuration |

---

## 8. Operations

- **Logs:** `docker compose logs -f backend worker` (secrets redacted)
- **Backup:** `docker compose exec db pg_dump -U sentinel sentinel > backup.sql`
  plus the `report_data` volume (generated reports)
- **Upgrade:** `git pull && docker compose up --build -d`
- **Kill switch:** Settings → Global kill switch (admin), or
  `redis-cli SET sentinel:killswitch 1`
- **Remove everything:** `docker compose down -v` (deletes database and reports)

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `{"status":"degraded"}` on `/api/health/ready` | `docker compose ps` — db or redis not healthy yet; wait for the healthcheck |
| Scan stuck in `queued` | the worker isn't running/consuming: check `docker compose logs worker` |
| `Scope validation failed: … private/link-local` | target resolves to a private address; use a public staging host or enable `ALLOW_PRIVATE_TARGETS` for an isolated lab |
| 403 creating a scan | authorization confirmation text doesn't exactly match the recorded statement |
| 401 after a while | JWT expired — sign in again (`ACCESS_TOKEN_EXPIRE_MINUTES`) |
| Frontend shows a blank page or API errors | `VITE_API_BASE` was baked in wrong — rebuild the frontend with the correct value |
| Frontend shows "Not Found" or "Cannot reach the Sentinel API" | The frontend is not pointing at the backend. Start the frontend with `VITE_API_BASE=http://localhost:8000 npm run dev` (or rebuild: `VITE_API_BASE=http://localhost:8000 npm run build`). Verify the API answers: `curl http://localhost:8000/api/health` |
| Login says "Too many login attempts" | 10 failures / 5 min / IP triggers Redis rate limiting; wait 5 minutes |
