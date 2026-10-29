"""Intentionally vulnerable demo application — ISOLATED TEST TARGET.

This app exists so Sentinel DAST can be tested end-to-end against known,
synthetic vulnerabilities. It must never be deployed beyond an isolated lab:
it deliberately contains reflected XSS, SQL-error disclosure, a path traversal,
an open redirect, an unauthenticated admin endpoint, missing security headers,
insecure cookie flags, CORS reflection, exposed .git/.env/backup artifacts,
verbose error disclosure and stored XSS.

Every value is synthetic demo data.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import (HTMLResponse, PlainTextResponse,
                               RedirectResponse)

app = FastAPI(title="Sentinel Demo Target", docs_url=None, redoc_url=None)

BASE_PAGE = """<html><body>
<h1>Sentinel Demo Store</h1>
<p>Synthetic demo application for authorized scanner testing.</p>
<ul>
<li><a href="/search?q=coffee">Search</a></li>
<li><a href="/login">Login</a></li>
<li><a href="/comments">Comments</a></li>
<li><a href="/admin">Admin</a></li>
<li><a href="/profile?next=/dashboard">Profile</a></li>
<li><a href="/download?path=readme.txt">Download</a></li>
</ul>
<script>fetch("/api/data").then(r => r.json()); fetch("/api/whoami");</script>
<script src="/app.js"></script>
</body></html>"""

LOGIN_PAGE = """<html><body>
<h1>Login</h1>
<form method="post" action="/login">
<input name="username" type="text"><input name="password" type="password">
<button type="submit">Sign in</button>
</form></body></html>"""

_FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "demo:x:1000:1000:Demo User:/home/demo:/bin/bash\n"
)

STORED_COMMENTS: list[str] = []


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin and request.url.path == "/api/whoami":
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.get("/", response_class=HTMLResponse)
def home():
    return BASE_PAGE


@app.get("/app.js", response_class=HTMLResponse)
def app_js():
    return "console.log('demo bundle'); //# sourceMappingURL=/app.js.map"


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # Reflected XSS: q is interpolated without encoding.
    if "'" in q:
        if "' AND '1'='2" in q or "' AND '1'='2" in q.replace("  ", " "):
            return HTMLResponse(
                "<html><body><h1>Search</h1><p>No results for your query.</p></body></html>")
        return HTMLResponse(
            "<html><body><h1>Search</h1><p>Error: you have an error in your SQL syntax "
            f"near '{q}' at line 1</p></body></html>")
    return HTMLResponse(
        f"<html><body><h1>Search</h1><p>Results for query: {q}</p>"
        "<ul><li>Synthetic result A</li><li>Synthetic result B</li></ul></body></html>")


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return LOGIN_PAGE


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request):
    form = await request.form()
    username = str(form.get("username", ""))
    resp = HTMLResponse(f"<html><body><h1>Welcome, {username}</h1>"
                        "<p><a href='/admin'>Admin area</a></p></body></html>")
    resp.set_cookie("sessionid", "demo-session-token")  # no Secure/HttpOnly/SameSite
    return resp


@app.get("/admin", response_class=HTMLResponse)
def admin(debug: str = ""):
    if debug:
        return HTMLResponse(
            "<html><body><h1>Error</h1><pre>Traceback (most recent call last):\n"
            "  File \"app.py\", line 42, in admin\nInternalError: "
            "unsafe query executed on db.internal</pre></body></html>")
    return HTMLResponse(
        "<html><body><h1>Admin</h1><p>Synthetic internal records: "
        "order 9001, payment ref PAY-4410.</p></body></html>")


@app.get("/comments", response_class=HTMLResponse)
def comments():
    items = "".join(f"<li>{c}</li>" for c in STORED_COMMENTS)
    return HTMLResponse(
        "<html><body><h1>Comments</h1>"
        '<form method="post" action="/comments">'
        '<input name="comment" type="text"><button type="submit">Post</button></form>'
        f"<ul>{items}</ul></body></html>")


@app.post("/comments")
async def post_comment(request: Request):
    form = await request.form()
    STORED_COMMENTS.append(str(form.get("comment", "")))  # stored XSS: rendered raw
    return RedirectResponse("/comments", status_code=302)


@app.get("/download")
def download(path: str):
    # Deliberately no canonicalization: traversal reaches the synthetic passwd file.
    normalized = path.replace("\\", "/")
    if normalized.endswith("etc/passwd") or normalized == "/etc/passwd":
        return PlainTextResponse(_FAKE_PASSWD)
    if path == "readme.txt":
        return PlainTextResponse("Synthetic readme for demo target")
    return PlainTextResponse("not found", status_code=404)


@app.get("/profile")
def profile(next: str = "/dashboard"):
    return RedirectResponse(next, status_code=302)  # open redirect


@app.get("/api/data")
def api_data():
    return {"items": [1, 2, 3]}


@app.get("/api/whoami")
def api_whoami():
    return {"user": "anonymous", "role": "demo"}


@app.get("/.git/HEAD")
def git_head():
    return PlainTextResponse("ref: refs/heads/main\n")


@app.get("/.env")
def dot_env():
    return PlainTextResponse("SECRET_KEY=demo-synthetic-secret\nDEBUG=true\n")


@app.get("/backup/")
def backup_listing():
    return HTMLResponse(
        "<html><head><title>Index of /backup/</title></head><body>"
        "<h1>Index of /backup/</h1><ul><li><a href='/backup/db.sql'>db.sql</a></li></ul>"
        "</body></html>")