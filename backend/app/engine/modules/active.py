"""Bounded active test modules.

Design rules shared by every module here:
- change one variable at a time, keep the original request recorded
- use deterministic, non-destructive payloads only (no destructive commands,
  no time-based blind payloads unless authorized-lab profile, no persistence)
- produce a FindingDraft only with a recorded response difference plus a
  confirmation signal; reflection alone is never 'validated'
"""
from __future__ import annotations

import logging
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..base import EndpointContext, FindingDraft, TestModule, VerificationStatus
from ..differential import body_similarity, summarize_difference
from ..transport import BudgetExhausted, Exchange, SafeHttpClient

logger = logging.getLogger("sentinel.modules")

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate[",
    "psql:fatal",
    "psql:error",
    "syntax error at or near",
    "sqlite3.operationalerror",
    "ora-01756",
    "mysql_fetch",
]

_OPEN_REDIRECT_PARAMS = {
    "next", "redirect", "redirect_uri", "return", "returnurl", "return_to", "url",
    "continue", "dest", "destination", "goto", "target", "rurl", "forward",
}

CORS_PROBE_ORIGIN = "https://sentinel-cors-probe.example"
REDIRECT_PROBE_URL = "https://sentinel-open-redirect-probe.example/"


def with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    qs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    replaced = False
    out = []
    for k, v in qs:
        if k == name and not replaced:
            out.append((name, value))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(out), parts.fragment))


def _base(url: str, ctx: EndpointContext) -> dict:
    return {"url": ctx.url, "method": "GET", "role": ctx.role,
            "references": ["https://owasp.org/www-project-top-ten/"]}


def _diff_evidence(original: Exchange, mutated: Exchange, note: str) -> dict:
    return {
        "type": "http_exchange",
        "original": {"url": original.url, "status": original.status_code},
        "mutated": {"url": mutated.url, "status": mutated.status_code,
                    "modification": note},
        "difference": summarize_difference(original.response_body, mutated.response_body),
    }


class ReflectedXSSModule(TestModule):
    id = "active.reflected_xss"
    title = "Reflected cross-site scripting (XSS)"
    owasp_category = "A05:2025 — Injection"
    cwe_ids = ["CWE-79"]
    safety = "safe"
    min_profile = "baseline"

    PAYLOAD_TEMPLATE = '"><svg/onload=document.title=1>SENTXSS{marker}<'

    def applies(self, ctx: EndpointContext) -> bool:
        return ctx.method == "GET" and bool(ctx.query_params) and ctx.baseline is not None

    def run(self, client: SafeHttpClient, ctx: EndpointContext) -> list[FindingDraft]:
        drafts = []
        for name in ctx.query_params[:5]:
            marker = f"{abs(hash((ctx.url, name))) % 100000}"
            payload = self.PAYLOAD_TEMPLATE.format(marker=marker)
            mutated_url = with_param(ctx.baseline.url, name, payload)
            try:
                mutated = client.get(mutated_url, attack=True)
            except Exception as exc:
                logger.info("xss probe error: %s", exc)
                continue
            body = mutated.response_body or ""
            raw_reflection = "<svg/onload=" in body and f"SENTXSS{marker}" in body
            if not raw_reflection:
                continue

            executed = _browser_execution_check(mutated_url)
            if executed is True:
                status, severity, conf = VerificationStatus.validated.value, "high", "firm"
                note = "Payload executed in a headless browser context"
            else:
                status = VerificationStatus.evidence_observed.value
                severity, conf = "high", "firm"
                note = ("Raw, unencoded payload reflected into the HTML response. "
                        "Execution was not verified in a browser context"
                        + ("" if _playwright_ok() else " — Playwright is not configured"))
            drafts.append(FindingDraft(
                module_id=self.id,
                title=f"Reflected XSS in parameter '{name}'",
                owasp_category=self.owasp_category,
                cwe_ids=self.cwe_ids,
                severity=severity, confidence=conf, verification_status=status,
                parameter=name,
                description=f"The value of parameter '{name}' is reflected into the HTML response without context-appropriate encoding, allowing script injection.",
                preconditions="Victim must click an attacker-crafted link to the affected URL.",
                reproduction_steps=[
                    f"1. Send: GET {mutated_url}",
                    "2. Observe the payload reflected raw into the response HTML.",
                ],
                impact="Session hijacking, credential theft, or defacement via injected script executing in the victim's browser.",
                root_cause_hypothesis="User input is inserted into HTML output without contextual output encoding.",
                remediation="Apply contextual output encoding (HTML entity, attribute, and JS contexts), prefer template auto-escaping, and add a restrictive CSP.",
                references=["https://owasp.org/Top10/A03_2025-Injection/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                evidence={**_diff_evidence(ctx.baseline, mutated, f"param '{name}' = XSS payload"), "execution_note": note},
                **_base(mutated_url, ctx),
            ))
        return drafts


class SQLInjectionModule(TestModule):
    id = "active.sqli"
    title = "SQL injection indicators (error-based and boolean-based)"
    owasp_category = "A05:2025 — Injection"
    cwe_ids = ["CWE-89"]
    safety = "safe"  # read-only GET probes; time-based blind is deliberately excluded
    min_profile = "baseline"

    def applies(self, ctx: EndpointContext) -> bool:
        return ctx.method == "GET" and bool(ctx.query_params) and ctx.baseline is not None

    def run(self, client: SafeHttpClient, ctx: EndpointContext) -> list[FindingDraft]:
        drafts = []
        for name in ctx.query_params[:3]:
            base_value = _original_param_value(ctx.baseline.url, name)

            # error-based: single quote perturbation
            err_url = with_param(ctx.baseline.url, name, base_value + "'")
            try:
                err_resp = client.get(err_url, attack=True)
            except Exception as exc:
                logger.info("sqli error probe failed: %s", exc)
                continue
            lower_body = (err_resp.response_body or "").lower()
            matched_sig = next((s for s in SQL_ERROR_SIGNATURES if s in lower_body), None)
            if matched_sig:
                drafts.append(FindingDraft(
                    module_id=self.id,
                    title=f"SQL error disclosure on parameter '{name}'",
                    owasp_category=self.owasp_category, cwe_ids=self.cwe_ids,
                    severity="high", confidence="firm",
                    verification_status=VerificationStatus.evidence_observed.value,
                    parameter=name,
                    description=f"Perturbing parameter '{name}' with a single quote produced a response containing SQL error detail ('{matched_sig}'), indicating the value reaches a SQL interpreter and errors surface to clients.",
                    preconditions="Parameter is concatenated into a SQL query; DBMS errors are returned to the client.",
                    reproduction_steps=[f"1. Send: GET {err_url}", "2. Observe DBMS error detail in the response."],
                    impact="Database schema/data disclosure and a reliable oracle for further injection.",
                    root_cause_hypothesis="String concatenation into SQL without parameterization; unhandled DB errors returned to clients.",
                    remediation="Use parameterized queries/prepared statements and return generic errors to clients.",
                    references=["https://owasp.org/Top10/A03_2025-Injection/"],
                    evidence={**_diff_evidence(ctx.baseline, err_resp, f"param '{name}' = {base_value!r} + \"'\""), "signature": matched_sig},
                    **_base(err_url, ctx),
                ))
                continue  # one finding per parameter is enough

            # boolean-based differential
            true_url = with_param(ctx.baseline.url, name, base_value + "' AND '1'='1")
            false_url = with_param(ctx.baseline.url, name, base_value + "' AND '1'='2")
            try:
                true_resp = client.get(true_url, attack=True)
                false_resp = client.get(false_url, attack=True)
            except Exception as exc:
                logger.info("sqli boolean probe failed: %s", exc)
                continue
            sim_true = body_similarity(ctx.baseline.response_body, true_resp.response_body)
            sim_false = body_similarity(ctx.baseline.response_body, false_resp.response_body)
            if sim_true > 0.9 and sim_false < 0.85 and sim_true - sim_false > 0.1:
                drafts.append(FindingDraft(
                    module_id=self.id,
                    title=f"Boolean-based SQL injection indicator on parameter '{name}'",
                    owasp_category=self.owasp_category, cwe_ids=self.cwe_ids,
                    severity="high", confidence="tentative",
                    verification_status=VerificationStatus.suspected.value,
                    parameter=name,
                    description=f"Appending logically-true vs logically-false SQL predicates to parameter '{name}' produced materially different responses (true-case matches baseline at {sim_true:.2f}, false-case at {sim_false:.2f}), a classic boolean-based injection oracle.",
                    preconditions="Parameter is interpolated into a SQL WHERE clause.",
                    reproduction_steps=[f"1. Send: GET {true_url}", f"2. Send: GET {false_url}", "3. Compare with the original response."],
                    impact="Complete database content extraction via inference.",
                    root_cause_hypothesis="Parameter interpolated into SQL without parameterization.",
                    remediation="Parameterize all queries; validate input types.",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    evidence={**_diff_evidence(ctx.baseline, false_resp, "boolean false-case"),
                              "true_case_similarity": sim_true, "false_case_similarity": sim_false,
                              "requires_confirmation": "manual review recommended before remediation planning"},
                    **_base(false_url, ctx),
                ))
        return drafts


class PathTraversalModule(TestModule):
    id = "active.path_traversal"
    title = "Path traversal / arbitrary file read indicator"
    owasp_category = "A05:2025 — Injection"
    cwe_ids = ["CWE-22"]
    safety = "safe"
    min_profile = "baseline"

    PAYLOADS = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "....//....//....//....//etc/passwd"]
    MARKER = "root:x:0:0:"

    def applies(self, ctx: EndpointContext) -> bool:
        return ctx.method == "GET" and bool(ctx.query_params) and ctx.baseline is not None

    def run(self, client: SafeHttpClient, ctx: EndpointContext) -> list[FindingDraft]:
        drafts = []
        for name in ctx.query_params[:3]:
            base_value = _original_param_value(ctx.baseline.url, name)
            for payload in self.PAYLOADS:
                probe_url = with_param(ctx.baseline.url, name, payload)
                try:
                    resp = client.get(probe_url, attack=True)
                except Exception as exc:
                    logger.info("traversal probe failed: %s", exc)
                    continue
                if self.MARKER in (resp.response_body or ""):
                    drafts.append(FindingDraft(
                        module_id=self.id,
                        title=f"Path traversal read of /etc/passwd via parameter '{name}'",
                        owasp_category=self.owasp_category, cwe_ids=self.cwe_ids,
                        severity="critical", confidence="firm",
                        verification_status=VerificationStatus.evidence_observed.value,
                        parameter=name,
                        description=f"Traversal sequences in parameter '{name}' caused the response to contain passwd file content.",
                        reproduction_steps=[f"1. Send: GET {probe_url}", "2. Observe passwd content in the response."],
                        impact="Arbitrary file read: credentials, source code and configuration disclosure.",
                        root_cause_hypothesis="File path built from user input without canonicalization/allowlist.",
                        remediation="Resolve user-supplied paths against an allowlist of permitted files; reject traversal sequences after normalization.",
                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                        evidence=_diff_evidence(ctx.baseline, resp, f"param '{name}' = {payload!r}"),
                        **_base(probe_url, ctx),
                    ))
                    break
        return drafts


class VerboseErrorInjectionModule(TestModule):
    id = "active.verbose_error"
    title = "Exception disclosure via malformed input"
    owasp_category = "A10:2025 — Mishandling of Exceptional Conditions"
    cwe_ids = ["CWE-209"]
    safety = "safe"
    min_profile = "standard"

    PROBES = ["'", "%7B", "%%"]

    def applies(self, ctx: EndpointContext) -> bool:
        return ctx.method == "GET" and bool(ctx.query_params) and ctx.baseline is not None

    def run(self, client: SafeHttpClient, ctx: EndpointContext) -> list[FindingDraft]:
        drafts = []
        for name in ctx.query_params[:2]:
            for probe in self.PROBES:
                probe_url = with_param(ctx.baseline.url, name, probe)
                try:
                    resp = client.get(probe_url, attack=True)
                except Exception:
                    continue
                body = (resp.response_body or "").lower()
                if resp.status_code and resp.status_code >= 400:
                    sig = next((s for s in SQL_ERROR_SIGNATURES if s in body), None)
                    if sig or "traceback (most recent call last)" in body:
                        drafts.append(FindingDraft(
                            module_id=self.id,
                            title=f"Unhandled exception exposes internals on parameter '{name}'",
                            owasp_category=self.owasp_category, cwe_ids=self.cwe_ids,
                            severity="medium", confidence="firm",
                            verification_status=VerificationStatus.evidence_observed.value,
                            parameter=name,
                            description=f"Malformed input in parameter '{name}' produced a {resp.status_code} response exposing internal error detail.",
                            reproduction_steps=[f"1. Send: GET {probe_url}", "2. Observe internal error detail."],
                            impact="Internal paths, versions and query fragments aid further attacks.",
                            remediation="Catch exceptions globally, log server-side with a correlation ID, and return generic errors.",
                            references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/"],
                            evidence=_diff_evidence(ctx.baseline, resp, f"param '{name}' = {probe!r}"),
                            **_base(probe_url, ctx),
                        ))
                        break
        return drafts


class DirectoryListingProbeModule(TestModule):
    id = "active.directory_listing_probe"
    title = "Sensitive directory/file exposure probe"
    owasp_category = "A02:2025 — Security Misconfiguration"
    cwe_ids = ["CWE-548", "CWE-538"]
    safety = "safe"
    min_profile = "baseline"

    PATHS = ["/backup/", "/.git/HEAD", "/.env", "/files/", "/uploads/", "/archive/", "/debug/"]

    def applies(self, ctx: EndpointContext) -> bool:
        return ctx.method == "GET"

    def run(self, client: SafeHttpClient, ctx: EndpointContext) -> list[FindingDraft]:
        drafts = []
        from urllib.parse import urljoin
        root = urljoin(ctx.url, "/")
        seen_paths = set()
        for path in self.PATHS:
            probe_url = urljoin(root, path.lstrip("/"))
            if probe_url in seen_paths:
                continue
            seen_paths.add(probe_url)
            try:
                resp = client.get(probe_url, attack=True)
            except Exception:
                continue
            body = (resp.response_body or "")
            finding = None
            if path == "/.git/HEAD" and body.startswith("ref: refs/"):
                finding = FindingDraft(
                    module_id=self.id,
                    title="Exposed .git repository (source disclosure)",
                    owasp_category=self.owasp_category, cwe_ids=["CWE-538"],
                    severity="high", confidence="certain",
                    verification_status=VerificationStatus.evidence_observed.value,
                    description="The .git/HEAD file is publicly served, exposing repository metadata and typically the full source tree.",
                    reproduction_steps=[f"1. Send: GET {probe_url}", "2. Observe 'ref: refs/...' response."],
                    impact="Complete source code and history disclosure.",
                    remediation="Block access to .git directories at the web server or remove them from deployment.",
                    references=["https://cwe.mitre.org/data/definitions/538.html"],
                    evidence={"type": "http_exchange", "url": probe_url, "status": resp.status_code, "note": body[:80]},
                    **_base(probe_url, ctx),
                )
            elif path == "/.env" and resp.status_code == 200 and "<html" not in body.lower() \
                    and re.search(r"^[A-Z_][A-Z0-9_]*=", body, re.M):
                finding = FindingDraft(
                    module_id=self.id,
                    title="Exposed .env configuration file",
                    owasp_category=self.owasp_category, cwe_ids=["CWE-538"],
                    severity="critical", confidence="firm",
                    verification_status=VerificationStatus.evidence_observed.value,
                    description="A .env file with KEY=VALUE entries is publicly served; contents frequently include credentials.",
                    reproduction_steps=[f"1. Send: GET {probe_url}", "2. Observe configuration entries (values redacted in evidence)."],
                    impact="Credential and configuration disclosure.",
                    remediation="Remove .env from the web root; block dotfiles at the web server.",
                    references=["https://cwe.mitre.org/data/definitions/538.html"],
                    evidence={"type": "http_exchange", "url": probe_url, "status": resp.status_code, "note": "[response body redacted: configuration contents]"},
                    **_base(probe_url, ctx),
                )
            elif path.endswith("/") and resp.status_code == 200 and (
                "<title>index of /" in body.lower() or "directory listing for" in body.lower()
            ):
                finding = FindingDraft(
                    module_id=self.id,
                    title=f"Directory listing exposed at {path}",
                    owasp_category=self.owasp_category, cwe_ids=["CWE-548"],
                    severity="medium", confidence="certain",
                    verification_status=VerificationStatus.evidence_observed.value,
                    description=f"{probe_url} returns an auto-index directory listing.",
                    reproduction_steps=[f"1. Send: GET {probe_url}", "2. Observe directory index."],
                    impact="Disclosure of file layout and sensitive files.",
                    remediation="Disable autoindex; remove sensitive directories from deployment.",
                    references=["https://cwe.mitre.org/data/definitions/548.html"],
                    evidence={"type": "http_exchange", "url": probe_url, "status": resp.status_code, "note": "directory index page"},
                    **_base(probe_url, ctx),
                )
            if finding:
                drafts.append(finding)
        return drafts


class CORSReflectionModule(TestModule):
    id = "active.cors_reflection"
    title = "CORS reflects arbitrary attacker origin"
    owasp_category = "A02:2025 — Security Misconfiguration"
    cwe_ids = ["CWE-942"]
    safety = "safe"
    min_profile = "standard"

    def applies(self, ctx: EndpointContext) -> bool:
        return ctx.method == "GET"

    def run(self, client: SafeHttpClient, ctx: EndpointContext) -> list[FindingDraft]:
        try:
            resp = client.get(ctx.url, headers={"Origin": CORS_PROBE_ORIGIN}, attack=True)
        except Exception:
            return []
        acao = resp.response_headers.get("access-control-allow-origin", "")
        acac = resp.response_headers.get("access-control-allow-credentials", "")
        if acao == CORS_PROBE_ORIGIN:
            severity = "high" if acac.lower() == "true" else "medium"
            return [FindingDraft(
                module_id=self.id,
                title="CORS policy reflects arbitrary origin" + (" with credentials" if acac.lower() == "true" else ""),
                owasp_category=self.owasp_category, cwe_ids=self.cwe_ids,
                severity=severity, confidence="certain",
                verification_status=VerificationStatus.evidence_observed.value,
                description=f"The response reflects Origin '{CORS_PROBE_ORIGIN}' in Access-Control-Allow-Origin"
                            + (" and allows credentialed cross-origin reads." if acac.lower() == "true" else "."),
                reproduction_steps=[f"1. Send: GET {ctx.url} with Origin: {CORS_PROBE_ORIGIN}",
                                    f"2. Observe Access-Control-Allow-Origin: {acao}"],
                impact="Attackers' sites can read same-origin-protected responses from victims' browsers.",
                remediation="Allow-list exact trusted origins server-side; never reflect arbitrary Origin headers.",
                references=["https://developer.mozilla.org/docs/Web/HTTP/CORS"],
                evidence={"type": "http_exchange", "url": ctx.url, "status": resp.status_code,
                          "request_origin": CORS_PROBE_ORIGIN, "acao": acao, "acac": acac},
                **_base(ctx.url, ctx),
            )]
        return []


class OpenRedirectModule(TestModule):
    id = "active.open_redirect"
    title = "Open redirect"
    owasp_category = "A01:2025 — Broken Access Control"
    cwe_ids = ["CWE-601"]
    safety = "safe"
    min_profile = "standard"

    def applies(self, ctx: EndpointContext) -> bool:
        if ctx.method != "GET":
            return False
        return any(p.lower() in _OPEN_REDIRECT_PARAMS for p in ctx.query_params)

    def run(self, client: SafeHttpClient, ctx: EndpointContext) -> list[FindingDraft]:
        drafts = []
        for name in ctx.query_params:
            if name.lower() not in _OPEN_REDIRECT_PARAMS:
                continue
            probe_url = with_param(ctx.baseline.url, name, REDIRECT_PROBE_URL)
            try:
                resp = client.get(probe_url, attack=True)
            except Exception:
                continue
            location = resp.response_headers.get("location", "")
            chain = resp.redirect_chain
            redirected_out = any("sentinel-open-redirect-probe.example" in hop for hop in chain)
            if (resp.status_code in (301, 302, 303, 307, 308) and "sentinel-open-redirect-probe.example" in location) or redirected_out:
                drafts.append(FindingDraft(
                    module_id=self.id,
                    title=f"Open redirect via parameter '{name}'",
                    owasp_category=self.owasp_category, cwe_ids=self.cwe_ids,
                    severity="medium", confidence="certain",
                    verification_status=VerificationStatus.evidence_observed.value,
                    parameter=name,
                    description=f"Parameter '{name}' redirects the user to an attacker-controlled origin without validation.",
                    reproduction_steps=[f"1. Send: GET {probe_url}", f"2. Observe redirect to {location or 'the probe domain'}."],
                    impact="Phishing via trusted-origin redirects; token leakage in OAuth flows.",
                    remediation="Validate redirect targets against an allowlist of trusted origins; use server-side mapping keys instead of raw URLs.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                    evidence={"type": "http_exchange", "url": probe_url, "status": resp.status_code,
                              "location": location[:200], "redirect_chain": chain[:5]},
                    **_base(probe_url, ctx),
                ))
        return drafts


class UnauthenticatedReplayModule(TestModule):
    """Replays an authenticated endpoint with an anonymous session."""
    id = "active.unauthenticated_replay"
    title = "Endpoint reachable without authentication"
    owasp_category = "A01:2025 — Broken Access Control"
    cwe_ids = ["CWE-306"]
    safety = "safe"
    min_profile = "standard"

    def applies(self, ctx: EndpointContext) -> bool:
        return ctx.method == "GET" and ctx.has_session and ctx.baseline is not None and ctx.policy is not None

    def run(self, client: SafeHttpClient, ctx: EndpointContext) -> list[FindingDraft]:
        baseline = ctx.baseline
        if not baseline.response_body or len(baseline.response_body) < 100:
            return []
        anon = SafeHttpClient(
            ctx.policy,
            max_requests=10,
            rate_limit_rps=1.0,
            controls=ctx.controls,
        )
        try:
            resp = anon.get(ctx.url, attack=True)
        except Exception as exc:
            logger.info("anon replay failed: %s", exc)
            return []
        finally:
            anon.close()
        if resp.status_code == 200 and body_similarity(baseline.response_body, resp.response_body) > 0.9:
            return [FindingDraft(
                module_id=self.id,
                title="Authenticated content returned to unauthenticated requests",
                owasp_category=self.owasp_category, cwe_ids=self.cwe_ids,
                severity="high", confidence="firm",
                verification_status=VerificationStatus.suspected.value,
                role=ctx.role,
                description="The endpoint returned substantially identical content without authentication credentials. Manual verification is required to confirm the missing-control interpretation.",
                reproduction_steps=[f"1. Authenticate and note the response of GET {ctx.url}.",
                                    "2. Repeat the request with cookies/credentials removed.",
                                    "3. Observe substantially identical content."],
                impact="Protected data and functions are exposed to anonymous users.",
                root_cause_hypothesis="Authorization check missing or only enforced client-side for this endpoint.",
                remediation="Enforce server-side authorization on every endpoint (default deny).",
                references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                evidence={"type": "http_exchange", "url": ctx.url,
                          "status_authenticated": baseline.status_code, "status_anonymous": resp.status_code,
                          "similarity": body_similarity(baseline.response_body, resp.response_body),
                          "requires_manual_review": True},
                **_base(ctx.url, ctx),
            )]
        return []


def _original_param_value(url: str, name: str) -> str:
    for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if k == name:
            return v
    return ""


def _playwright_ok() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except ImportError:
        return False


def _browser_execution_check(url: str) -> bool | None:
    """Verify script execution in a real browser context. Returns None when the
    optional Playwright integration is not configured (honest 'unverified')."""
    if not _playwright_ok():
        return None
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=10_000)
            page.wait_for_timeout(1_500)
            executed = page.evaluate("document.title === '1'")
            browser.close()
            return bool(executed)
    except Exception as exc:
        logger.info("browser execution check failed: %s", exc)
        return None


ACTIVE_MODULES: list[TestModule] = [
    ReflectedXSSModule(),
    SQLInjectionModule(),
    PathTraversalModule(),
    VerboseErrorInjectionModule(),
    DirectoryListingProbeModule(),
    CORSReflectionModule(),
    OpenRedirectModule(),
    UnauthenticatedReplayModule(),
]