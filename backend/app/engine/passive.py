"""Passive security analysis: traffic-only checks, no injected payloads.

Findings produced here differentiate confirmed exposure from informational
fingerprinting (severity + confidence reflect that distinction).
"""
from __future__ import annotations

import re

from .base import EndpointContext, FindingDraft, VerificationStatus
from .transport import Exchange

_STACK_SIGNATURES = [
    "traceback (most recent call last)", "at org.", "exception in thread",
    "system.web.httpexception", "warning: mysql", "psql:fatal", "sqlstate[",
    "stack trace:", "django debug page", "syntax error at or near",
]

_SOURCEMAP_RE = re.compile(r"""["'\s]([^\s"'']+\.js\.map)""")
_MIXED_RE = re.compile(r"""(?:src|href)\s*=\s*["']http://[^"']+["']""", re.I)


def _evidence(exchange: Exchange, url: str, note: str) -> dict:
    return {
        "type": "http_exchange",
        "url": url,
        "method": exchange.method,
        "status": exchange.status_code,
        "note": note,
    }


def run_passive_checks(exchange: Exchange, ctx: EndpointContext) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    headers = exchange.response_headers
    body = exchange.response_body or ""
    url = exchange.url
    is_https = url.startswith("https://")
    base = {
        "url": url,
        "method": exchange.method,
        "role": ctx.role,
        "references": ["https://owasp.org/www-project-top-ten/"],
    }

    # ---- A02: security headers
    if "content-security-policy" not in headers:
        drafts.append(FindingDraft(
            module_id="passive.csp_missing",
            title="Missing Content-Security-Policy header",
            owasp_category="A02:2025 — Security Misconfiguration",
            cwe_ids=["CWE-693"], severity="medium", confidence="certain",
            verification_status=VerificationStatus.evidence_observed.value,
            description="The response does not include a Content-Security-Policy header, removing a key mitigation against XSS and content-injection attacks.",
            remediation="Define and deploy a restrictive CSP, beginning with default-src 'self' and iterating with report-only mode.",
            evidence=_evidence(exchange, url, "CSP header absent"),
            **base,
        ))
    if is_https and "strict-transport-security" not in headers:
        drafts.append(FindingDraft(
            module_id="passive.hsts_missing",
            title="Missing Strict-Transport-Security header (HSTS)",
            owasp_category="A02:2025 — Security Misconfiguration",
            cwe_ids=["CWE-319"], severity="low", confidence="certain",
            verification_status=VerificationStatus.evidence_observed.value,
            description="HTTPS response lacks HSTS, permitting SSL-stripping downgrade attempts.",
            remediation="Send Strict-Transport-Security: max-age=63072000; includeSubDomains on all HTTPS responses.",
            evidence=_evidence(exchange, url, "HSTS header absent on HTTPS response"),
            **base,
        ))
    if "x-content-type-options" not in headers:
        drafts.append(FindingDraft(
            module_id="passive.xcto_missing",
            title="Missing X-Content-Type-Options header",
            owasp_category="A02:2025 — Security Misconfiguration",
            cwe_ids=["CWE-693"], severity="low", confidence="certain",
            verification_status=VerificationStatus.evidence_observed.value,
            description="Without nosniff, browsers may MIME-sniff responses into executable contexts.",
            remediation="Send X-Content-Type-Options: nosniff.",
            evidence=_evidence(exchange, url, "X-Content-Type-Options absent"),
            **base,
        ))
    if "x-frame-options" not in headers and "frame-ancestors" not in (headers.get("content-security-policy") or ""):
        drafts.append(FindingDraft(
            module_id="passive.framing_not_restricted",
            title="Framing not restricted (clickjacking exposure)",
            owasp_category="A02:2025 — Security Misconfiguration",
            cwe_ids=["CWE-1021"], severity="low", confidence="certain",
            verification_status=VerificationStatus.evidence_observed.value,
            description="Neither X-Frame-Options nor CSP frame-ancestors restrict framing.",
            remediation="Send X-Frame-Options: DENY or a CSP frame-ancestors directive.",
            evidence=_evidence(exchange, url, "no framing restriction headers"),
            **base,
        ))
    for h in ("server", "x-powered-by"):
        if h in headers and headers[h].strip():
            drafts.append(FindingDraft(
                module_id="passive.server_disclosure",
                title=f"Server software disclosed via {h} header",
                owasp_category="A02:2025 — Security Misconfiguration",
                cwe_ids=["CWE-200"], severity="informational", confidence="certain",
                verification_status=VerificationStatus.evidence_observed.value,
                description=f"The {h} header advertises server technology ({headers[h]}), aiding targeted attacks. Informational fingerprinting.",
                remediation="Suppress or genericize version-revealing server headers.",
                evidence=_evidence(exchange, url, f"{h}: {headers[h]}"),
                **base,
            ))

    # ---- A07: cookie flags
    for set_cookie in re.findall(r"(?i)set-cookie:\s*([^\r\n]+)", "\n".join(f"{k}: {v}" for k, v in headers.items())):
        name = set_cookie.split("=", 1)[0].strip()
        flags = set_cookie.lower()
        issues = []
        if is_https and "secure" not in flags:
            issues.append("missing Secure flag")
        if "httponly" not in flags:
            issues.append("missing HttpOnly flag")
        if "samesite" not in flags:
            issues.append("missing SameSite attribute")
        if issues:
            drafts.append(FindingDraft(
                module_id="passive.cookie_flags",
                title=f"Session cookie '{name}' lacks protections ({'; '.join(issues)})",
                owasp_category="A07:2025 — Authentication Failures",
                cwe_ids=["CWE-1004", "CWE-614"], severity="medium", confidence="certain",
                verification_status=VerificationStatus.evidence_observed.value,
                description=f"Cookie '{name}' was set without standard protective attributes: {', '.join(issues)}.",
                remediation="Set Secure, HttpOnly and SameSite=Lax (or Strict) on all session cookies.",
                evidence=_evidence(exchange, url, f"set-cookie: {name} [flags redacted]"),
                **base,
            ))

    # ---- A02: CORS
    acao = headers.get("access-control-allow-origin")
    if acao and (acao == "*" or acao.startswith("null")):
        drafts.append(FindingDraft(
            module_id="passive.cors_wildcard",
            title="Permissive CORS policy (wildcard/null origin)",
            owasp_category="A02:2025 — Security Misconfiguration",
            cwe_ids=["CWE-942"], severity="low", confidence="certain",
            verification_status=VerificationStatus.evidence_observed.value,
            description=f"Access-Control-Allow-Origin is '{acao}', allowing any origin to read responses.",
            remediation="Reflect only approved origins and never combine wildcard ACAO with credentials.",
            evidence=_evidence(exchange, url, f"access-control-allow-origin: {acao}"),
            **base,
        ))

    # ---- A10: observed verbose errors
    for sig in _STACK_SIGNATURES:
        if sig in body.lower():
            drafts.append(FindingDraft(
                module_id="passive.verbose_error",
                title="Verbose error information disclosed in response",
                owasp_category="A10:2025 — Mishandling of Exceptional Conditions",
                cwe_ids=["CWE-209"], severity="medium", confidence="firm",
                verification_status=VerificationStatus.evidence_observed.value,
                description=f"The response body contains error detail matching '{sig}'.",
                remediation="Return generic error pages; log details server-side with correlation IDs.",
                evidence=_evidence(exchange, url, f"stack-trace signature '{sig}' in body"),
                **base,
            ))
            break

    # ---- A04: sensitive content caching
    if ctx.has_session:
        cc = headers.get("cache-control", "")
        if "no-store" not in cc and "private" not in cc:
            drafts.append(FindingDraft(
                module_id="passive.cache_sensitive",
                title="Authenticated response may be cached by shared caches",
                owasp_category="A04:2025 — Cryptographic Failures",
                cwe_ids=["CWE-524"], severity="low", confidence="tentative",
                verification_status=VerificationStatus.suspected.value,
                description="An authenticated response lacks Cache-Control: no-store/private; intermediaries may retain sensitive content.",
                remediation="Send Cache-Control: no-store on authenticated, sensitive responses.",
                evidence=_evidence(exchange, url, f"cache-control: '{cc or 'absent'}'"),
                **base,
            ))

    # ---- A03: source maps
    for match in _SOURCEMAP_RE.findall(body)[:10]:
        drafts.append(FindingDraft(
            module_id="passive.sourcemap_reference",
            title="Source map referenced by served JavaScript",
            owasp_category="A03:2025 — Software Supply Chain Failures",
            cwe_ids=["CWE-540"], severity="low", confidence="tentative",
            verification_status=VerificationStatus.suspected.value,
            description=f"JavaScript references a source map ({match}). Public source maps can reveal implementation details.",
            remediation="Strip source maps from production bundles.",
            evidence=_evidence(exchange, url, f"sourcemap reference: {match}"),
            **base,
        ))

    # ---- A04: mixed content
    if is_https:
        for m in _MIXED_RE.findall(body)[:10]:
            drafts.append(FindingDraft(
                module_id="passive.mixed_content",
                title="Mixed content: HTTP resource referenced from HTTPS page",
                owasp_category="A04:2025 — Cryptographic Failures",
                cwe_ids=["CWE-311"], severity="medium", confidence="firm",
                verification_status=VerificationStatus.evidence_observed.value,
                description=f"HTTPS page references an insecure HTTP resource: {m}.",
                remediation="Serve all resources over HTTPS; apply CSP upgrade-insecure-requests.",
                evidence=_evidence(exchange, url, f"mixed-content reference: {m}"),
                **base,
            ))

    # ---- A02: directory listing observed
    if "<title>index of /" in body.lower() or "directory listing for" in body.lower():
        drafts.append(FindingDraft(
            module_id="passive.directory_listing",
            title="Directory listing exposed",
            owasp_category="A02:2025 — Security Misconfiguration",
            cwe_ids=["CWE-548"], severity="medium", confidence="certain",
            verification_status=VerificationStatus.evidence_observed.value,
            description="The server returned an auto-index directory listing.",
            remediation="Disable autoindex on directories not intended to be public.",
            evidence=_evidence(exchange, url, "directory listing page observed"),
            **base,
        ))

    return drafts


__all__ = ["run_passive_checks"]