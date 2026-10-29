"""Report generation: technical and executive reports in HTML and JSON,
generated strictly from persisted findings. HTML is rendered with autoescaping
because findings contain untrusted (target-controlled) content."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import jinja2

from .. import db as db_module
from ..config import settings
from ..models import Application, Endpoint, Finding, Report, Scan, ScanConfig, TestExecution

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

_TEMPLATE_ENV = jinja2.Environment(autoescape=True)

_TECHNICAL_TEMPLATE = _TEMPLATE_ENV.from_string("""<!doctype html>
<html><head><meta charset="utf-8"><title>Sentinel DAST — Technical Report</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a202c}
h1{border-bottom:2px solid #2563eb;padding-bottom:.3rem}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #cbd5e0;padding:.4rem .6rem;text-align:left;font-size:.9rem}
.sev-critical{background:#7f1d1d;color:#fff}.sev-high{background:#c53030;color:#fff}
.sev-medium{background:#d69e2e}.sev-low{background:#3182ce;color:#fff}.sev-informational{background:#a0aec0}
code,pre{background:#edf2f7;padding:.15rem .35rem;border-radius:4px;font-size:.85rem;white-space:pre-wrap}
.note{background:#fefcbf;padding:.5rem .8rem;border-left:4px solid #d69e2e;margin:1rem 0}
</style></head><body>
<h1>Sentinel DAST — Technical Report</h1>
<p><b>Application:</b> {{ report.application.name }} ({{ report.application.environment }})<br>
<b>Target:</b> {{ report.application.base_url }}<br>
<b>Scan:</b> {{ report.scan.id }} · started {{ report.scan.started_at }} · finished {{ report.scan.finished_at }}<br>
<b>Profile:</b> {{ report.scan.profile }} · requests {{ report.scan.requests_sent }} · endpoints {{ report.coverage.endpoints }}</p>

<div class="note">This report covers only the tests that actually ran. Untested areas and
inconclusive tests are listed explicitly; absence of findings is not proof of absence of
vulnerabilities, and scan profiles do not guarantee OWASP Top 10 coverage.</div>

<h2>Severity distribution</h2>
<table><tr><th>Severity</th><th>Findings</th></tr>
{% for sev, count in report.severity_distribution.items() %}<tr><td class="sev-{{ sev }}">{{ sev }}</td><td>{{ count }}</td></tr>{% endfor %}</table>

<h2>Coverage by OWASP category</h2>
<table><tr><th>Category</th><th>Findings</th></tr>
{% for cat, count in report.owasp_distribution.items() %}<tr><td>{{ cat }}</td><td>{{ count }}</td></tr>
{% endfor %}</table>

<h2>Findings ({{ report.findings|length }})</h2>
{% for f in report.findings %}
<div style="margin:1.5rem 0;border:1px solid #cbd5e0;border-radius:8px;padding:1rem">
<h3>{{ f.title }}</h3>
<p><span class="sev-{{ f.severity }}">{{ f.severity|upper }}</span>
· {{ f.owasp_category }} · {{ f.cwe_ids|join(', ') }}<br>
<b>Verification:</b> {{ f.verification_status }} · <b>Confidence:</b> {{ f.confidence }}<br>
<b>Location:</b> <code>{{ f.method }} {{ f.url }}</code>{% if f.parameter %} · parameter <code>{{ f.parameter }}</code>{% endif %}</p>
<p>{{ f.description }}</p>
<p><b>Preconditions:</b> {{ f.preconditions }}</p>
<p><b>Reproduction:</b></p><pre>{{ f.reproduction_steps|join('\n') }}</pre>
<p><b>Impact:</b> {{ f.impact }}</p>
<p><b>Remediation:</b> {{ f.remediation }}</p>
{% if f.evidence %}
<p><b>Evidence:</b></p><pre>{{ f.evidence|tojson }}</pre>
{% endif %}
</div>
{% else %}
<p><b>No findings were produced by this scan.</b></p>
{% endfor %}

<h2>Untested areas and limitations</h2>
<ul>
{% for lim in report.limitations %}<li>{{ lim }}</li>{% endfor %}
</ul>
</body></html>""")

_EXECUTIVE_TEMPLATE = _TEMPLATE_ENV.from_string("""<!doctype html>
<html><head><meta charset="utf-8"><title>Sentinel DAST — Executive Report</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a202c}
h1{border-bottom:2px solid #2563eb;padding-bottom:.3rem}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #cbd5e0;padding:.4rem .6rem;text-align:left}
li{margin:.3rem 0}
.note{background:#fefcbf;padding:.5rem .8rem;border-left:4px solid #d69e2e;margin:1rem 0}
</style></head><body>
<h1>Sentinel DAST — Executive Report</h1>
<p><b>Application:</b> {{ report.application.name }} ({{ report.application.environment }} environment)<br>
<b>Scope:</b> {{ report.application.base_url }}<br>
<b>Assessment window:</b> {{ report.scan.started_at }} — {{ report.scan.finished_at }}</p>

<h2>Overall risk summary</h2>
<p>{{ report.findings|length }} findings, of which
{{ report.confirmed_count }} carry evidence-confirmed status.
{% if report.severity_distribution.critical %}<b>Critical findings require immediate attention.</b>{% endif %}</p>

<h2>Severity distribution</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
{% for sev, count in report.severity_distribution.items() %}<tr><td>{{ sev|capitalize }}</td><td>{{ count }}</td></tr>{% endfor %}</table>

<h2>Most significant findings</h2>
<ul>
{% for f in report.findings[:8] %}
<li><b>{{ f.title }}</b> — {{ f.severity|capitalize }} ({{ f.owasp_category }})</li>
{% else %}<li>No findings — see limitations for untested areas.</li>
{% endfor %}</ul>

<h2>Business impact</h2>
<p>Confirmed and suspected findings should be assessed against the affected data flows.
Security misconfiguration findings increase exposure to automated exploitation; injection
indicators can lead to data theft; access-control weaknesses can bypass user boundaries.</p>

<h2>Remediation priorities</h2>
<ol>
<li>Validate and remediate critical/high findings first (see technical report reproduction steps).</li>
<li>Apply security-header and cookie hardening as low-effort, high-coverage fixes.</li>
<li>Schedule retesting after remediation to confirm effectiveness.</li>
</ol>

<h2>Limitations and exclusions</h2>
<ul>
{% for lim in report.limitations %}<li>{{ lim }}</li>{% endfor %}
</ul>
</body></html>""")


def scan_report_data(scan_id: str) -> dict:
    db = db_module.SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"scan {scan_id} not found")
        app = db.get(Application, scan.application_id)
        config = db.get(ScanConfig, scan.config_id)
        findings = db.query(Finding).filter_by(scan_id=scan.id).all()
        endpoints = db.query(Endpoint).filter_by(scan_id=scan.id).count()
        executions = db.query(TestExecution).filter_by(scan_id=scan.id).all()

        exec_counts: dict = {}
        for e in executions:
            exec_counts[e.status] = exec_counts.get(e.status, 0) + 1

        severity_distribution = {s: sum(1 for f in findings if f.severity == s)
                                 for s in _SEVERITY_ORDER}
        severity_distribution = {k: v for k, v in severity_distribution.items() if v}
        owasp_distribution: dict = {}
        for f in findings:
            owasp_distribution[f.owasp_category] = owasp_distribution.get(f.owasp_category, 0) + 1
        confirmed_count = sum(1 for f in findings
                              if f.verification_status in ("validated", "evidence_observed"))

        limitations = [
            "Automated scanning covered only the requests actually sent; untested areas are not represented here.",
            "Scan profile used: " + (config.profile if config else "unknown") + ". Profiles do not guarantee OWASP Top 10 coverage.",
            "Tests that could not produce reliable evidence were recorded as inconclusive (see test executions).",
            "Business-logic and logging findings marked 'requires_manual_review' need human validation.",
        ]
        if exec_counts.get("skipped"):
            limitations.append(f"{exec_counts['skipped']} test executions were skipped by profile gating or scope rules.")

        findings_data = []
        for f in findings:
            evidence_rows = db_module.SessionLocal()
            try:
                from ..models import Evidence
                evs = evidence_rows.query(Evidence).filter_by(finding_id=f.id).all()
                evidence = [
                    {"kind": e.kind, "request": e.redacted_request, "response": e.redacted_response}
                    for e in evs
                ]
            finally:
                evidence_rows.close()
            findings_data.append({
                "id": f.id, "title": f.title, "owasp_category": f.owasp_category,
                "cwe_ids": f.cwe_ids, "severity": f.severity, "confidence": f.confidence,
                "verification_status": f.verification_status, "url": f.url, "method": f.method,
                "parameter": f.parameter, "role": f.role, "description": f.description,
                "preconditions": f.preconditions, "reproduction_steps": f.reproduction_steps,
                "impact": f.impact, "root_cause_hypothesis": f.root_cause_hypothesis,
                "remediation": f.remediation, "references": f.references,
                "cvss_vector": f.cvss_vector, "cvss_score": f.cvss_score,
                "status": f.status, "retest_status": f.retest_status,
                "first_detected": f.first_detected.isoformat(),
                "evidence": evidence,
            })

        return {
            "application": {"name": app.name, "base_url": app.base_url,
                            "environment": app.environment,
                            "allowed_hosts": app.allowed_hosts,
                            "excluded_paths": app.excluded_paths},
            "scan": {"id": scan.id, "profile": config.profile if config else None,
                     "started_at": scan.started_at.isoformat() if scan.started_at else None,
                     "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                     "requests_sent": scan.requests_sent, "is_retest": scan.is_retest},
            "findings": findings_data,
            "severity_distribution": severity_distribution,
            "owasp_distribution": owasp_distribution,
            "confirmed_count": confirmed_count,
            "coverage": {"endpoints": endpoints,
                         "tests_run": exec_counts.get("ran", 0) + exec_counts.get("finding", 0),
                         "test_executions": exec_counts},
            "limitations": limitations,
        }
    finally:
        db.close()


def _storage_path(org_id: str, report_id: str, fmt: str) -> str:
    directory = os.path.join(settings.object_storage_dir, org_id)
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, f"{report_id}.{fmt}")


def _persist_report(db, scan: Scan, kind: str, fmt: str, content: str) -> Report:
    report = Report(organization_id=scan.organization_id, scan_id=scan.id,
                    application_id=scan.application_id, kind=kind, format=fmt, storage_path="")
    db.add(report)
    db.flush()
    path = _storage_path(scan.organization_id, report.id, fmt)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    report.storage_path = path
    db.commit()
    db.refresh(report)
    return report


def generate_scan_reports(scan_id: str) -> list[Report]:
    """Generate technical (html + json) and executive (html) reports for a scan."""
    db = db_module.SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return []
        data = scan_report_data(scan_id)
        reports = [
            _persist_report(db, scan, "technical", "json",
                            json.dumps(data, indent=2, default=str)),
            _persist_report(db, scan, "technical", "html",
                            _TECHNICAL_TEMPLATE.render(report=data)),
            _persist_report(db, scan, "executive", "html",
                            _EXECUTIVE_TEMPLATE.render(report=data)),
        ]
        return reports
    finally:
        db.close()


def portfolio_report_data(organization_id: str) -> dict:
    db = db_module.SessionLocal()
    try:
        apps = db.query(Application).filter_by(organization_id=organization_id).all()
        per_app = []
        for app in apps:
            findings = db.query(Finding).filter_by(application_id=app.id).all()
            open_count = sum(1 for f in findings if f.status in ("open", "confirmed"))
            per_app.append({
                "application": app.name, "environment": app.environment,
                "findings_total": len(findings),
                "findings_open": open_count,
                "critical": sum(1 for f in findings if f.severity == "critical" and f.status != "fixed"),
                "high": sum(1 for f in findings if f.severity == "high" and f.status != "fixed"),
            })
        return {"organization_id": organization_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "applications": per_app}
    finally:
        db.close()