"""Scan pipeline: orchestration of crawling, context extraction, test selection,
controlled mutation, differential analysis, confirmation, correlation and evidence
generation.

Stages (docs/ARCHITECTURE.md): baseline -> context -> selection -> mutation ->
differential -> confirmation -> correlation -> prioritization -> evidence.
"""
from __future__ import annotations

import json
import logging
import re
import time
from urllib.parse import urljoin

from .. import db as db_module
from ..config import settings
from ..crypto import decrypt_secret
from ..deps import kill_switch_enabled, scan_cancel_requested, scan_pause_requested
from ..models import (Application, Endpoint, Evidence, Finding, HttpExchange,
                      Scan, ScanConfig, TestExecution, now, uid)
from ..redaction import redact_body, redact_headers, redact_url_params
from ..scope_guard import ScopePolicy, ScopeViolation, validate_scope_policy, validate_url
from .authn import build_sessions, session_expired
from .base import EndpointContext, FindingDraft, module_enabled_for_profile
from .crawler import CrawlResult, HTTPCrawler, crawl_browser_optional
from .dedup import finding_key, should_upgrade_severity
from .discovery import extract_query_params
from .modules.access_control import RoleDifferentialModule
from .modules.active import ACTIVE_MODULES
from .passive import run_passive_checks
from .transport import (BudgetExhausted, Controls, Exchange, KillSwitchTriggered,
                        SafeHttpClient, ScanCancelled)

logger = logging.getLogger("sentinel.pipeline")


class ExchangeRecorder:
    """Persists HTTP exchanges with secret redaction applied before storage."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    def __call__(self, exchange: Exchange) -> None:
        db = db_module.SessionLocal()
        try:
            db.add(HttpExchange(
                scan_id=self.scan_id,
                method=exchange.method,
                url=redact_url_params(exchange.url)[:1000],
                status_code=exchange.status_code,
                request_headers=redact_headers(exchange.request_headers),
                request_body=redact_body(exchange.request_body),
                response_headers=redact_headers(exchange.response_headers),
                response_body=redact_body(exchange.response_body),
                duration_ms=exchange.duration_ms,
                is_attack_request=exchange.is_attack,
            ))
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()


def _controls(scan_id: str) -> Controls:
    return Controls(
        kill_check=kill_switch_enabled,
        cancel_check=lambda: scan_cancel_requested(scan_id),
        pause_check=lambda: scan_pause_requested(scan_id),
    )


def _sitemap_seeds(client: SafeHttpClient, sitemap_url: str) -> list[str]:
    try:
        exchange = client.get(sitemap_url)
        return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", exchange.response_body or "")[:100]
    except Exception as exc:
        logger.info("sitemap fetch failed: %s", exc)
        return []


class ScanPipeline:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    # ------------------------------------------------------------------ entry
    def _run(self) -> None:
        db = db_module.SessionLocal()
        try:
            scan = db.get(Scan, self.scan_id)
            if scan is None or scan.status not in ("pending", "queued"):
                return
            app = db.get(Application, scan.application_id)
            config = db.get(ScanConfig, scan.config_id)

            scan.status = "running"
            scan.phase = "crawl"
            scan.started_at = now()
            db.commit()

            policy = ScopePolicy.from_application(app, settings.allow_private_targets)
            try:
                validate_scope_policy(policy)
            except ScopeViolation as exc:
                self._finish_standalone("failed", str(exc))
                return

            deadline = time.time() + config.max_duration_seconds
            controls = _controls(self.scan_id)

            auth_config: dict = {}
            if config.auth_config_encrypted:
                try:
                    auth_config = json.loads(decrypt_secret(config.auth_config_encrypted))
                except Exception:
                    logger.warning("auth config could not be decrypted; continuing anonymous")
            transport_cfg = {"max_requests": config.max_requests,
                             "rate_limit_rps": config.rate_limit_rps}

            recorder = ExchangeRecorder(self.scan_id)
            sessions = build_sessions(policy, config.auth_type, auth_config, transport_cfg, controls)
            for session in sessions:
                session.client._client.headers.setdefault("User-Agent", "SentinelDAST/0.1 (authorized scan)")
            recorder_hooks = [s.client for s in sessions]
            for client in recorder_hooks:
                client.on_exchange = recorder

            seeds = [app.base_url] + self._openapi_seeds(app.base_url, config.openapi_spec)
            if config.sitemap_url and sessions:
                seeds += _sitemap_seeds(sessions[0].client, config.sitemap_url)

            # ------------------------------------------------------- crawling
            crawl = CrawlResult()
            sessions_to_crawl = sessions[:2]
            per_session_urls = max(20, config.max_urls // max(1, len(sessions_to_crawl)))
            for session in sessions_to_crawl:
                crawler = HTTPCrawler(session.client, policy,
                                      max_depth=config.max_depth, max_urls=per_session_urls)
                part = crawler.crawl(seeds)
                crawl.urls |= part.urls
                crawl.forms += part.forms
                crawl.js_endpoints |= part.js_endpoints

            browser_note = "disabled"
            if config.render_js:
                browser_result, browser_note = crawl_browser_optional(
                    policy, seeds, max_pages=min(50, config.max_urls // 2))
                if browser_result:
                    crawl.urls |= browser_result.urls
                    crawl.forms += browser_result.forms
                    crawl.js_endpoints |= browser_result.js_endpoints

            scan.progress = {
                "browser_crawler": browser_note,
                "playwright_available": browser_note != "disabled" and browser_note == "ok",
                "crawl_urls": len(crawl.urls),
                "forms": len(crawl.forms),
                "js_endpoints": len(crawl.js_endpoints),
            }
            db.commit()

            # --------------------------------------------------- endpoint rows
            seen = {(e.url, e.method) for e in
                    db.query(Endpoint).filter_by(scan_id=self.scan_id).all()}

            def add_endpoint(url: str, method: str = "GET", params: list | None = None) -> Endpoint | None:
                if (url, method) in seen:
                    return None
                ep = Endpoint(
                    organization_id=scan.organization_id,
                    application_id=scan.application_id,
                    scan_id=self.scan_id,
                    url=url[:1000], method=method,
                    parameters=params or [],
                    auth_required=session_any_auth,
                    observed_role=roles[0] if roles else None,
                )
                db.add(ep)
                seen.add((url, method))
                return ep

            session_any_auth = any(s.context.kind != "anonymous" for s in sessions)
            roles = [s.context.role for s in sessions]
            for url in sorted(crawl.urls):
                add_endpoint(url, params=extract_query_params(url))
            for form in crawl.forms:
                if form.method == "GET":
                    add_endpoint(form.action, "GET",
                                 [{"name": f["name"], "source": "form", "type": f["type"]} for f in form.fields])
            for js_url in sorted(crawl.js_endpoints)[:100]:
                try:
                    validate_url(js_url, policy)
                except ScopeViolation:
                    continue
                add_endpoint(js_url, params=extract_query_params(js_url))
            db.commit()

            endpoint_rows = db.query(Endpoint).filter_by(scan_id=self.scan_id).all()
            scan.endpoints_discovered = len(endpoint_rows)
            db.commit()

            # --------------------------------------- baseline + context + passive
            scan.phase = "passive"
            db.commit()

            drafts: list[FindingDraft] = []
            contexts: list[tuple] = []  # (session, ctx, ep)
            for session in sessions:
                others = [{"role": s.context.role, "client": s.client}
                          for s in sessions if s is not session]
                get_endpoints = [ep for ep in endpoint_rows if ep.method == "GET"][:config.max_urls]
                for ep in get_endpoints:
                    self._check_deadline(deadline)
                    try:
                        baseline = session.client.get(ep.url)
                    except ScopeViolation:
                        continue
                    except (BudgetExhausted, ScanCancelled, KillSwitchTriggered):
                        raise
                    except Exception as exc:
                        db.add(TestExecution(scan_id=self.scan_id, module_id="transport",
                                             endpoint_id=ep.id, status="failed",
                                             detail=redact_body(f"{type(exc).__name__}: {exc}")[:1000]))
                        db.commit()
                        continue

                    ctx = EndpointContext(
                        url=ep.url, method=ep.method, parameters=ep.parameters,
                        content_type=baseline.response_headers.get("content-type"),
                        has_session=session.context.kind != "anonymous",
                        role=session.context.role,
                        technologies=[], baseline=baseline,
                        other_sessions=others, auth_probe_url=app.base_url,
                        policy=policy, controls=controls,
                    )
                    ep.status_code = baseline.status_code
                    ep.content_type = ctx.content_type
                    contexts.append((session, ctx, ep))

                    for draft in run_passive_checks(baseline, ctx):
                        drafts.append(draft)
                    db.add(TestExecution(scan_id=self.scan_id, module_id="passive",
                                         endpoint_id=ep.id, status="ran"))
                    db.commit()

            # ------------------------------------------------ session validity
            if config.auth_type != "anonymous":
                for session in sessions:
                    if session.context.kind != "anonymous" and session_expired(session.client, app.base_url):
                        scan.progress = dict(scan.progress or {}) | {"session_expired": session.context.role}
                        db.add(TestExecution(scan_id=self.scan_id, module_id="auth.session",
                                             status="inconclusive",
                                             detail=f"Session for role {session.context.role} appears expired; authenticated tests may be incomplete"))

            # ------------------------------------------- active test selection
            scan.phase = "active"
            db.commit()

            all_modules = list(ACTIVE_MODULES) + [RoleDifferentialModule()]
            for session, ctx, ep in contexts:
                for module in all_modules:
                    self._check_deadline(deadline)
                    if not module_enabled_for_profile(module, config.profile):
                        continue
                    if not module.applies(ctx):
                        continue
                    try:
                        module_drafts = module.run(session.client, ctx)
                    except (ScanCancelled, KillSwitchTriggered, BudgetExhausted):
                        raise
                    except Exception as exc:
                        db.add(TestExecution(scan_id=self.scan_id, module_id=module.id,
                                             endpoint_id=ep.id, status="failed",
                                             detail=redact_body(f"{type(exc).__name__}: {exc}")[:1000]))
                        db.commit()
                        continue
                    if module_drafts:
                        drafts.extend(module_drafts)
                        db.add(TestExecution(scan_id=self.scan_id, module_id=module.id,
                                             endpoint_id=ep.id, status="finding",
                                             detail="; ".join(d.title for d in module_drafts)[:500]))
                    else:
                        db.add(TestExecution(scan_id=self.scan_id, module_id=module.id,
                                             endpoint_id=ep.id, status="ran"))
                    db.commit()

            # ------------------------------------- correlation, dedup, evidence
            scan.phase = "finalize"
            db.commit()

            matched_keys: set[str] = set()
            for draft in drafts:
                key = finding_key(draft.owasp_category, draft.module_id, draft.url,
                                  draft.method, draft.parameter)
                existing = db.query(Finding).filter_by(
                    application_id=scan.application_id, finding_key=key).first()
                if existing is not None:
                    matched_keys.add(key)
                    existing.last_detected = now()
                    if should_upgrade_severity(existing.severity, draft.severity):
                        existing.severity = draft.severity
                    continue
                finding = Finding(
                    organization_id=scan.organization_id,
                    application_id=scan.application_id,
                    scan_id=self.scan_id,
                    finding_key=key,
                    title=draft.title, module_id=draft.module_id,
                    owasp_category=draft.owasp_category, cwe_ids=draft.cwe_ids,
                    severity=draft.severity, confidence=draft.confidence,
                    verification_status=draft.verification_status,
                    url=draft.url[:1000], method=draft.method,
                    parameter=draft.parameter, role=draft.role,
                    description=draft.description,
                    preconditions=draft.preconditions,
                    reproduction_steps=draft.reproduction_steps,
                    impact=draft.impact,
                    root_cause_hypothesis=draft.root_cause_hypothesis,
                    remediation=draft.remediation,
                    references=draft.references,
                    cvss_vector=draft.cvss_vector, cvss_score=draft.cvss_score,
                )
                db.add(finding)
                db.flush()  # materialize the generated finding ID before storing evidence
                ev = draft.evidence or {}
                db.add(Evidence(
                    finding_id=finding.id,
                    kind=ev.get("type", "http_exchange"),
                    redacted_request={
                        "url": redact_url_params(ev.get("url", draft.url))[:1000],
                        "method": ev.get("method", draft.method),
                        "original": ev.get("original", {}),
                        "mutated": ev.get("mutated", {}),
                    },
                    redacted_response={k: v for k, v in ev.items()
                                       if k not in ("url", "method", "original", "mutated")},
                    notes=ev.get("note", ""),
                ))
            db.commit()

            # ------------------------------------------------------- retesting
            if scan.is_retest and scan.parent_scan_id:
                for parent_finding in db.query(Finding).filter_by(
                        application_id=scan.application_id).filter(
                        Finding.scan_id == scan.parent_scan_id).all():
                    if parent_finding.finding_key in matched_keys:
                        parent_finding.retest_status = "reproduced"
                    else:
                        parent_finding.retest_status = "not_reproduced"
                db.commit()

            # -------------------------------------------------------- finalize
            scan.requests_sent = sum(s.client.requests_sent for s in sessions)
            scan.tests_run = db.query(TestExecution).filter_by(scan_id=self.scan_id).filter(
                TestExecution.status.in_(["ran", "finding"])).count()
            scan.endpoints_discovered = len(endpoint_rows)
            self._finish(db, scan, "completed")

            try:
                from ..services.reporting import generate_scan_reports
                generate_scan_reports(self.scan_id)
            except Exception:
                logger.exception("report generation failed")

            from ..deps import record_audit
            record_audit(db, None, "scan.completed", "scan", self.scan_id, {"status": "completed"})
            db.commit()

        finally:
            db.close()

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _check_deadline(deadline: float) -> None:
        if time.time() > deadline:
            raise BudgetExhausted("max scan duration reached")

    @staticmethod
    def _openapi_seeds(base_url: str, spec: dict | None) -> list[str]:
        if not spec:
            return []
        seeds = []
        try:
            for path in list((spec or {}).get("paths", {}) or {})[:100]:
                concrete = re.sub(r"\{[^}]+\}", "sentinel-placeholder", str(path))
                seeds.append(urljoin(base_url, concrete))
        except Exception:
            pass
        return seeds

    @staticmethod
    def _finish(db, scan: Scan, status: str, error: str | None = None) -> None:
        scan.status = status
        scan.phase = "done"
        scan.finished_at = now()
        scan.error_message = error
        db.commit()

    def _finish_standalone(self, status: str, error: str | None) -> None:
        db = db_module.SessionLocal()
        try:
            scan = db.get(Scan, self.scan_id)
            if scan is None:
                return
            if status == "completed" and scan.error_message is None:
                error = None
            self._finish(db, scan, status, redact_body(error) if error else None)
        finally:
            db.close()


def run_scan(scan_id: str) -> None:
    """Entry point used by the Celery worker, the fallback thread, and tests."""
    pipeline = ScanPipeline(scan_id)
    try:
        pipeline._run()
    except ScanCancelled as exc:
        pipeline._finish_standalone("cancelled", str(exc))
    except KillSwitchTriggered as exc:
        pipeline._finish_standalone("cancelled", str(exc))
    except BudgetExhausted as exc:
        pipeline._finish_standalone("completed", f"Budget limit reached: {exc}")
    except ScopeViolation as exc:
        pipeline._finish_standalone("failed", str(exc))
    except Exception as exc:
        logger.exception("scan %s failed", scan_id)
        pipeline._finish_standalone("failed", f"{type(exc).__name__}: {exc}")