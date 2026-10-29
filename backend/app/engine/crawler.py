"""Hybrid crawling: HTTP-level crawler plus an optional Playwright browser crawler.

The browser crawler is an OPTIONAL integration: when Playwright is not installed,
crawl_browser() returns (CrawlResult, "unconfigured") and the HTTP crawler keeps
working. The pipeline records this honestly in scan progress.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from ..scope_guard import ScopePolicy, ScopeViolation
from .discovery import extract_js_endpoints
from .transport import Exchange, SafeHttpClient

logger = logging.getLogger("sentinel.crawler")


@dataclass
class DiscoveredForm:
    action: str
    method: str
    fields: list[dict] = field(default_factory=list)


@dataclass
class CrawlResult:
    urls: set[str] = field(default_factory=set)
    forms: list[DiscoveredForm] = field(default_factory=list)
    js_endpoints: set[str] = field(default_factory=set)
    pages_fetched: int = 0


class HTTPCrawler:
    """Breadth-first HTTP crawler. Discovers links, forms, scripts and JS endpoints.
    Never submits forms (login is handled exclusively by the auth module) —
    discovery must not trigger real business transactions."""

    def __init__(self, client: SafeHttpClient, policy: ScopePolicy, *, max_depth: int = 3, max_urls: int = 200):
        self.client = client
        self.policy = policy
        self.max_depth = max_depth
        self.max_urls = max_urls

    def crawl(self, seeds: list[str]) -> CrawlResult:
        result = CrawlResult()
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(s, 0) for s in seeds]
        base_origin = urlsplit(self.policy.base_url)

        while queue and len(result.urls) < self.max_urls:
            url, depth = queue.pop(0)
            norm = url.split("#")[0].rstrip("?")
            if norm in visited:
                continue
            visited.add(norm)
            try:
                exchange = self.client.get(norm)
            except ScopeViolation as exc:
                logger.info("crawler skipped out-of-scope url: %s", exc)
                continue
            except Exception as exc:
                logger.info("crawler fetch error for %s: %s", norm, exc)
                continue

            result.pages_fetched += 1
            if exchange.status_code and exchange.status_code >= 400:
                continue
            result.urls.add(norm)
            if depth >= self.max_depth:
                continue

            soup = BeautifulSoup(exchange.response_body, "html.parser")

            for a in soup.find_all("a", href=True):
                nxt = urljoin(norm, a["href"].split("#")[0])
                if urlsplit(nxt).scheme not in ("http", "https"):
                    continue
                # cross-origin links are never followed (scope escape prevention)
                if urlsplit(nxt).netloc != base_origin.netloc:
                    continue
                if nxt not in visited and len(result.urls) + len(queue) < self.max_urls * 2:
                    queue.append((nxt, depth + 1))

            for form in soup.find_all("form"):
                action = urljoin(norm, form.get("action") or norm)
                fields = [
                    {"name": inp.get("name"), "type": inp.get("type", "text")}
                    for inp in form.find_all(["input", "textarea", "select"])
                    if inp.get("name")
                ]
                result.forms.append(DiscoveredForm(action=action, method=(form.get("method") or "GET").upper(), fields=fields))

            for script in soup.find_all("script"):
                for ep in extract_js_endpoints(script.string or script.get_text() or ""):
                    result.js_endpoints.add(urljoin(base_origin.geturl(), ep))
            for script in soup.find_all("script", src=True):
                result.js_endpoints.add(urljoin(norm, script["src"]))

        return result


def playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except ImportError:
        return False


class BrowserCrawler:
    """Optional Playwright-based crawler for SPAs. Captures rendered links and
    XHR/fetch traffic. Requires `playwright` and its browsers to be installed."""

    def __init__(self, policy: ScopePolicy, *, max_pages: int = 50, headers: dict | None = None,
                 cookies: list | None = None):
        self.policy = policy
        self.max_pages = max_pages
        self.headers = headers or {}
        self.cookies = cookies or []

    def crawl(self, seeds: list[str]) -> CrawlResult:
        from playwright.sync_api import sync_playwright

        result = CrawlResult()
        visited: set[str] = set()
        queue = [s.split("#")[0] for s in seeds]
        base_origin = urlsplit(self.policy.base_url).netloc

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(extra_http_headers=self.headers)
            if self.cookies:
                context.add_cookies(self.cookies)
            page = context.new_page()

            def on_request(req):
                try:
                    if urlsplit(req.url).netloc == base_origin and req.resource_type in ("xhr", "fetch"):
                        result.js_endpoints.add(req.url.split("?")[0])
                        if req.url not in result.urls:
                            result.urls.add(req.url)
                except Exception:
                    pass

            page.on("request", on_request)

            while queue and len(visited) < self.max_pages:
                url = queue.pop(0)
                if url in visited or urlsplit(url).netloc != base_origin:
                    continue
                visited.add(url)
                try:
                    page.goto(url, wait_until="networkidle", timeout=20_000)
                except Exception as exc:
                    logger.info("browser crawl skip %s: %s", url, exc)
                    continue
                result.pages_fetched += 1
                result.urls.add(url)
                for href in page.eval_on_selector_all("a", "els => els.map(e => e.href)") or []:
                    nxt = href.split("#")[0]
                    if urlsplit(nxt).scheme in ("http", "https") and nxt not in visited:
                        queue.append(nxt)
                for form in page.evaluate(
                    """() => Array.from(document.forms).map(f => ({
                        action: f.action, method: f.method.toUpperCase(),
                        fields: Array.from(f.elements).filter(e => e.name)
                            .map(e => ({name: e.name, type: e.type || 'text'})) }))"""
                ) or []:
                    result.forms.append(DiscoveredForm(**form))
            browser.close()

        return result


def crawl_browser_optional(policy: ScopePolicy, seeds: list[str], **kw) -> tuple[CrawlResult | None, str]:
    if not playwright_available():
        return None, "unconfigured"
    try:
        return BrowserCrawler(policy, **kw).crawl(seeds), "ok"
    except Exception as exc:  # browser crashes must not fail the whole scan
        logger.warning("browser crawler failed: %s", exc)
        return None, f"error: {exc}"