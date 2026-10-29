"""Safe outbound HTTP transport for the scan engine.

Every request goes through: kill-switch/cancel/pause checks -> request budget ->
full scope validation (scheme, allowlist, paths, DNS resolution with per-address
policy checks) -> token-bucket rate limiting -> send -> manual redirect loop where
each hop is independently re-validated. Exchanges are recorded for evidence.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlsplit

import httpx

from ..scope_guard import ScopePolicy, ScopeViolation, validate_redirect, validate_url

MAX_RESPONSE_BYTES = 200_000


class KillSwitchTriggered(Exception):
    """Global kill switch is active — all scans must stop immediately."""


class ScanCancelled(Exception):
    """This scan was cancelled by an operator."""


class BudgetExhausted(Exception):
    """Request budget or time budget exhausted."""


@dataclass
class Exchange:
    method: str
    url: str
    status_code: int | None
    request_headers: dict
    request_body: str | None
    response_headers: dict
    response_body: str
    duration_ms: int
    redirect_chain: list[str] = field(default_factory=list)
    is_attack: bool = False


class RateLimiter:
    """Token-bucket-ish minimum-interval limiter, thread-safe."""

    def __init__(self, rps: float):
        self.min_interval = 1.0 / max(rps, 0.01)
        self._lock = threading.Lock()
        self._next_slot = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next_slot - now)
            self._next_slot = max(now, self._next_slot) + self.min_interval
        if delay:
            time.sleep(delay)


@dataclass
class Controls:
    """Runtime scan controls wired to Redis by the pipeline."""

    kill_check: Callable[[], bool] | None = None
    cancel_check: Callable[[], bool] | None = None
    pause_check: Callable[[], bool] | None = None

    def check(self) -> None:
        while True:
            if self.kill_check and self.kill_check():
                raise KillSwitchTriggered("Global kill switch is active; all requests stopped")
            if self.cancel_check and self.cancel_check():
                raise ScanCancelled("Scan cancelled by operator")
            if self.pause_check and self.pause_check():
                time.sleep(1.0)
                continue
            return


class SafeHttpClient:
    def __init__(
        self,
        policy: ScopePolicy,
        *,
        max_requests: int = 500,
        rate_limit_rps: float = 1.0,
        timeout: float = 15.0,
        default_headers: dict | None = None,
        cookies: dict | None = None,
        controls: Controls | None = None,
        on_exchange: Callable[[Exchange], None] | None = None,
        max_redirects: int = 5,
    ):
        self.policy = policy
        self.max_requests = max_requests
        self.requests_sent = 0
        self.limiter = RateLimiter(rate_limit_rps)
        self.controls = controls or Controls()
        self.on_exchange = on_exchange
        self.max_redirects = max_redirects
        self._client = httpx.Client(
            follow_redirects=False,
            timeout=timeout,
            verify=True,
            headers=default_headers or {},
            cookies=cookies or {},
        )

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------ core
    def request(
        self,
        method: str,
        url: str,
        *,
        data: dict | str | None = None,
        json: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        attack: bool = False,
    ) -> Exchange:
        current = url
        chain: list[str] = []
        body: str | None = None
        first = True

        for _hop in range(self.max_redirects + 1):
            self.controls.check()
            if self.requests_sent >= self.max_requests:
                raise BudgetExhausted(f"Request budget of {self.max_requests} exhausted")

            validate_url(current, self.policy)  # raises ScopeViolation before any send
            self.limiter.wait()

            send_method = method if first else "GET"
            send_kwargs: dict = {"headers": headers if first else None}
            if first:
                if data is not None:
                    send_kwargs["data"] = data
                if json is not None:
                    send_kwargs["json"] = json
                if params is not None:
                    send_kwargs["params"] = params

            request_body = None
            if data is not None and first:
                request_body = data if isinstance(data, str) else str(data)
            elif json is not None and first:
                request_body = str(json)

            start = time.monotonic()
            resp = self._client.request(send_method.upper(), current, **send_kwargs)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            self.requests_sent += 1

            body = self._decode_body(resp)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            req_headers = {str(k).lower(): v for k, v in {**self._client.headers, **(headers or {})}.items()}

            exchange = Exchange(
                method=send_method.upper(),
                url=current,
                status_code=resp.status_code,
                request_headers=req_headers,
                request_body=request_body,
                response_headers=resp_headers,
                response_body=body,
                duration_ms=elapsed_ms,
                redirect_chain=list(chain),
                is_attack=attack,
            )
            if self.on_exchange:
                self.on_exchange(exchange)

            if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp_headers:
                try:
                    nxt = validate_redirect(current, resp_headers["location"], self.policy).url
                except ScopeViolation:
                    # Redirect escapes the approved scope: it is never followed
                    # (scope-escape prevention), but the exchange is returned so
                    # detection logic can inspect the Location header as evidence.
                    return exchange
                chain.append(nxt)
                current = nxt
                first = False
                method = "GET"
                continue
            return exchange

        return Exchange(
            method=method.upper(), url=current, status_code=None,
            request_headers={}, request_body=None, response_headers={},
            response_body="too many redirects", duration_ms=0, redirect_chain=chain,
            is_attack=attack,
        )

    @staticmethod
    def _decode_body(resp: httpx.Response) -> str:
        raw = resp.content[:MAX_RESPONSE_BYTES]
        return raw.decode(resp.encoding or "utf-8", errors="replace")

    # convenience
    def get(self, url: str, **kw) -> Exchange:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> Exchange:
        return self.request("POST", url, **kw)


__all__ = [
    "BudgetExhausted", "Controls", "Exchange", "KillSwitchTriggered",
    "RateLimiter", "SafeHttpClient", "ScanCancelled", "ScopeViolation",
]