"""Scope and target validation for outbound scan traffic.

Enforced at both API validation time and inside the scanning transport, so every
request — including every redirect hop — is re-validated. This module deliberately
does NOT rely on URL string matching alone: the target host is resolved and every
resolved address is checked against the private/link-local/loopback policy before a
request is sent.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# Cloud metadata and other never-scan addresses, even in lab mode.
RESERVED_FORBIDDEN_IPS = {"169.254.169.254"}


class ScopeViolation(Exception):
    """Raised when a URL or resolved address is outside the approved scope."""


def _address_forbidden(ip: str, allow_private: bool) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if str(addr) in RESERVED_FORBIDDEN_IPS:
        return True
    if allow_private:
        return False
    return not (
        addr.is_global
        and not addr.is_private
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_reserved
        and not addr.is_unspecified
    )


@dataclass
class ScopePolicy:
    base_url: str = ""
    allowed_hosts: list[str] = field(default_factory=list)
    included_paths: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    approved_origins: list[str] = field(default_factory=list)
    allow_private_targets: bool = False

    @classmethod
    def from_application(cls, app_row, allow_private: bool) -> "ScopePolicy":
        return cls(
            base_url=app_row.base_url,
            allowed_hosts=list(app_row.allowed_hosts or []),
            included_paths=list(app_row.included_paths or []),
            excluded_paths=list(app_row.excluded_paths or []),
            approved_origins=list(app_row.approved_origins or []),
            allow_private_targets=allow_private,
        )


@dataclass
class ResolvedTarget:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    resolved_ips: list[str]


def _host_allowed(policy: ScopePolicy, host: str) -> bool:
    h = host.lower().rstrip(".")
    base_host = urlsplit(policy.base_url).hostname or ""
    if base_host and h == base_host.lower().rstrip("."):
        return True
    for pattern in policy.allowed_hosts or []:
        p = str(pattern).lower().replace("http://", "").replace("https://", "").rstrip("/").rstrip(".")
        if p.startswith("*."):
            suffix = p[1:]  # ".example.com"
            if h.endswith(suffix) or h == p[2:]:
                return True
        elif h == p:
            return True
    return False


def _path_allowed(policy: ScopePolicy, path: str) -> bool:
    p = path or "/"
    for ex in policy.excluded_paths or []:
        if ex and p.startswith(ex):
            return False
    if policy.included_paths:
        return any(inc and p.startswith(inc) for inc in policy.included_paths)
    return True


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeViolation(f"DNS resolution failed for {host!r}") from exc
    return [str(info[4][0]) for info in infos]


def validate_url(url: str, policy: ScopePolicy) -> ResolvedTarget:
    """Full validation: scheme, host allowlist, path rules, DNS + per-IP checks."""
    try:
        parts = urlsplit(url)
    except Exception as exc:
        raise ScopeViolation(f"Unparseable URL: {url!r}") from exc

    if parts.scheme not in ("http", "https"):
        raise ScopeViolation(f"Scheme {parts.scheme!r} is not permitted (http/https only)")
    host = parts.hostname
    if not host:
        raise ScopeViolation(f"URL has no host: {url!r}")
    if not _host_allowed(policy, host):
        raise ScopeViolation(f"Host {host!r} is not in the approved scope")
    if not _path_allowed(policy, parts.path or "/"):
        raise ScopeViolation(f"Path {parts.path!r} is excluded from the approved scope")

    ips = resolve_host(host)
    if not ips:
        raise ScopeViolation(f"No addresses resolved for {host!r}")
    for ip in ips:
        if _address_forbidden(ip, policy.allow_private_targets):
            raise ScopeViolation(
                f"Resolved address {ip} for {host!r} is private/link-local/loopback/metadata; "
                f"scanning it requires an explicitly approved isolated lab (ALLOW_PRIVATE_TARGETS)"
            )
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return ResolvedTarget(url=url, scheme=parts.scheme, host=host, port=port,
                          path=parts.path or "/", resolved_ips=ips)


def validate_redirect(current_url: str, location: str, policy: ScopePolicy) -> ResolvedTarget:
    """Validate a redirect target against scope (protects against redirect scope escape)."""
    from urllib.parse import urljoin
    target = urljoin(current_url, location)
    t = urlsplit(target)
    if t.scheme not in ("http", "https"):
        raise ScopeViolation(f"Redirect to non-HTTP scheme blocked: {target!r}")
    return validate_url(target, policy)


def validate_scope_policy(policy: ScopePolicy) -> None:
    """Validate a policy itself (used when a scan is created)."""
    if not policy.base_url:
        raise ScopeViolation("A target base URL is required")
    validate_url(policy.base_url, policy)