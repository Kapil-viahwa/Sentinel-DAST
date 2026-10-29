"""OWASP ZAP integration adapter — UNCONFIGURED / NOT IMPLEMENTED.

This module defines the adapter surface for integrating OWASP ZAP through its
supported API. It is intentionally NOT functional: no ZAP calls are made, and no
ZAP capability is reported as available anywhere in the product until this
integration is implemented and tested against a live ZAP instance.

To enable later work: configure ZAP_API_URL / ZAP_API_KEY environment variables
and implement the adapter methods; `status()` then flips to a truthful state and
the UI picks it up via the integrations status endpoint.
"""
from __future__ import annotations

import os


class ZapAdapter:
    """External-engine adapter surface. See docs/IMPLEMENTATION_STATUS.md."""

    def __init__(self, api_url: str | None = None, api_key: str | None = None):
        self.api_url = api_url
        self.api_key = api_key

    @classmethod
    def from_env(cls) -> "ZapAdapter":
        return cls(os.getenv("ZAP_API_URL"), os.getenv("ZAP_API_KEY"))

    @property
    def configured(self) -> bool:
        return bool(self.api_url)

    def status(self) -> dict:
        if not self.configured:
            return {
                "engine": "owasp-zap",
                "available": False,
                "state": "unconfigured",
                "reason": "ZAP_API_URL is not set; the adapter is defined but the "
                          "integration has not been implemented or tested. "
                          "Scans use the sentinel-native engine only.",
            }
        return {
            "engine": "owasp-zap",
            "available": False,
            "state": "not_implemented",
            "reason": "Configuration is present but the ZAP integration is not yet "
                      "implemented. No ZAP capabilities are offered.",
        }

    # --- adapter surface to be implemented -----------------------------------
    def start_spider(self, target: str) -> None:  # pragma: no cover
        raise NotImplementedError("ZAP integration is not implemented")

    def start_active_scan(self, target: str) -> None:  # pragma: no cover
        raise NotImplementedError("ZAP integration is not implemented")

    def poll_alerts(self) -> list:  # pragma: no cover
        raise NotImplementedError("ZAP integration is not implemented")