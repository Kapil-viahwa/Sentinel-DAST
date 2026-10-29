"""Finding correlation and deduplication.

Duplicates are grouped by root cause (vulnerability class + module + host +
normalized path + method + parameter) so repeated evidence updates a single
finding without merging distinct root causes on other resources.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _normalized_path(url: str) -> str:
    path = urlsplit(url).path or "/"
    path = _UUID_RE.sub("/{uuid}", path)
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    return path


def finding_key(owasp_category: str, module_id: str, url: str, method: str, parameter: str | None) -> str:
    parts = urlsplit(url)
    raw = "|".join([
        owasp_category,
        module_id,
        parts.netloc.lower(),
        method.upper(),
        _normalized_path(url),
        parameter or "",
    ])
    return hashlib.sha256(raw.encode()).hexdigest()


_SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def should_upgrade_severity(existing: str, new: str) -> bool:
    return _SEVERITY_RANK.get(new, 0) > _SEVERITY_RANK.get(existing, 0)