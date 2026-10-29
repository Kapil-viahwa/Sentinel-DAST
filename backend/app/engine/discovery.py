"""JavaScript route/API endpoint discovery and query-parameter extraction."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

# fetch()/axios/XHR-style endpoint literals in served JavaScript.
_JS_ENDPOINT_PATTERNS = [
    re.compile(r"""(?:fetch|axios(?:\.\w+)?|\$\.(?:get|post|ajax))\(\s*["'`](/[^"'`\s]{1,200})["'`]"""),
    re.compile(r"""["'`](/(?:api|v[0-9]+|graphql|rest)[^"'`\s]{0,180})["'`]"""),
    re.compile(r"""url\s*:\s*["'`](/[^"'`\s]{1,200})["'`]"""),
]

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def extract_js_endpoints(script_text: str) -> list[str]:
    found: set[str] = set()
    for pattern in _JS_ENDPOINT_PATTERNS:
        for match in pattern.finditer(script_text or ""):
            path = match.group(1).split("?")[0]
            if path and len(path) > 1:
                found.add(path)
    return sorted(found)[:200]


def extract_query_params(url: str) -> list[dict]:
    try:
        qs = urlsplit(url).query
    except Exception:
        return []
    return [{"name": k, "source": "query", "type": "string"} for k, _ in parse_qsl(qs, keep_blank_values=True)]


def normalize_path(path: str) -> str:
    """Collapse numeric/UUID path segments so dedup keys group the same resource shape."""
    p = UUID_RE.sub("{uuid}", path)
    p = re.sub(r"/\d+(?=/|$)", "/{id}", p)
    return p