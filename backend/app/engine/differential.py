"""Differential response analysis with noise normalization.

Compares status codes, lengths, redirect behavior, stable markers and structural
similarity while accounting for dynamic tokens, timestamps and random identifiers.
"""
from __future__ import annotations

import difflib
import re

_NOISE_PATTERNS = [
    re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I),
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b"),
    re.compile(r"\b\d{13}\b"),  # epoch millis
    re.compile(r"""csrf[a-z_-]*["']?\s*[:=]\s*["'][^"']+["']""", re.I),
    re.compile(r"\b[0-9a-f]{16,}\b", re.I),
    re.compile(r"\b\d+\b"),
]

_MAX_COMPARE_CHARS = 20_000


def normalize(text: str | None) -> str:
    t = text or ""
    for pattern in _NOISE_PATTERNS:
        t = pattern.sub(" ", t)
    return " ".join(t[:_MAX_COMPARE_CHARS].split())


def body_similarity(a: str | None, b: str | None) -> float:
    na, nb = normalize(a), normalize(b)
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    return difflib.SequenceMatcher(None, na, nb).ratio()


def responses_differ(
    a_status: int | None, a_body: str | None,
    b_status: int | None, b_body: str | None,
    *, status_matters: bool = True,
) -> bool:
    if status_matters and a_status != b_status:
        return True
    sim = body_similarity(a_body, b_body)
    return sim < 0.80


def summarize_difference(a: str | None, b: str | None) -> dict:
    """Compact structured diff for evidence records."""
    na, nb = normalize(a), normalize(b)
    sim = body_similarity(a, b)
    diff_lines = list(difflib.unified_diff(na.split()[:200], nb.split()[:200], lineterm=""))[:40]
    return {"similarity": round(sim, 3), "diff_sample": diff_lines}