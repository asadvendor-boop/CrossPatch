"""Fail-closed display and publication policy for public incident titles."""

from __future__ import annotations

import re

from crosspatch.evidence.sanitizer import sanitize_evidence

_INTERNAL_RUN_PATTERNS = (
    re.compile(r"\bfresh[-\s]+output\b", re.IGNORECASE),
    re.compile(r"\brelease\s+evaluation\b", re.IGNORECASE),
    re.compile(r"\b(?:qa\s+)?(?:run|evaluation)\s*(?:#|no\.?\s*)?\d+\b", re.IGNORECASE),
)
_SCENARIO_TITLES = {
    "webhook-race": "Duplicate order-paid delivery",
    "webhook-worker": "Duplicate order-paid delivery",
}


def public_title_issues(title: str) -> tuple[str, ...]:
    """Return stable policy codes without reflecting an untrusted title."""
    if not isinstance(title, str) or not title.strip():
        return ("SANITIZER_REJECTED",)
    sanitized = sanitize_evidence(title.encode("utf-8"), "incident title")
    issues: set[str] = set()
    if (
        sanitized.text != title
        or sanitized.tags
        or sanitized.provenance_tags
        or sanitized.truncated
    ):
        issues.add("SANITIZER_REJECTED")
    if any(pattern.search(title) for pattern in _INTERNAL_RUN_PATTERNS):
        issues.add("INTERNAL_RUN_VOCABULARY")
    return tuple(sorted(issues))


def _scenario_title(scenario: str) -> str:
    mapped = _SCENARIO_TITLES.get(scenario.lower())
    if mapped is not None:
        return mapped
    words = re.sub(r"[^A-Za-z0-9]+", " ", scenario).strip().lower()
    if not words:
        return "Recorded incident"
    return f"{words.capitalize()} incident"[:240]


def public_display_title(title: str, scenario: str) -> str:
    """Return the recorded title when safe, otherwise a scenario-derived label."""
    return title if not public_title_issues(title) else _scenario_title(scenario)


def require_publishable_title(title: str) -> str:
    """Reject unsafe/internal titles before a new projection becomes public."""
    if public_title_issues(title):
        raise ValueError("public incident title policy rejected the recorded title")
    return title


__all__ = ["public_display_title", "public_title_issues", "require_publishable_title"]
