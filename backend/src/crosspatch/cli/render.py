"""Stable human-readable rendering helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping

from crosspatch.cli.client import StreamEvent


def render_json(value: Mapping[str, object]) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def render_event(value: StreamEvent) -> str:
    summary = value.data.get("summary", "")
    return f"{value.id} {value.event} {summary}".rstrip()


def render_warrant(value: Mapping[str, object]) -> str:
    canonical = value.get("canonical_document")
    digest = value.get("warrant_sha256")
    if not isinstance(canonical, str) or not isinstance(digest, str):
        raise ValueError("warrant response omitted canonical document or hash")
    actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual, digest):
        raise ValueError("canonical warrant document hash mismatch")
    return canonical
