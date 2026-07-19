#!/usr/bin/env python3
"""Black-box acceptance check for the authority-free recorded replay profile."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

INCIDENT_ID = "inc_e032c6cde04f44b8a5dc6371c8c6f690"
BANNER = "RECORDED REPLAY — signed export, no model calls"
LIVE_ONLY_PATHS = (
    "/overview",
    "/overview/",
    "/open-incident",
    "/open-incident/",
    "/approvals",
    "/approvals/",
    "/artifacts",
    "/artifacts/",
    "/incidents",
    "/incidents/",
    "/incidents/inc-live-only",
)
FORBIDDEN_ENDPOINTS = (
    ("POST", "/api/incidents"),
    ("POST", "/api/warrants/replay/approve"),
    ("GET", "/api/incidents/replay/export"),
    ("GET", "/mcp/judge"),
)


class ReplayVerificationError(RuntimeError):
    """The running replay does not enforce its recorded-only boundary."""


@dataclass(frozen=True, slots=True)
class HTTPResult:
    status: int
    headers: dict[str, str]
    body: bytes


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _fetch(base_url: str, method: str, path: str) -> HTTPResult:
    request = Request(f"{base_url}{path}", method=method)
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=8) as response:
            return HTTPResult(
                status=response.status,
                headers={key.casefold(): value for key, value in response.headers.items()},
                body=response.read(2_000_001),
            )
    except HTTPError as error:
        return HTTPResult(
            status=error.code,
            headers={key.casefold(): value for key, value in error.headers.items()},
            body=error.read(2_000_001),
        )
    except URLError as error:
        raise ReplayVerificationError(f"replay endpoint unavailable: {path}") from error


def _json_object(response: HTTPResult, *, label: str) -> dict[str, Any]:
    if response.status != 200:
        raise ReplayVerificationError(f"{label} returned HTTP {response.status}")
    try:
        value = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReplayVerificationError(f"{label} returned malformed JSON") from error
    if not isinstance(value, dict):
        raise ReplayVerificationError(f"{label} did not return an object")
    return value


def _contains_key(value: Any, forbidden: str) -> bool:
    if isinstance(value, dict):
        return forbidden in value or any(_contains_key(item, forbidden) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, forbidden) for item in value)
    return False


def verify_replay(
    base_url: str,
    *,
    request: Callable[[str, str], HTTPResult] | None = None,
) -> dict[str, Any]:
    base_url = base_url.rstrip("/")
    fetch = request or (lambda method, path: _fetch(base_url, method, path))

    health = _json_object(fetch("GET", "/healthz"), label="replay health")
    if health != {
        "status": "ok",
        "mode": "recorded-replay",
        "model_calls": "disabled",
        "mutation": "disabled",
    }:
        raise ReplayVerificationError("replay health does not prove disabled authority")

    index = _json_object(fetch("GET", "/api/public/cases"), label="public case index")
    cases = index.get("cases")
    if not isinstance(cases, list) or [case.get("incident_id") for case in cases] != [INCIDENT_ID]:
        raise ReplayVerificationError("public case index is not the pinned one-case replay")

    detail = _json_object(
        fetch("GET", f"/api/public/cases/{INCIDENT_ID}"),
        label="public case detail",
    )
    projection = detail.get("projection")
    if not isinstance(projection, dict):
        raise ReplayVerificationError("public case detail has no projection")
    incident = projection.get("incident")
    events = projection.get("events")
    warrants = projection.get("warrants")
    if (
        not isinstance(incident, dict)
        or incident.get("state") != "VERIFIED"
        or not isinstance(events, list)
        or len(events) != 58
        or not isinstance(warrants, list)
        or len(warrants) != 1
        or _contains_key(projection, "raw_evidence")
    ):
        raise ReplayVerificationError("public case detail is not the complete sanitized record")

    root = fetch("GET", "/")
    if root.status != 302 or root.headers.get("location") != "/cases":
        raise ReplayVerificationError("root redirect does not resolve to the replay gallery")

    for path in LIVE_ONLY_PATHS:
        response = fetch("GET", path)
        if response.status != 302 or response.headers.get("location") != "/cases":
            raise ReplayVerificationError(f"live-only route remained reachable: {path}")
        if any(token in response.body for token in (b"IncidentOpenForm", b"IncidentAccessForm")):
            raise ReplayVerificationError(f"live-only route leaked a component payload: {path}")

    for method, path in FORBIDDEN_ENDPOINTS:
        response = fetch(method, path)
        if response.status != 404:
            raise ReplayVerificationError(f"forbidden endpoint remained reachable: {method} {path}")

    gallery = fetch("GET", "/cases")
    if gallery.status != 200 or BANNER.encode("utf-8") not in gallery.body:
        raise ReplayVerificationError("recorded replay banner is absent from the gallery")

    return {"incident_id": INCIDENT_ID, "event_count": len(events), "status": "PASS"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    arguments = parser.parse_args()
    try:
        report = verify_replay(arguments.base_url)
    except ReplayVerificationError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1) from error
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
