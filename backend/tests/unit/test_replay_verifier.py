from __future__ import annotations

import json
from copy import deepcopy

import pytest

from scripts.verify_replay import (
    LIVE_ONLY_PATHS,
    HTTPResult,
    ReplayVerificationError,
    verify_replay,
)

INCIDENT_ID = "inc_e032c6cde04f44b8a5dc6371c8c6f690"


def _responses() -> dict[tuple[str, str], HTTPResult]:
    redirects = {
        path: HTTPResult(status=302, headers={"location": "/cases"}, body=b"")
        for path in ("/", *LIVE_ONLY_PATHS)
    }
    forbidden = {
        (method, path): HTTPResult(status=404, headers={}, body=b"not found")
        for method, path in (
            ("POST", "/api/incidents"),
            ("POST", "/api/warrants/replay/approve"),
            ("GET", "/api/incidents/replay/export"),
            ("GET", "/mcp/judge"),
        )
    }
    return {
        ("GET", "/healthz"): HTTPResult(
            status=200,
            headers={},
            body=(
                b'{"status":"ok","mode":"recorded-replay",'
                b'"model_calls":"disabled","mutation":"disabled"}'
            ),
        ),
        ("GET", "/api/public/cases"): HTTPResult(
            status=200,
            headers={},
            body=(f'{{"cases":[{{"incident_id":"{INCIDENT_ID}"}}]}}').encode(),
        ),
        ("GET", f"/api/public/cases/{INCIDENT_ID}"): HTTPResult(
            status=200,
            headers={},
            body=json.dumps(
                {
                    "incident_id": INCIDENT_ID,
                    "projection": {
                        "incident": {"state": "VERIFIED"},
                        "events": [],
                        "warrants": [{}],
                    },
                }
            ).encode(),
        ),
        ("GET", "/cases"): HTTPResult(
            status=200,
            headers={},
            body=b"<strong>RECORDED REPLAY \xe2\x80\x94 signed export, no model calls</strong>",
        ),
        **{("GET", path): response for path, response in redirects.items()},
        **forbidden,
    }


def _with_58_events(responses: dict[tuple[str, str], HTTPResult]) -> None:
    detail = responses[("GET", f"/api/public/cases/{INCIDENT_ID}")]
    responses[("GET", f"/api/public/cases/{INCIDENT_ID}")] = HTTPResult(
        status=detail.status,
        headers=detail.headers,
        body=json.dumps(
            {
                "incident_id": INCIDENT_ID,
                "projection": {
                    "incident": {"state": "VERIFIED"},
                    "events": [{} for _ in range(58)],
                    "warrants": [{}],
                },
            }
        ).encode(),
    )


def test_black_box_verifier_accepts_only_the_complete_recorded_boundary() -> None:
    responses = _responses()
    _with_58_events(responses)

    report = verify_replay(
        "http://replay.invalid",
        request=lambda method, path: responses[(method, path)],
    )

    assert report == {"incident_id": INCIDENT_ID, "event_count": 58, "status": "PASS"}


@pytest.mark.parametrize(
    ("method", "path", "replacement", "message"),
    (
        (
            "GET",
            "/",
            HTTPResult(status=200, headers={}, body=b""),
            "root redirect",
        ),
        (
            "GET",
            "/open-incident",
            HTTPResult(status=200, headers={}, body=b"IncidentOpenForm"),
            "live-only route",
        ),
        (
            "POST",
            "/api/incidents",
            HTTPResult(status=200, headers={}, body=b"{}"),
            "forbidden endpoint",
        ),
    ),
)
def test_black_box_verifier_fails_closed_on_route_regression(
    method: str,
    path: str,
    replacement: HTTPResult,
    message: str,
) -> None:
    responses = deepcopy(_responses())
    _with_58_events(responses)
    responses[(method, path)] = replacement

    with pytest.raises(ReplayVerificationError, match=message):
        verify_replay(
            "http://replay.invalid",
            request=lambda request_method, request_path: responses[
                (request_method, request_path)
            ],
        )
