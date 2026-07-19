#!/usr/bin/env python3
"""Open and observe the shipped webhook race through public control-plane APIs."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

ROOT = Path(__file__).resolve().parents[1]
LOCAL_COMPOSE_OPERATOR_TOKEN = "crosspatch-local-operator-token-change-me"
TERMINAL_OR_GATE_STATES = {
    "APPROVAL_PENDING",
    "BLOCKED",
    "HUMAN_ESCALATION",
    "TEST_FAILED",
    "VERIFIED",
}


def token_value(*, local: bool) -> str:
    configured = (
        os.environ.get("CROSSPATCH_OPERATOR_TOKEN", "").strip()
        or os.environ.get("CROSSPATCH_TOKEN", "").strip()
    )
    if configured:
        return configured
    if local:
        return LOCAL_COMPOSE_OPERATOR_TOKEN
    path = ROOT / ".crosspatch" / "secrets" / "operator-token"
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        value = ""
    if not value:
        raise RuntimeError(
            "CROSSPATCH_OPERATOR_TOKEN is required for non-loopback deployments"
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url", default=os.environ.get("CROSSPATCH_PUBLIC_URL", "https://localhost")
    )
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--no-wait", action="store_true")
    arguments = parser.parse_args()
    parsed = urlparse(arguments.url)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    verify: bool = not local
    headers = {"Authorization": f"Bearer {token_value(local=local)}"}

    with httpx.Client(
        base_url=arguments.url.rstrip("/"),
        headers=headers,
        verify=verify,
        timeout=30,
        follow_redirects=False,
    ) as client:
        response = client.post(
            "/api/incidents",
            json={"scenario": "webhook-race", "title": "Duplicate order-paid delivery"},
        )
        response.raise_for_status()
        incident = response.json()
        incident_id = incident.get("id")
        if not isinstance(incident_id, str) or not incident_id:
            raise RuntimeError("control API did not return an incident identifier")
        print(json.dumps({"incident": incident, "source": "control-api"}, sort_keys=True))
        if arguments.no_wait:
            return 0

        deadline = time.monotonic() + arguments.timeout
        last_state: str | None = None
        while time.monotonic() < deadline:
            room = client.get(f"/api/incidents/{incident_id}/room")
            room.raise_for_status()
            payload = room.json()
            state = payload.get("incident", {}).get("state")
            if isinstance(state, str) and state != last_state:
                print(json.dumps({"incident_id": incident_id, "state": state}, sort_keys=True))
                last_state = state
            if state in TERMINAL_OR_GATE_STATES:
                print(json.dumps(payload, indent=2, sort_keys=True))
                return 0
            time.sleep(1)
    raise TimeoutError(f"incident {incident_id} did not reach an observable gate in time")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, TimeoutError, httpx.HTTPError) as error:
        print(f"sample incident failed: {error}", file=sys.stderr)
        sys.exit(1)
