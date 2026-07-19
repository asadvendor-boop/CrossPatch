"""Authenticated HTTP/SSE client used by every CLI command."""

from __future__ import annotations

import json
import ssl
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from crosspatch.url_policy import validated_control_url


class CrossPatchClientError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class StreamEvent:
    id: str
    event: str
    data: dict[str, Any]


class CrossPatchClient:
    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        origin: str,
        csrf_token: str | None = None,
        step_up_token: str | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        verify: bool | ssl.SSLContext | None = None,
    ) -> None:
        base_url = validated_control_url(base_url)
        if not token:
            raise ValueError("CROSSPATCH_TOKEN is required")
        if not origin:
            raise ValueError("CROSSPATCH_ORIGIN is required")
        self._origin = origin.rstrip("/")
        self._csrf_token = csrf_token
        self._step_up_token = step_up_token
        parsed = urlparse(base_url)
        local_https = parsed.scheme == "https" and parsed.hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }
        tls_verification = not local_https if verify is None else verify
        self._http = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            transport=transport,
            verify=tls_verification,
        )

    def close(self) -> None:
        self._http.close()

    def open_incident(self, scenario: str) -> dict[str, Any]:
        return self._json("POST", "/api/incidents", json={"scenario": scenario})

    def get_warrant(self, warrant_id: str) -> dict[str, Any]:
        return self._json("GET", f"/api/warrants/{warrant_id}")

    def approve_warrant(self, warrant_id: str, warrant_sha256: str) -> dict[str, Any]:
        return self._json(
            "POST",
            f"/api/warrants/{warrant_id}/approve",
            json={"confirmation": "APPROVE", "warrant_sha256": warrant_sha256},
            headers=self._approval_headers(),
        )

    def reject_warrant(self, warrant_id: str, warrant_sha256: str) -> dict[str, Any]:
        return self._json(
            "POST",
            f"/api/warrants/{warrant_id}/reject",
            json={"confirmation": "REJECT", "warrant_sha256": warrant_sha256},
            headers=self._approval_headers(),
        )

    def export_case(self, incident_id: str) -> bytes:
        response = self._http.get(f"/api/incidents/{incident_id}/export")
        self._raise_for_status(response)
        return response.content

    def rotate_judge_token(self, incident_id: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"confirmation": "ROTATE"}
        if incident_id is not None:
            body["incident_id"] = incident_id
        return self._json(
            "POST",
            "/api/judge-tokens/rotate",
            json=body,
            headers=self._approval_headers(),
        )

    def list_judge_tokens(self) -> dict[str, Any]:
        return self._json("GET", "/api/judge-tokens")

    def revoke_judge_token(self, token_id: str) -> dict[str, Any]:
        return self._json(
            "POST",
            f"/api/judge-tokens/{token_id}/revoke",
            json={"confirmation": "REVOKE"},
            headers=self._approval_headers(),
        )

    def stream_room(
        self, incident_id: str, last_event_id: str | None = None
    ) -> Iterator[StreamEvent]:
        headers: dict[str, str] = {"Accept": "text/event-stream"}
        if last_event_id is not None:
            headers["Last-Event-ID"] = last_event_id
        with self._http.stream(
            "GET", f"/api/incidents/{incident_id}/events/stream", headers=headers
        ) as response:
            self._raise_for_status(response)
            current: dict[str, str] = {}
            data_lines: list[str] = []
            for line in response.iter_lines():
                if line == "":
                    if current or data_lines:
                        yield _stream_event(current, data_lines)
                    current = {}
                    data_lines = []
                    continue
                if line.startswith(":") or ":" not in line:
                    continue
                key, value = line.split(":", 1)
                value = value.lstrip(" ")
                if key == "data":
                    data_lines.append(value)
                elif key in {"id", "event"}:
                    current[key] = value
            if current or data_lines:
                yield _stream_event(current, data_lines)

    def _approval_headers(self) -> dict[str, str]:
        if not self._csrf_token or not self._step_up_token:
            raise CrossPatchClientError(
                "CROSSPATCH_CSRF_TOKEN and CROSSPATCH_STEP_UP_TOKEN are required"
            )
        return {
            "Origin": self._origin,
            "X-CSRF-Token": self._csrf_token,
            "X-CrossPatch-Step-Up": self._step_up_token,
        }

    def _json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = self._http.request(method, path, **kwargs)
        self._raise_for_status(response)
        value = response.json()
        if not isinstance(value, dict):
            raise CrossPatchClientError("CrossPatch API returned an invalid JSON object")
        return value

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.is_success:
            return
        try:
            body = response.json()
            detail = body.get("detail") if isinstance(body, dict) else None
        except (ValueError, json.JSONDecodeError):
            detail = None
        message = detail if isinstance(detail, str) and len(detail) <= 240 else "request failed"
        raise CrossPatchClientError(f"CrossPatch API {response.status_code}: {message}")


def _stream_event(fields: dict[str, str], data_lines: list[str]) -> StreamEvent:
    try:
        parsed = json.loads("\n".join(data_lines))
    except json.JSONDecodeError as error:
        raise CrossPatchClientError("CrossPatch SSE returned invalid JSON") from error
    if not isinstance(parsed, dict):
        raise CrossPatchClientError("CrossPatch SSE data must be an object")
    return StreamEvent(
        id=fields.get("id", ""),
        event=fields.get("event", "message"),
        data=parsed,
    )
