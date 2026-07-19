from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest
from crosspatch.api.app import create_app
from crosspatch.api.dependencies import Principal, Role, StaticTokenAuthenticator
from crosspatch.api.models import PublishedEvent


class StreamingService:
    def __init__(self, events: tuple[PublishedEvent, ...]) -> None:
        self.events = events
        self.stream_calls: list[tuple[str, int]] = []

    async def list_events(self, incident_id: str, *, after: int, limit: int):
        return tuple(event for event in self.events if event.sequence > after)[:limit]

    async def stream_events(self, incident_id: str, *, after: int) -> AsyncIterator[PublishedEvent]:
        self.stream_calls.append((incident_id, after))
        for event in self.events:
            if event.sequence > after:
                yield event


def _event(
    sequence: int,
    *,
    incident_id: str = "inc-a",
    summary: str | None = None,
    published: bool = True,
) -> PublishedEvent:
    return PublishedEvent(
        id=f"evt-{sequence}",
        incident_id=incident_id,
        sequence=sequence,
        type="TEST_EVENT",
        actor="runner",
        summary=summary or f"Event {sequence}",
        details={"result": "sanitized"},
        event_hash=f"{sequence:064x}",
        created_at=datetime(2026, 7, 14, sequence, tzinfo=UTC),
        published=published,
    )


def _auth() -> StaticTokenAuthenticator:
    return StaticTokenAuthenticator(
        {
            "read-a": Principal(
                subject="reader-a",
                role=Role.READ_ONLY,
                incident_ids=frozenset({"inc-a"}),
                expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            )
        }
    )


def _parse_sse(body: str) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    for block in body.strip().split("\n\n"):
        parsed: dict[str, str] = {}
        for line in block.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                parsed[key] = value.lstrip()
        if parsed:
            events.append(parsed)
    return events


@pytest.mark.asyncio
async def test_sse_replays_after_last_event_id() -> None:
    service = StreamingService(tuple(_event(index) for index in range(1, 6)))
    app = create_app(
        service=service,
        authenticator=_auth(),
        allowed_origins=("https://crosspatch.test",),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/incidents/inc-a/events/stream?limit=2",
            headers={"Authorization": "Bearer read-a", "Last-Event-ID": "3"},
        )

    assert response.status_code == 200
    parsed = _parse_sse(response.text)
    assert [event["id"] for event in parsed] == ["4", "5"]
    assert service.stream_calls == [("inc-a", 3)]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-accel-buffering"] == "no"


@pytest.mark.asyncio
async def test_sse_authorizes_incident_before_replay() -> None:
    service = StreamingService((_event(1, incident_id="inc-b", summary="B-UNIQUE-SENTINEL"),))
    app = create_app(
        service=service,
        authenticator=_auth(),
        allowed_origins=("https://crosspatch.test",),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/incidents/inc-b/events/stream",
            headers={"Authorization": "Bearer read-a"},
        )

    assert response.status_code == 404
    assert service.stream_calls == []
    assert "B-UNIQUE-SENTINEL" not in response.text


@pytest.mark.asyncio
async def test_sse_drops_cross_incident_unpublished_and_oversized_events() -> None:
    # The public DTO cap is 16 KiB; this still exceeds the route's tighter 4 KiB cap.
    huge = "X" * 8_000
    service = StreamingService(
        (
            _event(1),
            _event(2, incident_id="inc-b", summary="B-UNIQUE-SENTINEL"),
            _event(3, summary="UNPUBLISHED-SENTINEL", published=False),
            _event(4, summary=huge),
            _event(5, summary="must-not-continue-after-invalid-event"),
        )
    )
    app = create_app(
        service=service,
        authenticator=_auth(),
        allowed_origins=("https://crosspatch.test",),
        max_sse_event_bytes=4096,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/incidents/inc-a/events/stream",
            headers={"Authorization": "Bearer read-a"},
        )

    assert [event["id"] for event in _parse_sse(response.text)] == ["1"]
    assert "B-UNIQUE-SENTINEL" not in response.text
    assert "UNPUBLISHED-SENTINEL" not in response.text
    assert "must-not-continue" not in response.text


@pytest.mark.asyncio
async def test_rest_replay_drops_cross_incident_and_unpublished_events() -> None:
    service = StreamingService(
        (
            _event(1),
            _event(2, incident_id="inc-b", summary="B-UNIQUE-SENTINEL"),
            _event(3, summary="UNPUBLISHED-SENTINEL", published=False),
        )
    )
    app = create_app(
        service=service,
        authenticator=_auth(),
        allowed_origins=("https://crosspatch.test",),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/incidents/inc-a/events",
            headers={"Authorization": "Bearer read-a"},
        )

    assert response.status_code == 200
    assert [event["sequence"] for event in response.json()] == [1]
    assert "B-UNIQUE-SENTINEL" not in response.text
    assert "UNPUBLISHED-SENTINEL" not in response.text


class RevokingAuthenticator(StaticTokenAuthenticator):
    def __init__(self) -> None:
        super().__init__(
            {
                "read-a": Principal(
                    subject="reader-a",
                    role=Role.READ_ONLY,
                    incident_ids=frozenset({"inc-a"}),
                    expires_at=datetime(2099, 1, 1, tzinfo=UTC),
                )
            }
        )
        self.checks = 0

    async def revalidate(self, principal: Principal) -> bool:
        self.checks += 1
        # One check authenticates the request, one permits the first event.
        return self.checks <= 2


@pytest.mark.asyncio
async def test_sse_terminates_when_session_is_revoked() -> None:
    service = StreamingService((_event(1), _event(2, summary="revoked-leak")))
    app = create_app(
        service=service,
        authenticator=RevokingAuthenticator(),
        allowed_origins=("https://crosspatch.test",),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/incidents/inc-a/events/stream",
            headers={"Authorization": "Bearer read-a"},
        )

    assert [event["id"] for event in _parse_sse(response.text)] == ["1"]
    assert "revoked-leak" not in response.text
