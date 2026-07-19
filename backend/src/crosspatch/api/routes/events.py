"""Bounded REST replay and server-sent timeline events."""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from crosspatch.api.dependencies import (
    ControlService,
    Principal,
    TokenAuthenticator,
    get_principal,
    get_service,
    require_incident_access,
)
from crosspatch.api.models import PublishedEvent

router = APIRouter(prefix="/api/incidents", tags=["timeline"])


class SSEConnectionLimiter:
    def __init__(self, maximum_per_subject: int) -> None:
        if maximum_per_subject < 1:
            raise ValueError("SSE connection limit must be positive")
        self._maximum = maximum_per_subject
        self._counts: defaultdict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def acquire(self, subject: str) -> bool:
        async with self._lock:
            if self._counts[subject] >= self._maximum:
                return False
            self._counts[subject] += 1
            return True

    async def release(self, subject: str) -> None:
        async with self._lock:
            if self._counts[subject] <= 1:
                self._counts.pop(subject, None)
            else:
                self._counts[subject] -= 1


def _public_events(
    values: object,
    *,
    incident_id: str,
    after: int,
) -> list[PublishedEvent]:
    if not isinstance(values, (list, tuple)):
        return []
    result: list[PublishedEvent] = []
    previous = after
    for event in values:
        if (
            not isinstance(event, PublishedEvent)
            or not event.published
            or event.incident_id != incident_id
            or event.sequence <= previous
        ):
            break
        result.append(event)
        previous = event.sequence
    return result


@router.get("/{incident_id}/events", response_model=list[PublishedEvent])
async def list_events(
    incident_id: str,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
) -> list[PublishedEvent]:
    require_incident_access(principal, incident_id)
    values = await service.list_events(incident_id, after=after, limit=limit)
    return _public_events(values, incident_id=incident_id, after=after)[:limit]


def _sse_bytes(event: PublishedEvent) -> bytes:
    public = event.model_dump(mode="json", exclude={"published"})
    payload = json.dumps(public, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"id: {event.sequence}\nevent: {event.type}\ndata: {payload}\n\n".encode()


@router.get("/{incident_id}/events/stream", response_class=StreamingResponse)
async def stream_events(
    request: Request,
    incident_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
) -> StreamingResponse:
    require_incident_access(principal, incident_id)
    if last_event_id is None:
        after = 0
    elif not last_event_id.isascii() or not last_event_id.isdecimal():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid Last-Event-ID")
    else:
        after = int(last_event_id)

    limiter: SSEConnectionLimiter = request.app.state.sse_limiter
    if not await limiter.acquire(principal.subject):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="stream limit")
    authenticator: TokenAuthenticator = request.app.state.authenticator
    maximum_bytes: int = request.app.state.max_sse_event_bytes

    async def generate():
        previous = after
        emitted = 0
        try:
            try:
                stream = service.stream_events(incident_id, after=after)
                async for event in stream:
                    if await request.is_disconnected():
                        break
                    if not await authenticator.revalidate(principal):
                        break
                    if (
                        not isinstance(event, PublishedEvent)
                        or not event.published
                        or event.incident_id != incident_id
                        or event.sequence <= previous
                    ):
                        break
                    encoded = _sse_bytes(event)
                    if len(encoded) > maximum_bytes:
                        break
                    yield encoded
                    previous = event.sequence
                    emitted += 1
                    if emitted >= limit:
                        break
            except Exception:
                # A stream failure is a termination signal, never model/evidence output.
                return
        finally:
            await limiter.release(principal.subject)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            "X-Content-Type-Options": "nosniff",
        },
    )
