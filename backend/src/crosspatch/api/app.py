"""FastAPI application factory for the CrossPatch control plane."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import AbstractAsyncContextManager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from crosspatch.api.dependencies import (
    ControlService,
    PublicCaseReader,
    PublicCasesUnavailable,
    TokenAuthenticator,
)
from crosspatch.api.routes import events, evidence, exports, incidents, public_cases, warrants
from crosspatch.api.routes.events import SSEConnectionLimiter
from crosspatch.runtime.authority import WarrantDecisionConflict
from crosspatch.runtime.live_trials import (
    LiveTrialBudgetExceeded,
    LiveTrialDenied,
    LiveTrialRateLimited,
)


class RequestSizeLimitMiddleware:
    """Bound and replay request bytes before any parser or endpoint sees them."""

    def __init__(self, app: ASGIApp, maximum: int) -> None:
        self.app = app
        self.maximum = maximum

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        content_length = _content_length(scope)
        if content_length is None:
            await _json_error(
                scope, receive, send, status.HTTP_400_BAD_REQUEST, "invalid content length"
            )
            return
        if content_length > self.maximum:
            await _json_error(
                scope,
                receive,
                send,
                status.HTTP_413_CONTENT_TOO_LARGE,
                "request too large",
            )
            return

        messages: list[Message] = []
        received = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            received += len(message.get("body", b""))
            if received > self.maximum:
                await _json_error(
                    scope,
                    receive,
                    send,
                    status.HTTP_413_CONTENT_TOO_LARGE,
                    "request too large",
                )
                return
            if not message.get("more_body", False):
                break

        async def replay() -> Message:
            if messages:
                return messages.pop(0)
            return await receive()

        await self.app(scope, replay, send)


def _content_length(scope: Scope) -> int | None:
    values = [value for key, value in scope.get("headers", ()) if key.lower() == b"content-length"]
    if not values:
        return 0
    if len(values) != 1:
        return None
    try:
        value = int(values[0])
    except ValueError:
        return None
    return value if value >= 0 else None


async def _json_error(
    scope: Scope,
    receive: Receive,
    send: Send,
    status_code: int,
    detail: str,
) -> None:
    response = JSONResponse(status_code=status_code, content={"detail": detail})
    await response(scope, receive, send)


def create_app(
    *,
    service: ControlService,
    authenticator: TokenAuthenticator,
    allowed_origins: Sequence[str],
    public_case_reader: PublicCaseReader | None = None,
    max_request_bytes: int = 1_048_576,
    max_sse_event_bytes: int = 65_536,
    max_sse_connections_per_subject: int = 3,
    lifespan: Callable[[FastAPI], AbstractAsyncContextManager[Any]] | None = None,
) -> FastAPI:
    origins = tuple(allowed_origins)
    if not origins or "*" in origins:
        raise ValueError("explicit CORS origins are required; wildcard origins are forbidden")
    if any(
        not origin.startswith(("https://", "http://localhost", "http://127.0.0.1"))
        for origin in origins
    ):
        raise ValueError("CORS origins must use HTTPS except loopback development")
    if max_request_bytes < 1 or max_sse_event_bytes < 256:
        raise ValueError("request and SSE payload limits must be positive")

    app = FastAPI(
        title="CrossPatch Control API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.control_service = service
    app.state.authenticator = authenticator
    app.state.public_case_reader = public_case_reader
    app.state.allowed_origins = frozenset(origins)
    app.state.max_request_bytes = max_request_bytes
    app.state.max_sse_event_bytes = max_sse_event_bytes
    app.state.sse_limiter = SSEConnectionLimiter(max_sse_connections_per_subject)

    @app.exception_handler(WarrantDecisionConflict)
    async def warrant_conflict(
        _request: Request,
        error: WarrantDecisionConflict,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": str(error), "code": error.code},
        )

    @app.exception_handler(LiveTrialDenied)
    async def live_trial_denied(
        _request: Request,
        error: LiveTrialDenied,
    ) -> JSONResponse:
        limited = isinstance(
            error,
            (LiveTrialBudgetExceeded, LiveTrialRateLimited),
        )
        code = (
            "LIVE_TRIAL_GLOBAL_BUDGET_EXHAUSTED"
            if isinstance(error, LiveTrialBudgetExceeded)
            else "LIVE_TRIAL_RATE_LIMITED"
            if isinstance(error, LiveTrialRateLimited)
            else "LIVE_TRIAL_DENIED"
        )
        return JSONResponse(
            status_code=(
                status.HTTP_429_TOO_MANY_REQUESTS
                if limited
                else status.HTTP_403_FORBIDDEN
            ),
            content={"detail": str(error), "code": code},
        )

    @app.exception_handler(PublicCasesUnavailable)
    async def public_cases_unavailable(
        _request: Request,
        _error: PublicCasesUnavailable,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "detail": "published cases unavailable",
                "code": "PUBLIC_CASES_UNAVAILABLE",
            },
        )

    app.add_middleware(RequestSizeLimitMiddleware, maximum=max_request_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Last-Event-ID",
            "X-CSRF-Token",
            "X-CrossPatch-Step-Up",
        ],
        expose_headers=["Content-Disposition"],
        max_age=600,
    )

    async def health_response() -> JSONResponse:
        health = getattr(service, "health", None)
        if health is None:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unavailable"},
            )
        try:
            payload = await health()
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unavailable"},
            )
        return JSONResponse(status_code=status.HTTP_200_OK, content=payload)

    app.add_api_route(
        "/healthz",
        health_response,
        methods=["GET"],
        include_in_schema=False,
    )
    app.add_api_route(
        "/api/health",
        health_response,
        methods=["GET"],
        tags=["health"],
    )

    app.include_router(incidents.router)
    app.include_router(evidence.router)
    app.include_router(events.router)
    app.include_router(warrants.router)
    app.include_router(exports.router)
    app.include_router(public_cases.router)
    return app
