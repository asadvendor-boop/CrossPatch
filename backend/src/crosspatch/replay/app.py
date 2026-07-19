"""Dedicated authority-free HTTP application for a sealed replay database."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.engine import make_url

from crosspatch.api.dependencies import PublicCasesUnavailable
from crosspatch.api.routes import public_cases
from crosspatch.runtime.database import RuntimeDatabase
from crosspatch.runtime.readers import DatabasePublishedCaseReader


def _read_only_database_url(value: str) -> str:
    try:
        parsed = make_url(value)
    except Exception as error:
        raise ValueError("replay requires a read-only SQLite database URL") from error
    query = {str(key): str(item).casefold() for key, item in parsed.query.items()}
    if (
        parsed.drivername != "sqlite+aiosqlite"
        or not str(parsed.database or "").startswith("file:")
        or query.get("mode") != "ro"
        or query.get("uri") != "true"
    ):
        raise ValueError("replay requires a read-only SQLite database URL")
    return value


def create_replay_app(*, database_url: str | None = None) -> FastAPI:
    if os.getenv("OPENAI_API_KEY", "").strip():
        raise ValueError("recorded replay refuses model credentials")
    configured_url = database_url or os.getenv("CROSSPATCH_REPLAY_DATABASE_URL", "")
    database = RuntimeDatabase(_read_only_database_url(configured_url))
    reader = DatabasePublishedCaseReader(database.store)
    app = FastAPI(
        title="CrossPatch Recorded Replay API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.public_case_reader = reader
    app.state.runtime_database = database

    @app.exception_handler(PublicCasesUnavailable)
    async def public_cases_unavailable(
        _request: Request,
        _error: PublicCasesUnavailable,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "detail": "recorded replay unavailable",
                "code": "RECORDED_REPLAY_UNAVAILABLE",
            },
        )

    @app.get("/healthz", include_in_schema=False)
    @app.get("/health", include_in_schema=False)
    async def health() -> JSONResponse:
        try:
            healthy = await database.health()
        except Exception:
            healthy = False
        return JSONResponse(
            status_code=200 if healthy else 503,
            content={
                "status": "ok" if healthy else "unavailable",
                "mode": "recorded-replay",
                "model_calls": "disabled",
                "mutation": "disabled",
            },
        )

    app.include_router(public_cases.router)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if not await database.health() or not await reader.list_public_cases():
            await database.close()
            raise RuntimeError("recorded replay database contains no verified public case")
        try:
            yield
        finally:
            await database.close()

    app.router.lifespan_context = lifespan
    return app
