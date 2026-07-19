"""FastAPI entry point for the signed order-paid webhook."""

from __future__ import annotations

import os

from crosspatch.runner.secrets import (
    INSECURE_VICTIM_DATABASE_PASSWORD,
    INSECURE_VICTIM_WEBHOOK_SECRET,
    validate_release_database_url,
    validate_release_secret,
)
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from victim.db import Database, IngestDisposition
from victim.signing import SIGNATURE_HEADER, verify_signature
from victim.webhooks import ingest


def create_app(*, database: Database | None = None, signing_secret: str | None = None) -> FastAPI:
    environment = dict(os.environ)
    resolved_database = database
    if resolved_database is None:
        dsn = os.environ.get("VICTIM_DATABASE_URL")
        if not dsn:
            raise RuntimeError("VICTIM_DATABASE_URL is required")
        validate_release_database_url(
            environment,
            dsn,
            label="victim database",
            insecure_passwords={INSECURE_VICTIM_DATABASE_PASSWORD},
        )
        resolved_database = Database(dsn)
    resolved_secret = signing_secret or os.environ.get("VICTIM_WEBHOOK_SECRET")
    if not resolved_secret:
        raise RuntimeError("VICTIM_WEBHOOK_SECRET is required")
    validate_release_secret(
        environment,
        resolved_secret,
        label="victim webhook secret",
        insecure_values={INSECURE_VICTIM_WEBHOOK_SECRET},
    )

    application = FastAPI(title="CrossPatch webhook victim", docs_url=None, redoc_url=None)

    @application.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.post("/webhooks/order-paid")
    async def order_paid(request: Request) -> JSONResponse:
        body = await request.body()
        supplied = request.headers.get(SIGNATURE_HEADER, "")
        if not verify_signature(body, supplied, resolved_secret):
            raise HTTPException(status_code=401, detail="invalid webhook signature")
        try:
            disposition = await run_in_threadpool(ingest, resolved_database, body)
        except ValidationError as error:
            raise HTTPException(status_code=422, detail="invalid webhook payload") from error
        if disposition is IngestDisposition.PAYLOAD_MISMATCH:
            raise HTTPException(status_code=409, detail="event id reused with different payload")
        if disposition is IngestDisposition.DUPLICATE:
            return JSONResponse(status_code=200, content={"status": "duplicate"})
        return JSONResponse(status_code=202, content={"status": "accepted"})

    return application
