"""Signed webhook parsing and business response mapping."""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field

from victim.db import Database, IngestDisposition, WebhookEvent


class OrderPaid(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    provider: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9-]+$")
    event_id: str = Field(min_length=1, max_length=160)
    order_id: str = Field(min_length=1, max_length=160)
    amount_cents: int = Field(ge=0)
    log_message: str | None = Field(default=None, min_length=1, max_length=500)


def ingest(database: Database, body: bytes) -> IngestDisposition:
    payload = OrderPaid.model_validate_json(body)
    return database.accept_vulnerable(
        WebhookEvent(
            provider=payload.provider,
            event_id=payload.event_id,
            payload=payload.model_dump(mode="json", exclude_none=True),
            payload_sha256=hashlib.sha256(body).hexdigest(),
        )
    )
