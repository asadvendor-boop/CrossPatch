"""PostgreSQL persistence for the webhook victim.

`accept_vulnerable` intentionally contains the incident's check-then-insert race:
the outbox row is created before the receipt is published.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


class IngestDisposition(StrEnum):
    ACCEPTED = "ACCEPTED"
    DUPLICATE = "DUPLICATE"
    PAYLOAD_MISMATCH = "PAYLOAD_MISMATCH"


@dataclass(frozen=True, slots=True)
class WebhookEvent:
    provider: str
    event_id: str
    payload: dict[str, Any]
    payload_sha256: str


class Database:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    def connect(self, *, autocommit: bool = False):
        return psycopg.connect(self.dsn, autocommit=autocommit, row_factory=dict_row)

    def initialize(self) -> None:
        root = Path(__file__).parents[3]
        schema = (root / "infra/postgres/victim-init.sql").read_text(encoding="utf-8")
        with self.connect(autocommit=True) as connection:
            connection.execute(schema)

    def reset(self) -> None:
        with self.connect(autocommit=True) as connection:
            connection.execute(
                "TRUNCATE deliveries, outbox_jobs, webhook_receipts RESTART IDENTITY CASCADE"
            )

    def clear_event(self, provider: str, event_id: str) -> None:
        with self.connect() as connection, connection.transaction():
            connection.execute(
                "DELETE FROM deliveries WHERE provider = %s AND event_id = %s",
                (provider, event_id),
            )
            connection.execute(
                "DELETE FROM outbox_jobs WHERE provider = %s AND event_id = %s",
                (provider, event_id),
            )
            connection.execute(
                "DELETE FROM webhook_receipts WHERE provider = %s AND event_id = %s",
                (provider, event_id),
            )

    def accept_vulnerable(self, event: WebhookEvent) -> IngestDisposition:
        with self.connect() as connection, connection.transaction():
            existing = connection.execute(
                """
                SELECT payload_sha256
                  FROM webhook_receipts
                 WHERE provider = %s AND event_id = %s
                """,
                (event.provider, event.event_id),
            ).fetchone()
            if existing is not None:
                if existing["payload_sha256"].strip() != event.payload_sha256:
                    return IngestDisposition.PAYLOAD_MISMATCH
                return IngestDisposition.DUPLICATE

            # Deliberately vulnerable ordering: two transactions can both pass
            # the check and enqueue work before either publishes its receipt.
            connection.execute(
                """
                INSERT INTO outbox_jobs (provider, event_id, payload, payload_sha256)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    event.provider,
                    event.event_id,
                    Jsonb(event.payload),
                    event.payload_sha256,
                ),
            )
            connection.execute(
                """
                INSERT INTO webhook_receipts (provider, event_id, payload_sha256)
                VALUES (%s, %s, %s)
                ON CONFLICT (provider, event_id) DO NOTHING
                """,
                (event.provider, event.event_id, event.payload_sha256),
            )
            return IngestDisposition.ACCEPTED

    def counts(self, *, provider: str, event_id: str | None = None) -> dict[str, int]:
        if event_id is not None:
            parameters = (provider, event_id)
            receipts_query = (
                "SELECT count(*) AS count FROM webhook_receipts "
                "WHERE provider = %s AND event_id = %s"
            )
            jobs_query = (
                "SELECT count(*) AS count FROM outbox_jobs "
                "WHERE provider = %s AND event_id = %s"
            )
            deliveries_query = (
                "SELECT count(*) AS count FROM deliveries "
                "WHERE provider = %s AND event_id = %s"
            )
        else:
            parameters = (provider,)
            receipts_query = (
                "SELECT count(*) AS count FROM webhook_receipts WHERE provider = %s"
            )
            jobs_query = "SELECT count(*) AS count FROM outbox_jobs WHERE provider = %s"
            deliveries_query = (
                "SELECT count(*) AS count FROM deliveries WHERE provider = %s"
            )
        with self.connect(autocommit=True) as connection:
            return {
                "receipts": connection.execute(
                    receipts_query,
                    parameters,
                ).fetchone()["count"],
                "jobs": connection.execute(
                    jobs_query,
                    parameters,
                ).fetchone()["count"],
                "deliveries": connection.execute(
                    deliveries_query,
                    parameters,
                ).fetchone()["count"],
            }

    def observed_log_entries(self, *, provider: str, event_id: str) -> tuple[str, ...]:
        query = (
            "SELECT DISTINCT payload ->> 'log_message' AS log_message "
            "FROM outbox_jobs "
            "WHERE provider = %s AND event_id = %s "
            "AND payload ? 'log_message' "
            "ORDER BY log_message"
        )
        with self.connect(autocommit=True) as connection:
            rows = connection.execute(query, (provider, event_id)).fetchall()
        return tuple(
            row["log_message"]
            for row in rows
            if isinstance(row.get("log_message"), str) and row["log_message"]
        )

    @contextmanager
    def transaction(self) -> Iterator[psycopg.Connection]:
        with self.connect() as connection, connection.transaction():
            yield connection
