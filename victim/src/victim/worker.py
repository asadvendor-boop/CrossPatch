"""Transactional outbox consumer with bounded retry state."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from victim.db import Database


@dataclass(frozen=True, slots=True)
class JobResult:
    job_id: int
    state: str
    attempt_count: int


class DeliveryWorker:
    def __init__(
        self,
        database: Database,
        *,
        deliver: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.database = database
        self.deliver = deliver or (lambda _job: None)

    def run_once(self) -> JobResult | None:
        with self.database.transaction() as connection:
            job = connection.execute(
                """
                SELECT id, provider, event_id, payload_sha256, attempt_count, max_attempts
                  FROM outbox_jobs
                 WHERE state = 'PENDING'
                 ORDER BY created_at, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
                """
            ).fetchone()
            if job is None:
                return None
            attempt = job["attempt_count"] + 1
            connection.execute(
                "UPDATE outbox_jobs SET state = 'PROCESSING', attempt_count = %s WHERE id = %s",
                (attempt, job["id"]),
            )
            try:
                self.deliver(dict(job))
            except Exception as error:
                state = "DEAD" if attempt >= job["max_attempts"] else "PENDING"
                connection.execute(
                    "UPDATE outbox_jobs SET state = %s, last_error = %s WHERE id = %s",
                    (state, str(error)[:500], job["id"]),
                )
                return JobResult(job_id=job["id"], state=state, attempt_count=attempt)

            connection.execute(
                """
                INSERT INTO deliveries (job_id, provider, event_id, payload_sha256)
                VALUES (%s, %s, %s, %s)
                """,
                (job["id"], job["provider"], job["event_id"], job["payload_sha256"]),
            )
            connection.execute(
                """
                UPDATE outbox_jobs
                   SET state = 'COMPLETED', completed_at = CURRENT_TIMESTAMP, last_error = NULL
                 WHERE id = %s
                """,
                (job["id"],),
            )
            return JobResult(job_id=job["id"], state="COMPLETED", attempt_count=attempt)

    def drain(self, *, limit: int = 1000) -> int:
        completed = 0
        for _ in range(limit):
            result = self.run_once()
            if result is None:
                break
            completed += result.state == "COMPLETED"
        return completed
