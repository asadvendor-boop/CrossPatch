"""Minimal production loop for the real webhook victim's transactional outbox."""

from __future__ import annotations

import os
import signal
import time

from crosspatch.runner.secrets import (
    INSECURE_VICTIM_DATABASE_PASSWORDS,
    validate_release_database_url,
)
from victim.db import Database
from victim.worker import DeliveryWorker

running = True


def _stop(_signum: int, _frame: object) -> None:
    global running
    running = False


def _validated_database_url() -> str:
    dsn = os.environ.get("VICTIM_DATABASE_URL")
    if not dsn:
        raise RuntimeError("VICTIM_DATABASE_URL is required")
    return validate_release_database_url(
        os.environ,
        dsn,
        label="victim worker database",
        insecure_passwords=INSECURE_VICTIM_DATABASE_PASSWORDS,
    )


def main() -> int:
    dsn = _validated_database_url()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    database = Database(dsn)
    worker = DeliveryWorker(database)
    while running:
        if worker.run_once() is None:
            time.sleep(0.25)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
