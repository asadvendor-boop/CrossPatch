from victim.db import WebhookEvent
from victim.worker import DeliveryWorker


def test_failed_delivery_is_retried_without_losing_the_job(database):
    database.accept_vulnerable(
        WebhookEvent(
            provider="acme-pay",
            event_id="evt-retry",
            payload={"order_id": "order-retry"},
            payload_sha256="a" * 64,
        )
    )
    attempts = 0

    def fail_once(_job):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ConnectionError("downstream unavailable")

    worker = DeliveryWorker(database, deliver=fail_once)

    assert worker.run_once().state == "PENDING"
    assert database.counts(provider="acme-pay", event_id="evt-retry")["deliveries"] == 0
    assert worker.run_once().state == "COMPLETED"
    assert attempts == 2
    assert database.counts(provider="acme-pay", event_id="evt-retry") == {
        "receipts": 1,
        "jobs": 1,
        "deliveries": 1,
    }


def test_worker_returns_none_when_no_job_is_pending(database):
    assert DeliveryWorker(database).run_once() is None
