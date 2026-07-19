import asyncio

import httpx
import pytest
from crosspatch.runner.reproduction import RaceReproducer, ReproductionOutcome
from victim.app import create_app
from victim.signing import signed_headers
from victim.worker import DeliveryWorker


@pytest.mark.asyncio
async def test_affected_revision_reproduces_real_duplicate_delivery(database):
    result = await RaceReproducer(
        database=database,
        signing_secret="test-webhook-secret",
        transport=httpx.ASGITransport(
            app=create_app(database=database, signing_secret="test-webhook-secret")
        ),
        drain_jobs=DeliveryWorker(database).drain,
    ).run(event_id="evt-race")

    assert result.lock_state_reached is True
    assert result.outcome is ReproductionOutcome.FAILED
    assert result.counts == {"receipts": 1, "jobs": 2, "deliveries": 2}


@pytest.mark.asyncio
async def test_thirty_two_duplicate_requests_obey_documented_baseline(database):
    app = create_app(database=database, signing_secret="test-webhook-secret")
    body = b'{"amount_cents":1,"event_id":"evt-stress","order_id":"o","provider":"acme-pay"}'
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://victim"
    ) as client:
        responses = await asyncio.gather(
            *(
                client.post(
                    "/webhooks/order-paid",
                    content=body,
                    headers=signed_headers(body, "test-webhook-secret"),
                )
                for _ in range(32)
            )
        )

    DeliveryWorker(database).drain(limit=64)
    assert all(response.status_code in {200, 202} for response in responses)
    counts = database.counts(provider="acme-pay", event_id="evt-stress")
    assert counts["receipts"] == 1
    assert counts["jobs"] >= 1
    assert counts["jobs"] == counts["deliveries"]


@pytest.mark.asyncio
async def test_thirty_two_distinct_events_are_not_coalesced(database):
    app = create_app(database=database, signing_secret="test-webhook-secret")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://victim"
    ) as client:
        requests = []
        for index in range(32):
            body = (
                f'{{"amount_cents":1,"event_id":"evt-{index}",'
                f'"order_id":"o-{index}","provider":"acme-pay"}}'
            ).encode()
            requests.append(
                client.post(
                    "/webhooks/order-paid",
                    content=body,
                    headers=signed_headers(body, "test-webhook-secret"),
                )
            )
        responses = await asyncio.gather(*requests)

    DeliveryWorker(database).drain(limit=64)
    assert all(response.status_code == 202 for response in responses)
    assert database.counts(provider="acme-pay") == {
        "receipts": 32,
        "jobs": 32,
        "deliveries": 32,
    }
