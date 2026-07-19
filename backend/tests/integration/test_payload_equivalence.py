from __future__ import annotations

import os

import httpx
import pytest
from crosspatch.runner.reproduction import (
    PayloadEquivalenceReproducer,
    ReproductionOutcome,
    _payload_equivalence_bodies,
)
from victim.app import create_app
from victim.db import Database
from victim.signing import SIGNATURE_HEADER, signed_headers, verify_signature
from victim.webhooks import OrderPaid
from victim.worker import DeliveryWorker


def _database() -> Database:
    url = os.environ.get("CROSSPATCH_TEST_DATABASE_URL")
    if url is None:
        pytest.skip("CROSSPATCH_TEST_DATABASE_URL is required for real PostgreSQL verification")
    database = Database(url)
    database.initialize()
    database.reset()
    return database


def test_equivalence_bodies_are_typed_negative_controls_with_exact_byte_hmac() -> None:
    body_a, body_b, body_c = _payload_equivalence_bodies("evt-equivalence-contract")
    typed_a = OrderPaid.model_validate_json(body_a)
    typed_b = OrderPaid.model_validate_json(body_b)
    typed_c = OrderPaid.model_validate_json(body_c)

    assert body_a != body_b
    assert typed_a == typed_b
    assert typed_a != typed_c

    secret = "owned-sandbox-test-secret"
    headers = tuple(signed_headers(body, secret) for body in (body_a, body_b, body_c))
    assert all(
        verify_signature(body, header[SIGNATURE_HEADER], secret)
        for body, header in zip((body_a, body_b, body_c), headers, strict=True)
    )
    assert verify_signature(body_a, headers[1][SIGNATURE_HEADER], secret) is False
    assert verify_signature(body_b, headers[0][SIGNATURE_HEADER], secret) is False


@pytest.mark.asyncio
async def test_affected_revision_rejects_semantically_equivalent_retry() -> None:
    database = _database()
    try:
        result = await PayloadEquivalenceReproducer(
            database=database,
            signing_secret="owned-sandbox-test-secret",
            transport=httpx.ASGITransport(
                app=create_app(
                    database=database,
                    signing_secret="owned-sandbox-test-secret",
                )
            ),
            drain_jobs=DeliveryWorker(database).drain,
        ).run(event_id="evt-payload-equivalence-affected")

        assert result.lock_state_reached is True
        assert result.outcome is ReproductionOutcome.FAILED
        assert result.response_statuses == (202, 409, 409)
        assert result.counts == {"receipts": 1, "jobs": 1, "deliveries": 1}
        assert "typed A equals B: true" in result.diagnostics
        assert "typed A equals C: false" in result.diagnostics
    finally:
        database.reset()
