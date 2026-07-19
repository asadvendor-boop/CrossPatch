from datetime import UTC, datetime, timedelta, timezone

import pytest
from crosspatch.domain.hashing import CanonicalizationError, canonical_json, sha256_hex


def test_canonical_json_normalizes_key_order_unicode_time_and_semantic_sets():
    left = {
        "z": {"beta", "alpha"},
        "name": "Cafe\u0301",
        "at": datetime(2026, 7, 14, 7, tzinfo=UTC),
        "nested": {"b": 2, "a": 1},
    }
    right = {
        "nested": {"a": 1, "b": 2},
        "at": datetime(2026, 7, 14, 12, tzinfo=timezone(timedelta(hours=5))),
        "name": "Café",
        "z": {"alpha", "beta"},
    }

    assert canonical_json(left) == canonical_json(right)
    assert sha256_hex(left) == sha256_hex(right)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_non_finite_numbers(value):
    with pytest.raises(CanonicalizationError):
        canonical_json({"value": value})


def test_canonical_json_is_compact_utf8_with_trailing_newline_absent():
    encoded = canonical_json({"message": "verified", "count": 1})
    assert encoded == b'{"count":1,"message":"verified"}'
    assert not encoded.endswith(b"\n")
