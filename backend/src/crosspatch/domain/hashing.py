"""Canonical byte encoding and seat-specific semantic fingerprints."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, RootModel

from crosspatch.domain.enums import MechanismCode, RetryDisposition, Seat


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented without ambiguity."""


def _sort_key(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _normalize(value: Any) -> Any:
    if isinstance(value, RootModel):
        return _normalize(value.root)
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python"))
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise CanonicalizationError("naive datetimes are not canonical")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("non-finite numbers are not canonical")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str):
                raise CanonicalizationError("canonical object keys must be strings")
            key = unicodedata.normalize("NFC", raw_key)
            if key in normalized:
                raise CanonicalizationError(f"duplicate key after Unicode normalization: {key}")
            normalized[key] = _normalize(raw_value)
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, (set, frozenset)):
        values = [_normalize(item) for item in value]
        return sorted(values, key=_sort_key)
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    raise CanonicalizationError(f"unsupported canonical type: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return compact deterministic UTF-8 bytes for a supported value."""
    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def byte_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_WHITESPACE = re.compile(r"\s+")


def _semantic_text(value: str) -> str:
    return _WHITESPACE.sub(" ", unicodedata.normalize("NFKC", value)).strip().casefold()


def _semantic_mechanism(value: Any) -> str:
    if isinstance(value, MechanismCode):
        return value.value
    if isinstance(value, Mapping) and "code" in value:
        return str(value["code"])
    normalized = _semantic_text(str(value))
    tokens = set(re.findall(r"[a-z0-9]+", normalized))
    stems = {
        "check" if token in {"check", "checked", "checking", "checks"} else token
        for token in tokens
    }
    stems = {
        "insert" if token in {"insert", "inserted", "inserting", "inserts"} else token
        for token in stems
    }
    if {"check", "insert"} <= stems:
        return MechanismCode.CHECK_THEN_INSERT_RACE.value
    if {"worker", "retry"} <= stems:
        return MechanismCode.WORKER_RETRY_DUPLICATION.value
    if {"payload", "id"} <= stems and stems & {"reuse", "collision", "mismatch"}:
        return MechanismCode.PAYLOAD_ID_COLLISION.value
    return normalized


def _semantic_value(value: Any) -> Any:
    if isinstance(value, str):
        return _semantic_text(value)
    if isinstance(value, Mapping):
        return {key: _semantic_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        normalized = [_semantic_value(item) for item in value]
        return sorted(normalized, key=_sort_key)
    if isinstance(value, Enum):
        return value.value
    return value


def _as_mapping(payload: Any) -> Mapping[str, Any]:
    if isinstance(payload, RootModel):
        payload = payload.root
    if isinstance(payload, BaseModel):
        payload = payload.model_dump(mode="python")
    if not isinstance(payload, Mapping):
        raise CanonicalizationError("seat output must be an object")
    return payload


def _ordered_semantic_set(value: Any) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise CanonicalizationError("semantic set field must be a collection")
    return _semantic_value(value)


def _normalize_diff(value: str) -> str:
    lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip() + "\n"


def semantic_payload(seat: Seat, payload: Any) -> dict[str, Any]:
    output = _as_mapping(payload)
    if seat is Seat.INSPECTOR:
        return {
            "mechanism": _semantic_mechanism(output.get("mechanism", "")),
            "evidence_ids": _ordered_semantic_set(output.get("evidence_ids", [])),
            "falsifiers": _ordered_semantic_set(output.get("falsifiers", [])),
        }
    if seat is Seat.PROSECUTOR:
        # Prosecutor is intentionally object-shaped for the Responses API; its
        # discriminated finding sits under `root`, unlike the other seat outputs.
        nested = output.get("root")
        if isinstance(nested, Mapping):
            output = nested
        outcome = output.get("outcome")
        material = {
            "outcome": outcome,
            "counterexample_ids": _ordered_semantic_set(output.get("counterexample_ids", [])),
            "test_ids": _ordered_semantic_set(output.get("test_ids", [])),
        }
        if outcome == "SUPPORTED_RIVAL":
            material["rival_mechanism"] = _semantic_mechanism(output.get("rival_mechanism", ""))
        return material
    if seat is Seat.COUNSEL:
        return {
            "normalized_diff": _normalize_diff(str(output.get("normalized_diff", ""))),
            "test_intentions": _ordered_semantic_set(output.get("test_intentions", [])),
        }
    if seat is Seat.MAGISTRATE:
        required_changes = []
        for change in output.get("required_changes", []):
            if isinstance(change, Mapping):
                required_changes.append(
                    {
                        "code": _semantic_value(change.get("code", "")),
                        "target": change.get("target"),
                    }
                )
            else:
                required_changes.append(_semantic_value(change))
        return {
            "verdict": output.get("verdict"),
            "finding_codes": _ordered_semantic_set(output.get("finding_codes", [])),
            "required_changes": _ordered_semantic_set(required_changes),
            "remand_target": output.get("remand_target"),
        }
    if seat is Seat.BAILIFF:
        return {"warrant_id": output.get("warrant_id")}
    raise CanonicalizationError(f"unsupported seat: {seat}")


def semantic_fingerprint(seat: Seat, payload: Any) -> str:
    return sha256_hex(semantic_payload(seat, payload))


def classify_retry(previous_fingerprint: str, retry_fingerprint: str) -> RetryDisposition:
    if previous_fingerprint == retry_fingerprint:
        return RetryDisposition.FAILED_RETRY_DUPLICATE
    return RetryDisposition.MATERIAL
