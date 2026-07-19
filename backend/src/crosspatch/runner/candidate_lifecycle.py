"""Authenticated per-boot identity for the disposable candidate executor."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from crosspatch.domain.hashing import canonical_json

_BOOT_MAC_DOMAIN = b"crosspatch-candidate-executor-boot-v1\x00"


def new_candidate_executor_boot_id() -> str:
    return f"cpb-{secrets.token_hex(16)}"


def candidate_executor_boot_mac(token: str, boot_id: str, candidate_uid: int) -> str:
    material = canonical_json(
        {
            "boot_id": boot_id,
            "candidate_uid": candidate_uid,
            "service_role": "candidate-executor",
        }
    )
    return hmac.new(
        token.encode("utf-8"),
        _BOOT_MAC_DOMAIN + material,
        hashlib.sha256,
    ).hexdigest()
