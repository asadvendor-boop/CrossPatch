"""Provider-compatible HMAC signing over the exact HTTP request body."""

from __future__ import annotations

import hashlib
import hmac
import re

SIGNATURE_HEADER = "X-Webhook-Signature"
_SIGNATURE = re.compile(r"^sha256=([0-9a-f]{64})$")


def _digest(body: bytes, secret: str) -> str:
    if not secret:
        raise ValueError("webhook signing secret must not be blank")
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def signed_headers(body: bytes, secret: str) -> dict[str, str]:
    """Return the one authentication header required by the victim endpoint."""
    return {SIGNATURE_HEADER: f"sha256={_digest(body, secret)}"}


def verify_signature(body: bytes, supplied: str, secret: str) -> bool:
    """Validate a strict sha256 header without accepting ambiguous encodings."""
    match = _SIGNATURE.fullmatch(supplied)
    if match is None:
        return False
    expected = _digest(body, secret)
    return hmac.compare_digest(match.group(1), expected)
