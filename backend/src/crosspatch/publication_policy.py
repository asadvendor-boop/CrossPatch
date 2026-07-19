"""Shared field-name policy for every sanitized public projection boundary."""

from __future__ import annotations

import re

FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "access_token",
        "analysis",
        "api_key",
        "approval_mac_key",
        "approval_json",
        "approval_mac",
        "approval_nonce",
        "authority_json",
        "authorization",
        "canonical_document",
        "candidate_context",
        "credential",
        "document_json",
        "envelope_json",
        "nonce",
        "normalized_diff",
        "mutation_capability",
        "output_json",
        "passwd",
        "password",
        "patch_b64",
        "private_key",
        "raw",
        "raw_artifact_path",
        "raw_bytes",
        "raw_path",
        "raw_sha256",
        "receipt",
        "result_json",
        "secret",
        "secret_value",
        "server_mac",
        "shell_capability",
        "signing_key",
        "token",
        "test_run_capability",
    }
)
FORBIDDEN_PUBLIC_KEY_PARTS = frozenset(
    {"authorization", "credential", "nonce", "passwd", "password", "secret", "token"}
)
PUBLIC_ONE_WAY_DIGEST_KEYS = frozenset({"nonce_sha256"})


def normalize_public_key(key: str) -> str:
    """Normalize camelCase and punctuation before applying the public policy."""
    snake_key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    return re.sub(r"[^A-Za-z0-9]+", "_", snake_key).strip("_").lower()


def is_forbidden_public_key(key: str) -> bool:
    """Return whether a field name could carry raw evidence or authority material."""
    normalized = normalize_public_key(key)
    if normalized in PUBLIC_ONE_WAY_DIGEST_KEYS:
        return False
    key_parts = frozenset(normalized.split("_"))
    return (
        normalized in FORBIDDEN_PUBLIC_KEYS
        or not key_parts.isdisjoint(FORBIDDEN_PUBLIC_KEY_PARTS)
        or {"private", "key"} <= key_parts
        or {"signing", "key"} <= key_parts
        or normalized.startswith("raw_")
        or normalized.startswith("nonce_")
        or normalized.endswith("_nonce")
    )
