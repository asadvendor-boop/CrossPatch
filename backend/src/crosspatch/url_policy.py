"""Shared URL policy for clients that attach privileged bearer credentials."""

from __future__ import annotations

from urllib.parse import urlparse

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def validated_control_url(value: str) -> str:
    """Require HTTPS, except for an exact loopback HTTP hostname."""
    normalized = value.rstrip("/")
    parsed = urlparse(normalized)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(
            "CrossPatch control URL must use HTTPS except for loopback development"
        ) from error

    del port
    valid_https = parsed.scheme == "https" and parsed.hostname is not None
    valid_loopback_http = parsed.scheme == "http" and parsed.hostname in _LOOPBACK_HOSTS
    if parsed.username is not None or parsed.password is not None:
        valid_https = False
        valid_loopback_http = False
    if not (valid_https or valid_loopback_http):
        raise ValueError(
            "CrossPatch control URL must use HTTPS except for loopback development"
        )
    return normalized
