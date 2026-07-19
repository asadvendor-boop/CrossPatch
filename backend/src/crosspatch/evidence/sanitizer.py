"""Deterministic sanitization for evidence that may contain prompt injection."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_EVIDENCE_BYTES = 256 * 1024
MAX_EVIDENCE_LINES = 2_000
MAX_LINE_CHARACTERS = 4_096
MAX_PROVENANCE_CHARACTERS = 512
PROVENANCE_TRUNCATION_MARKER = "[LINE_TRUNCATED field=provenance]"

TagKind = Literal[
    "POTENTIAL_INSTRUCTION_REDACTED",
    "SECRET_REDACTED",
    "CONTROL_SEQUENCE_REMOVED",
    "INVALID_UTF8_REPLACED",
    "LINE_TRUNCATED",
    "EVIDENCE_TRUNCATED",
]

_INSTRUCTION_PATTERNS = (
    re.compile(r"(?:^|\s)\[(?:system|developer|assistant|tool)\](?:\s|$)", re.I),
    re.compile(r"(?:^|\s)#{1,6}\s*(?:system|developer|assistant|tool)\b", re.I),
    re.compile(r"<\|\s*(?:system|developer|assistant|tool)\s*\|>", re.I),
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b", re.I),
    re.compile(
        r"\b(?:reveal|print|return|expose)\s+(?:the\s+)?(?:system|developer)\s+prompt\b",
        re.I,
    ),
    re.compile(
        r"\b(?:execute|run|invoke|call)\s+(?:the\s+)?(?:shell|command|tool|function)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:override|disregard|bypass)\s+(?:the\s+)?(?:policy|guardrail|instructions?)\b",
        re.I,
    ),
    re.compile(r"\byou\s+are\s+(?:now\s+)?(?:chatgpt|an?\s+assistant|the\s+system)\b", re.I),
    re.compile(r"\byou\s+must\s+(?:approve|clear|execute|ignore|reveal|return)\b", re.I),
    re.compile(r"\bfollow\s+(?:these|the)\s+new\s+(?:directions|instructions)\b", re.I),
    re.compile(r"\bdo\s+not\s+follow\s+(?:the\s+)?developer\s+(?:message|instructions)\b", re.I),
    re.compile(r"\bobey\s+(?:this|the)\s+(?:log|message|evidence)\b", re.I),
    re.compile(r"\b(?:call|invoke|run)\s+execute_warrant\b", re.I),
)
_XML_CONTROL = re.compile(
    r"<\s*/?\s*(?:tool(?:_call)?|function(?:_call)?|system|assistant|developer|instruction|command)\b",
    re.I,
)
_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])")
_AUTHORIZATION = re.compile(r"\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[^\s,;]+", re.I)
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9._-]{6,}")
_SECRET_FIELD_NAMES = (
    r"api[_-]?key|access[_-]?token|token|password|passwd|secret|credential|"
    r"private[_-]?key|signing[_-]?key"
)
_JSON_NAMED_SECRET = re.compile(
    rf'(?P<prefix>["\'](?:{_SECRET_FIELD_NAMES})["\']\s*:\s*)'
    r'(?P<quote>["\'])(?P<value>.*?)(?P=quote)',
    re.I,
)
_NAMED_SECRET = re.compile(
    rf"\b({_SECRET_FIELD_NAMES})\s*([:=])\s*([^\s,;]+)",
    re.I,
)
_PEM_PRIVATE_KEY_BEGIN = re.compile(
    r"-----BEGIN (?P<label>(?:(?:ENCRYPTED|RSA|EC|DSA|OPENSSH) )?PRIVATE KEY)-----",
    re.I,
)

_FORMAT_CONTROLS = frozenset(
    {
        "\u061c",
        "\u180e",
        "\u200b",
        "\u200c",
        "\u200d",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2060",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
        "\ufeff",
    }
)


class SanitizationTag(BaseModel):
    """A redaction record bound to both artifact hashes and a raw byte range."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: TagKind
    raw_byte_start: int = Field(ge=0)
    raw_byte_end: int = Field(ge=0)
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sanitized_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SanitizedEvidence(BaseModel):
    """Model-safe view of untrusted bytes; it never contains a raw path or bytes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    classification: Literal["UNTRUSTED_EVIDENCE"] = "UNTRUSTED_EVIDENCE"
    provenance: str = Field(min_length=1, max_length=MAX_PROVENANCE_CHARACTERS)
    provenance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provenance_tags: tuple[TagKind, ...]
    text: str
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sanitized_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_size_bytes: int = Field(ge=0)
    sanitized_size_bytes: int = Field(ge=0)
    truncated: bool
    tags: tuple[SanitizationTag, ...]


@dataclass(frozen=True, slots=True)
class _PendingTag:
    kind: TagKind
    raw_byte_start: int
    raw_byte_end: int


def sanitize_evidence(
    raw: bytes,
    provenance: str,
    *,
    secret_values: tuple[str, ...] = (),
) -> SanitizedEvidence:
    """Return a deterministic, bounded view safe to place in model context."""
    if not isinstance(raw, bytes):
        raise TypeError("raw evidence must be bytes")
    if not isinstance(provenance, str) or not provenance.strip():
        raise ValueError("provenance must be a non-empty string")

    safe_provenance, provenance_sha256, provenance_tags = _sanitize_provenance(
        provenance,
        secret_values,
    )
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    limited = raw[:MAX_EVIDENCE_BYTES]
    truncated_at = len(limited) if len(limited) < len(raw) else None
    pending: list[_PendingTag] = []
    output: list[str] = []
    offset = 0

    all_lines = limited.splitlines(keepends=True)
    if not all_lines and limited == b"":
        all_lines = []
    line_limit = MAX_EVIDENCE_LINES - 1
    if len(all_lines) > line_limit:
        kept_lines = all_lines[:line_limit]
        line_boundary = sum(len(line) for line in kept_lines)
        truncated_at = line_boundary if truncated_at is None else min(truncated_at, line_boundary)
        all_lines = kept_lines
    instruction_lines = _instruction_line_indexes(all_lines)
    pem_secret_lines = _pem_private_key_line_indexes(all_lines)

    configured = tuple(
        sorted({value for value in secret_values if value}, key=lambda value: (-len(value), value))
    )
    for line_index, raw_line in enumerate(all_lines):
        start = offset
        end = offset + len(raw_line)
        offset = end
        decoded = raw_line.decode("utf-8", errors="replace")
        content, newline = _split_line_ending(decoded)

        if "\ufffd" in content:
            pending.append(_PendingTag("INVALID_UTF8_REPLACED", start, end))

        normalized, controls_removed = _strip_format_controls(content)
        if controls_removed:
            pending.append(_PendingTag("CONTROL_SEQUENCE_REMOVED", start, end))

        if line_index in pem_secret_lines:
            begin = _PEM_PRIVATE_KEY_BEGIN.search(normalized)
            prefix = normalized[: begin.start()] if begin is not None else ""
            output.append(f"{prefix}[SECRET_REDACTED]{newline}")
            pending.append(_PendingTag("SECRET_REDACTED", start, end))
            continue

        if controls_removed or line_index in instruction_lines:
            output.append(f"[POTENTIAL_INSTRUCTION_REDACTED raw_bytes={start}:{end}]{newline}")
            pending.append(_PendingTag("POTENTIAL_INSTRUCTION_REDACTED", start, end))
            continue

        sanitized_line, secret_found = _redact_secrets(normalized, configured)
        if secret_found:
            pending.append(_PendingTag("SECRET_REDACTED", start, end))

        if len(sanitized_line) > MAX_LINE_CHARACTERS:
            sanitized_line = (
                sanitized_line[:MAX_LINE_CHARACTERS] + f"[LINE_TRUNCATED raw_bytes={start}:{end}]"
            )
            pending.append(_PendingTag("LINE_TRUNCATED", start, end))
        output.append(sanitized_line + newline)

    if truncated_at is not None:
        output.append(f"[EVIDENCE_TRUNCATED raw_bytes={truncated_at}:{len(raw)}]")
        pending.append(_PendingTag("EVIDENCE_TRUNCATED", truncated_at, len(raw)))

    text = "".join(output)
    sanitized_bytes = text.encode("utf-8")
    sanitized_sha256 = hashlib.sha256(sanitized_bytes).hexdigest()
    tags = tuple(
        SanitizationTag(
            kind=tag.kind,
            raw_byte_start=tag.raw_byte_start,
            raw_byte_end=tag.raw_byte_end,
            raw_sha256=raw_sha256,
            sanitized_sha256=sanitized_sha256,
        )
        for tag in pending
    )
    return SanitizedEvidence(
        provenance=safe_provenance,
        provenance_sha256=provenance_sha256,
        provenance_tags=provenance_tags,
        text=text,
        raw_sha256=raw_sha256,
        sanitized_sha256=sanitized_sha256,
        raw_size_bytes=len(raw),
        sanitized_size_bytes=len(sanitized_bytes),
        truncated=truncated_at is not None,
        tags=tags,
    )


def _pem_private_key_line_indexes(lines: list[bytes]) -> frozenset[int]:
    secret_lines: set[int] = set()
    active_label: str | None = None

    for line_index, raw_line in enumerate(lines):
        decoded = raw_line.decode("utf-8", errors="replace")
        normalized, _ = _strip_format_controls(decoded)
        if active_label is None:
            begin = _PEM_PRIVATE_KEY_BEGIN.search(normalized)
            if begin is None:
                continue
            active_label = begin.group("label")

        secret_lines.add(line_index)
        if re.search(rf"-----END {re.escape(active_label)}-----", normalized, re.I):
            active_label = None

    return frozenset(secret_lines)


def _sanitize_provenance(
    provenance: str,
    secret_values: tuple[str, ...],
) -> tuple[str, str, tuple[TagKind, ...]]:
    raw = provenance.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    normalized, controls_removed = _strip_format_controls(provenance)
    tags: list[TagKind] = []
    if controls_removed:
        tags.append("CONTROL_SEQUENCE_REMOVED")
    if controls_removed or _contains_instruction(normalized):
        tags.append("POTENTIAL_INSTRUCTION_REDACTED")
        return "[POTENTIAL_INSTRUCTION_REDACTED field=provenance]", digest, tuple(tags)

    configured = tuple(
        sorted({value for value in secret_values if value}, key=lambda value: (-len(value), value))
    )
    sanitized, secret_found = _redact_secrets(normalized, configured)
    if secret_found:
        tags.append("SECRET_REDACTED")
    if len(sanitized) > MAX_PROVENANCE_CHARACTERS:
        sanitized = (
            sanitized[: MAX_PROVENANCE_CHARACTERS - len(PROVENANCE_TRUNCATION_MARKER)]
            + PROVENANCE_TRUNCATION_MARKER
        )
        tags.append("LINE_TRUNCATED")
    if not sanitized.strip():
        sanitized = "[POTENTIAL_INSTRUCTION_REDACTED field=provenance]"
        tags.append("POTENTIAL_INSTRUCTION_REDACTED")
    return sanitized, digest, tuple(tags)


def _strip_format_controls(value: str) -> tuple[str, bool]:
    normalized = unicodedata.normalize("NFKC", value)
    stripped = "".join(
        character
        for character in normalized
        if character not in _FORMAT_CONTROLS
        and not (unicodedata.category(character) == "Cc" and character != "\t")
    )
    return stripped, stripped != normalized


def _split_line_ending(value: str) -> tuple[str, str]:
    if value.endswith("\r\n"):
        return value[:-2], "\n"
    if value.endswith(("\n", "\r")):
        return value[:-1], "\n"
    return value, ""


def _instruction_line_indexes(raw_lines: list[bytes]) -> frozenset[int]:
    scan_parts: list[str] = []
    content_spans: list[tuple[int, int]] = []
    cursor = 0
    for raw_line in raw_lines:
        decoded = raw_line.decode("utf-8", errors="replace")
        content, _ = _split_line_ending(decoded)
        normalized, _ = _strip_format_controls(content)
        start = cursor
        scan_parts.append(normalized)
        cursor += len(normalized)
        content_spans.append((start, cursor))
        scan_parts.append("\n")
        cursor += 1

    matches = _instruction_match_spans("".join(scan_parts))
    return frozenset(
        line_index
        for line_index, (line_start, line_end) in enumerate(content_spans)
        if line_start < line_end
        and any(
            line_start < match_end and match_start < line_end
            for match_start, match_end in matches
        )
    )


def _instruction_match_spans(value: str) -> tuple[tuple[int, int], ...]:
    spans = {match.span() for match in _XML_CONTROL.finditer(value)}
    boundary_normalized = re.sub(r"[_-]", " ", value)
    for candidate in (value, boundary_normalized):
        for pattern in _INSTRUCTION_PATTERNS:
            spans.update(match.span() for match in pattern.finditer(candidate))
    spans.update(
        match.span()
        for match in _BASE64_TOKEN.finditer(value)
        if _decoded_token_contains_instruction(match.group(0))
    )
    return tuple(sorted(spans))


def _contains_instruction(value: str) -> bool:
    return bool(_instruction_match_spans(value))


def _decoded_token_contains_instruction(token: str) -> bool:
    padded = token + "=" * ((4 - len(token) % 4) % 4)
    try:
        if "-" in padded or "_" in padded:
            decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
        else:
            decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return False
    if not decoded or len(decoded) > MAX_LINE_CHARACTERS * 4:
        return False
    decoded_text = decoded.decode("utf-8", errors="ignore")
    normalized, _ = _strip_format_controls(decoded_text)
    return bool(
        _XML_CONTROL.search(normalized)
        or any(pattern.search(normalized) for pattern in _INSTRUCTION_PATTERNS)
    )


def _redact_secrets(value: str, configured: tuple[str, ...]) -> tuple[str, bool]:
    redacted = value
    found = False

    redacted, count = _AUTHORIZATION.subn("Authorization: [SECRET_REDACTED]", redacted)
    found |= count > 0
    redacted, count = _OPENAI_KEY.subn("[SECRET_REDACTED]", redacted)
    found |= count > 0

    def replace_json_named(match: re.Match[str]) -> str:
        return (
            f"{match.group('prefix')}{match.group('quote')}"
            f"[SECRET_REDACTED]{match.group('quote')}"
        )

    redacted, count = _JSON_NAMED_SECRET.subn(replace_json_named, redacted)
    found |= count > 0

    def replace_named(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}[SECRET_REDACTED]"

    redacted, count = _NAMED_SECRET.subn(replace_named, redacted)
    found |= count > 0
    for secret in configured:
        if secret in redacted:
            redacted = redacted.replace(secret, "[SECRET_REDACTED]")
            found = True
    return redacted, found
