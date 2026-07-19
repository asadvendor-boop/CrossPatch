"""Application service that atomically creates raw and sanitized evidence records."""

from __future__ import annotations

from crosspatch.evidence.artifacts import ArtifactIntegrityError, ArtifactStore
from crosspatch.evidence.sanitizer import sanitize_evidence
from crosspatch.evidence.views import EvidenceKind, UntrustedEvidenceEnvelope


class EvidenceService:
    """Ingest evidence through one sanitizer before it can reach any model surface."""

    def __init__(self, store: ArtifactStore, *, secret_values: tuple[str, ...] = ()) -> None:
        self._store = store
        self._secret_values = secret_values

    def ingest(
        self,
        *,
        kind: EvidenceKind,
        raw_bytes: bytes,
        provenance: str,
        evidence_id: str | None = None,
    ) -> UntrustedEvidenceEnvelope:
        if not isinstance(kind, EvidenceKind):
            raise TypeError("kind must be an EvidenceKind")

        sanitized = sanitize_evidence(
            raw_bytes,
            provenance,
            secret_values=self._secret_values,
        )
        raw_ref, sanitized_ref = self._store.put_evidence_pair(
            raw=raw_bytes,
            sanitized=sanitized.text.encode("utf-8"),
        )
        if raw_ref.sha256 != sanitized.raw_sha256:
            raise ArtifactIntegrityError("raw artifact digest disagrees with sanitizer")
        if sanitized_ref.sha256 != sanitized.sanitized_sha256:
            raise ArtifactIntegrityError("sanitized artifact digest disagrees with sanitizer")
        return UntrustedEvidenceEnvelope.from_sanitized(
            evidence_id=evidence_id or f"ev_{sanitized.sanitized_sha256[:32]}",
            incident_id=self._store.incident_id,
            kind=kind,
            evidence=sanitized,
        )
