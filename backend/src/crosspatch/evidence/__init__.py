"""Hostile-evidence isolation and model-safe evidence views."""

from crosspatch.evidence.artifacts import (
    ArtifactIntegrityError,
    ArtifactStore,
    RawArtifactRef,
    SanitizedArtifactRef,
    UnsafeArtifactPath,
)
from crosspatch.evidence.sanitizer import SanitizedEvidence, sanitize_evidence
from crosspatch.evidence.service import EvidenceService
from crosspatch.evidence.views import EvidenceKind, UntrustedEvidenceEnvelope

__all__ = [
    "ArtifactIntegrityError",
    "ArtifactStore",
    "EvidenceKind",
    "EvidenceService",
    "RawArtifactRef",
    "SanitizedArtifactRef",
    "SanitizedEvidence",
    "UnsafeArtifactPath",
    "UntrustedEvidenceEnvelope",
    "sanitize_evidence",
]
