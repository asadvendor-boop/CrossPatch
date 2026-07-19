"""Sanitized, transactionally published evidence endpoints."""

from fastapi import APIRouter, Depends

from crosspatch.api.dependencies import (
    ControlService,
    Principal,
    get_principal,
    get_service,
    require_incident_access,
)
from crosspatch.api.models import EvidenceView

router = APIRouter(prefix="/api/incidents", tags=["evidence"])


@router.get("/{incident_id}/evidence", response_model=list[EvidenceView])
async def list_evidence(
    incident_id: str,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
) -> list[EvidenceView]:
    require_incident_access(principal, incident_id)
    evidence = await service.list_evidence(incident_id)
    return [item for item in evidence if item.incident_id == incident_id and item.published]
