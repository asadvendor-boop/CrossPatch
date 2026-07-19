"""Incident control endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status

from crosspatch.api.dependencies import (
    ControlService,
    Principal,
    Role,
    get_principal,
    get_service,
    require_incident_access,
    require_operator,
)
from crosspatch.api.models import IncidentCreate, IncidentRoomView, IncidentView
from crosspatch.runtime.scenarios import (
    require_live_trial_scenario,
    require_operator_evidence_profile,
    require_operator_scenario,
)

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.post("", response_model=IncidentView, status_code=status.HTTP_201_CREATED)
async def open_incident(
    body: IncidentCreate,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
) -> IncidentView:
    if principal.role is Role.LIVE_TRIAL:
        if body.evidence_profile != "standard":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="live trials support only standard evidence",
            )
        try:
            definition = require_live_trial_scenario(body.scenario)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(error),
            ) from error
        return await service.open_live_trial(
            scenario=definition.scenario_id,
            title=body.title,
            actor=principal.subject,
        )
    require_operator(principal)
    try:
        definition = require_operator_scenario(body.scenario)
        evidence_profile = require_operator_evidence_profile(
            definition.scenario_id,
            body.evidence_profile,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error
    return await service.open_incident(
        scenario=definition.scenario_id,
        title=body.title,
        actor=principal.subject,
        evidence_profile=evidence_profile,
    )


@router.get("/{incident_id}", response_model=IncidentView)
async def get_incident(
    incident_id: str,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
) -> IncidentView:
    require_incident_access(principal, incident_id)
    incident = await service.get_incident(incident_id)
    if incident is None or incident.id != incident_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
    return incident


@router.get("/{incident_id}/room", response_model=IncidentRoomView)
async def get_incident_room(
    incident_id: str,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
) -> IncidentRoomView:
    require_incident_access(principal, incident_id)
    room = await service.get_room(incident_id, principal)
    if room is None or room.incident.id != incident_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
    return room
