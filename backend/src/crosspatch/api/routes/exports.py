"""Incident-bound signed case export endpoint."""

from fastapi import APIRouter, Depends, Response, status
from fastapi.responses import JSONResponse

from crosspatch.api.dependencies import (
    ControlService,
    Principal,
    get_principal,
    get_service,
    require_incident_access,
)

router = APIRouter(prefix="/api/incidents", tags=["exports"])


@router.get("/{incident_id}/export", response_class=Response)
async def export_case(
    incident_id: str,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
) -> Response:
    require_incident_access(principal, incident_id)
    try:
        archive = await service.export_case(incident_id)
    except ValueError:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "detail": "Case export is available after verified execution.",
                "code": "CASE_EXPORT_NOT_READY",
            },
        )
    if not isinstance(archive, bytes):
        raise TypeError("control service exports must be immutable bytes")
    return Response(
        content=archive,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="crosspatch-{incident_id}.zip"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
