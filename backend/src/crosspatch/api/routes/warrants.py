"""Human approval-gate and judge-token rotation endpoints."""

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from crosspatch.api.dependencies import (
    ControlService,
    Principal,
    Role,
    get_principal,
    get_service,
    require_approval_controls,
    require_approver,
    require_incident_access,
    require_operator,
)
from crosspatch.api.models import (
    IncidentView,
    JudgeTokenListView,
    JudgeTokenMetadataView,
    JudgeTokenRevokeRequest,
    JudgeTokenRotateRequest,
    JudgeTokenView,
    LiveTrialCredentialRevokeRequest,
    LiveTrialCredentialRotateRequest,
    LiveTrialCredentialView,
    WarrantDecisionRequest,
    WarrantRevisionRequest,
    WarrantView,
)

router = APIRouter(prefix="/api", tags=["approval"])


async def _authorized_warrant(
    service: ControlService,
    warrant_id: str,
    principal: Principal,
) -> WarrantView:
    warrant = await service.get_warrant_for_principal(warrant_id, principal)
    if warrant is None or warrant.id != warrant_id or not principal.can_access(warrant.incident_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="warrant not found")
    return warrant


@router.get("/warrants/{warrant_id}", response_model=WarrantView)
async def get_warrant(
    warrant_id: str,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
) -> WarrantView:
    if principal.role is not Role.LIVE_TRIAL:
        require_operator(principal)
    return await _authorized_warrant(service, warrant_id, principal)


def _controls(
    request: Request,
    principal: Principal,
    origin: str | None,
    csrf_token: str | None,
    step_up_token: str | None,
) -> None:
    if principal.role is Role.LIVE_TRIAL:
        allowed_origins: frozenset[str] = request.app.state.allowed_origins
        if origin is None or origin not in allowed_origins:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="origin rejected",
            )
        return
    require_approval_controls(
        request,
        principal,
        origin=origin,
        csrf_token=csrf_token,
        step_up_token=step_up_token,
    )


async def _decide(
    *,
    approve: bool,
    warrant_id: str,
    body: WarrantDecisionRequest,
    request: Request,
    principal: Principal,
    service: ControlService,
    origin: str | None,
    csrf_token: str | None,
    step_up_token: str | None,
) -> WarrantView:
    _controls(request, principal, origin, csrf_token, step_up_token)
    expected_confirmation = "APPROVE" if approve else "REJECT"
    if body.confirmation != expected_confirmation:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="confirmation mismatch"
        )
    warrant = await _authorized_warrant(service, warrant_id, principal)
    if warrant.status != "PENDING_APPROVAL":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="warrant is not pending")
    if not hmac.compare_digest(warrant.warrant_sha256, body.warrant_sha256):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="warrant changed")
    if principal.role is Role.LIVE_TRIAL and not approve and body.reason is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="live-trial rejection requires a reason",
        )
    decision = (
        service.decide_live_trial_warrant
        if principal.role is Role.LIVE_TRIAL
        else service.decide_warrant
    )
    return await decision(
        warrant_id=warrant_id,
        approve=approve,
        warrant_sha256=body.warrant_sha256,
        actor=principal.subject,
        reason=body.reason,
    )


@router.post("/warrants/{warrant_id}/approve", response_model=WarrantView)
async def approve_warrant(
    warrant_id: str,
    body: WarrantDecisionRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
    origin: str | None = Header(default=None),
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    step_up_token: str | None = Header(default=None, alias="X-CrossPatch-Step-Up"),
) -> WarrantView:
    return await _decide(
        approve=True,
        warrant_id=warrant_id,
        body=body,
        request=request,
        principal=principal,
        service=service,
        origin=origin,
        csrf_token=csrf_token,
        step_up_token=step_up_token,
    )


@router.post("/warrants/{warrant_id}/reject", response_model=WarrantView)
async def reject_warrant(
    warrant_id: str,
    body: WarrantDecisionRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
    origin: str | None = Header(default=None),
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    step_up_token: str | None = Header(default=None, alias="X-CrossPatch-Step-Up"),
) -> WarrantView:
    return await _decide(
        approve=False,
        warrant_id=warrant_id,
        body=body,
        request=request,
        principal=principal,
        service=service,
        origin=origin,
        csrf_token=csrf_token,
        step_up_token=step_up_token,
    )


@router.post(
    "/warrants/{warrant_id}/request-revision",
    response_model=IncidentView,
    status_code=status.HTTP_202_ACCEPTED,
)
async def request_warrant_revision(
    warrant_id: str,
    body: WarrantRevisionRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
    origin: str | None = Header(default=None),
) -> IncidentView:
    if principal.role is not Role.LIVE_TRIAL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="live-trial role required",
        )
    _controls(request, principal, origin, None, None)
    warrant = await _authorized_warrant(service, warrant_id, principal)
    if warrant.status != "PENDING_APPROVAL":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="warrant is not pending")
    if not hmac.compare_digest(warrant.warrant_sha256, body.warrant_sha256):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="warrant changed")
    return await service.request_live_trial_revision(
        warrant_id=warrant_id,
        warrant_sha256=body.warrant_sha256,
        comment=body.comment,
        actor=principal.subject,
    )


@router.post("/judge-tokens/rotate", response_model=JudgeTokenView)
async def rotate_judge_token(
    body: JudgeTokenRotateRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
    origin: str | None = Header(default=None),
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    step_up_token: str | None = Header(default=None, alias="X-CrossPatch-Step-Up"),
) -> JudgeTokenView:
    _controls(request, principal, origin, csrf_token, step_up_token)
    if body.incident_id is not None:
        require_incident_access(principal, body.incident_id)
    return await service.rotate_judge_token(
        actor=principal.subject,
        incident_id=body.incident_id,
    )


@router.post(
    "/live-trial-credentials/rotate",
    response_model=LiveTrialCredentialView,
)
async def rotate_live_trial_credential(
    body: LiveTrialCredentialRotateRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
    origin: str | None = Header(default=None),
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    step_up_token: str | None = Header(default=None, alias="X-CrossPatch-Step-Up"),
) -> LiveTrialCredentialView:
    _controls(request, principal, origin, csrf_token, step_up_token)
    return await service.rotate_live_trial_credential(actor=principal.subject)


@router.post(
    "/live-trial-credentials/{subject}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_live_trial_credential(
    subject: str,
    body: LiveTrialCredentialRevokeRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
    origin: str | None = Header(default=None),
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    step_up_token: str | None = Header(default=None, alias="X-CrossPatch-Step-Up"),
) -> None:
    _controls(request, principal, origin, csrf_token, step_up_token)
    try:
        await service.revoke_live_trial_credential(subject, actor=principal.subject)
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="live-trial credential not found",
        ) from error


@router.get("/judge-tokens", response_model=JudgeTokenListView)
async def list_judge_tokens(
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
) -> JudgeTokenListView:
    require_approver(principal)
    return await service.list_judge_tokens()


@router.post(
    "/judge-tokens/{token_id}/revoke",
    response_model=JudgeTokenMetadataView,
)
async def revoke_judge_token(
    token_id: str,
    body: JudgeTokenRevokeRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    service: ControlService = Depends(get_service),
    origin: str | None = Header(default=None),
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    step_up_token: str | None = Header(default=None, alias="X-CrossPatch-Step-Up"),
) -> JudgeTokenMetadataView:
    _controls(request, principal, origin, csrf_token, step_up_token)
    try:
        return await service.revoke_judge_token(token_id, actor=principal.subject)
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="judge token not found",
        ) from error
