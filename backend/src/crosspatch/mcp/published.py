"""Shared read-only DTO and application contracts for MCP surfaces."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import BaseModel

from crosspatch.mcp.auth import AuthPolicy, MCPAuthMiddleware
from crosspatch.publication_policy import is_forbidden_public_key, normalize_public_key

_INCIDENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

READ_ONLY_TOOL = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


def transport_security(auth: AuthPolicy) -> TransportSecuritySettings:
    """Apply the same explicit Host/Origin policy inside FastMCP itself."""
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=sorted(auth.config.allowed_hosts),
        allowed_origins=sorted(auth.config.allowed_origins),
    )


def require_incident_id(incident_id: str) -> str:
    if not _INCIDENT_ID.fullmatch(incident_id):
        raise ValueError("invalid incident identifier")
    return incident_id


def publicable(value: Any) -> Any:
    """Normalize a DTO and reject raw, secret-bearing, or non-JSON values."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        raise ValueError("binary content cannot cross a read-only MCP boundary")
    if isinstance(value, (list, tuple)):
        return [publicable(item) for item in value]
    if isinstance(value, dict):
        normalized_keys = {
            normalize_public_key(key): key for key in value if isinstance(key, str)
        }
        classification_key = normalized_keys.get("classification")
        for freeform_key in ("content", "text"):
            if (
                freeform_key in normalized_keys
                and value.get(classification_key) != "UNTRUSTED_EVIDENCE"
            ):
                raise ValueError(f"unclassified freeform MCP field: {freeform_key}")
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("MCP DTO keys must be strings")
            if is_forbidden_public_key(key):
                raise ValueError(f"forbidden MCP DTO field: {key}")
            normalized[key] = publicable(item)
        return normalized
    raise ValueError(f"unsupported MCP DTO type: {type(value).__name__}")


def publicable_for_incident(value: Any, incident_id: str) -> Any:
    """Reject a projection that smuggles a different incident identifier."""
    normalized = publicable(value)

    def validate(item: Any) -> None:
        if isinstance(item, list):
            for child in item:
                validate(child)
            return
        if not isinstance(item, dict):
            return
        returned_incident = item.get("incident_id")
        if returned_incident is not None and returned_incident != incident_id:
            raise ValueError("MCP reader returned data from a different incident")
        for child in item.values():
            validate(child)

    validate(normalized)
    return normalized


def mcp_result(*, operation: str, data: Any, incident_id: str | None = None) -> dict[str, Any]:
    """Tag every model-visible MCP result as untrusted data."""
    envelope: dict[str, Any] = {
        "classification": "UNTRUSTED_EVIDENCE",
        "kind": "mcp_result",
        "operation": operation,
        "data": publicable(data),
    }
    if incident_id is not None:
        envelope["incident_id"] = require_incident_id(incident_id)
    return envelope


def require_auth_zone(
    auth: AuthPolicy,
    *,
    audience: str,
    zone: str,
    subjects: frozenset[str] | None = None,
    judge_registry: bool = False,
) -> None:
    if auth.config.audience != audience or auth.config.zone != zone:
        raise ValueError(f"MCP auth policy must target the {zone} trust zone")
    if subjects is not None and auth.config.allowed_subjects != subjects:
        expected = ", ".join(sorted(subjects))
        raise ValueError(f"MCP auth policy must allow exactly: {expected}")
    if judge_registry and not auth.has_judge_token_registry:
        raise ValueError("judge MCP requires a hashed revocable token registry")
    if judge_registry and not auth.allows_registered_token_reuse:
        raise ValueError("judge MCP requires reusable registered bearer sessions")


@dataclass(frozen=True, slots=True)
class PublishedMCP:
    name: str
    server: FastMCP
    inner_app: Any
    app: Any
    auth: AuthPolicy
    declared_tool_names: tuple[str, ...]
    declared_resource_templates: tuple[str, ...] = ()


def publish_server(
    *,
    name: str,
    server: FastMCP,
    auth: AuthPolicy,
    tool_names: tuple[str, ...],
    resource_templates: tuple[str, ...] = (),
) -> PublishedMCP:
    inner_app = server.streamable_http_app()
    return PublishedMCP(
        name=name,
        server=server,
        inner_app=inner_app,
        app=MCPAuthMiddleware(inner_app, auth),
        auth=auth,
        declared_tool_names=tool_names,
        declared_resource_templates=resource_templates,
    )


class EvidenceReader(Protocol):
    async def list_incident_evidence(self, incident_id: str) -> Any: ...

    async def get_sanitized_artifact(self, incident_id: str, evidence_id: str) -> Any: ...

    async def search_source(self, incident_id: str, query: str) -> Any: ...

    async def get_source_blob(self, incident_id: str, source_id: str) -> Any: ...

    async def list_test_catalog(self, incident_id: str) -> Any: ...

    async def get_test_result(self, incident_id: str, test_run_id: str) -> Any: ...

    async def get_incident_timeline(self, incident_id: str) -> Any: ...


class PublishedCaseReader(Protocol):
    async def list_incidents(self) -> Any: ...

    async def get_case_file(self, incident_id: str) -> Any: ...

    async def get_verdicts(self, incident_id: str) -> Any: ...

    async def search_evidence(self, incident_id: str, query: str) -> Any: ...

    async def get_sanitized_evidence(self, incident_id: str, evidence_id: str) -> Any: ...

    async def get_warrant_log(self, incident_id: str) -> Any: ...

    async def verify_artifact_manifest(self, incident_id: str) -> Any: ...

    async def get_summary(self, incident_id: str) -> Any: ...

    async def get_timeline(self, incident_id: str) -> Any: ...

    async def get_warrants(self, incident_id: str) -> Any: ...


class BrokerExecutor(Protocol):
    async def execute_warrant(self, warrant_id: str) -> Any: ...
