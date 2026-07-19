"""Publicly proxyable, read-only judge MCP backed by published projections."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from crosspatch.mcp.auth import AuthPolicy
from crosspatch.mcp.published import (
    READ_ONLY_TOOL,
    PublishedCaseReader,
    PublishedMCP,
    mcp_result,
    publicable,
    publicable_for_incident,
    publish_server,
    require_auth_zone,
    require_incident_id,
    transport_security,
)

JUDGE_TOOL_ALLOWLIST = (
    "list_incidents",
    "get_case_file",
    "get_verdicts",
    "search_evidence",
    "get_sanitized_evidence",
    "get_warrant_log",
    "verify_artifact_manifest",
)

JUDGE_RESOURCE_ALLOWLIST = (
    "crosspatch://incidents/{id}/summary",
    "crosspatch://incidents/{id}/timeline",
    "crosspatch://incidents/{id}/verdicts",
    "crosspatch://incidents/{id}/warrants",
)


def _resource_json(value) -> str:
    return json.dumps(publicable(value), sort_keys=True, separators=(",", ":"))


def build_judge_mcp(reader: PublishedCaseReader, *, auth: AuthPolicy) -> PublishedMCP:
    require_auth_zone(
        auth,
        audience="crosspatch-judge",
        zone="judge",
        judge_registry=True,
    )

    def authorized_published_incident(value: str) -> str:
        incident_id = require_incident_id(value)
        if auth.config.incident_scoped:
            return auth.require_incident(incident_id)
        return incident_id

    server = FastMCP(
        "crosspatch-judge",
        instructions="Read-only access to transactionally published incident projections.",
        stateless_http=False,
        json_response=True,
        transport_security=transport_security(auth),
    )

    @server.tool(annotations=READ_ONLY_TOOL)
    async def list_incidents():
        incidents = publicable(await reader.list_incidents())
        if not auth.config.incident_scoped:
            return mcp_result(operation="list_incidents", data=incidents)
        incident_id = auth.authorized_incident()
        scoped = [
            item
            for item in incidents
            if isinstance(item, dict) and item.get("incident_id") == incident_id
        ]
        return mcp_result(operation="list_incidents", data=scoped, incident_id=incident_id)

    @server.tool(annotations=READ_ONLY_TOOL)
    async def get_case_file(incident_id: str):
        incident_id = authorized_published_incident(incident_id)
        return mcp_result(
            operation="get_case_file",
            data=publicable_for_incident(await reader.get_case_file(incident_id), incident_id),
            incident_id=incident_id,
        )

    @server.tool(annotations=READ_ONLY_TOOL)
    async def get_verdicts(incident_id: str):
        incident_id = authorized_published_incident(incident_id)
        return mcp_result(
            operation="get_verdicts",
            data=publicable_for_incident(await reader.get_verdicts(incident_id), incident_id),
            incident_id=incident_id,
        )

    @server.tool(annotations=READ_ONLY_TOOL)
    async def search_evidence(incident_id: str, query: str):
        incident_id = authorized_published_incident(incident_id)
        return mcp_result(
            operation="search_evidence",
            data=publicable_for_incident(
                await reader.search_evidence(incident_id, query), incident_id
            ),
            incident_id=incident_id,
        )

    @server.tool(annotations=READ_ONLY_TOOL)
    async def get_sanitized_evidence(incident_id: str, evidence_id: str):
        incident_id = authorized_published_incident(incident_id)
        return mcp_result(
            operation="get_sanitized_evidence",
            data=publicable_for_incident(
                await reader.get_sanitized_evidence(incident_id, evidence_id), incident_id
            ),
            incident_id=incident_id,
        )

    @server.tool(annotations=READ_ONLY_TOOL)
    async def get_warrant_log(incident_id: str):
        incident_id = authorized_published_incident(incident_id)
        return mcp_result(
            operation="get_warrant_log",
            data=publicable_for_incident(await reader.get_warrant_log(incident_id), incident_id),
            incident_id=incident_id,
        )

    @server.tool(annotations=READ_ONLY_TOOL)
    async def verify_artifact_manifest(incident_id: str):
        incident_id = authorized_published_incident(incident_id)
        return mcp_result(
            operation="verify_artifact_manifest",
            data=publicable_for_incident(
                await reader.verify_artifact_manifest(incident_id), incident_id
            ),
            incident_id=incident_id,
        )

    @server.resource(JUDGE_RESOURCE_ALLOWLIST[0], mime_type="application/json")
    async def incident_summary(id: str) -> str:
        incident_id = authorized_published_incident(id)
        result = await reader.get_summary(incident_id)
        return _resource_json(
            mcp_result(
                operation="incident_summary",
                data=publicable_for_incident(result, incident_id),
                incident_id=incident_id,
            )
        )

    @server.resource(JUDGE_RESOURCE_ALLOWLIST[1], mime_type="application/json")
    async def incident_timeline(id: str) -> str:
        incident_id = authorized_published_incident(id)
        return _resource_json(
            mcp_result(
                operation="incident_timeline",
                data=publicable_for_incident(
                    await reader.get_timeline(incident_id), incident_id
                ),
                incident_id=incident_id,
            )
        )

    @server.resource(JUDGE_RESOURCE_ALLOWLIST[2], mime_type="application/json")
    async def incident_verdicts(id: str) -> str:
        incident_id = authorized_published_incident(id)
        return _resource_json(
            mcp_result(
                operation="incident_verdicts",
                data=publicable_for_incident(
                    await reader.get_verdicts(incident_id), incident_id
                ),
                incident_id=incident_id,
            )
        )

    @server.resource(JUDGE_RESOURCE_ALLOWLIST[3], mime_type="application/json")
    async def incident_warrants(id: str) -> str:
        incident_id = authorized_published_incident(id)
        return _resource_json(
            mcp_result(
                operation="incident_warrants",
                data=publicable_for_incident(
                    await reader.get_warrants(incident_id), incident_id
                ),
                incident_id=incident_id,
            )
        )

    return publish_server(
        name="crosspatch-judge",
        server=server,
        auth=auth,
        tool_names=JUDGE_TOOL_ALLOWLIST,
        resource_templates=JUDGE_RESOURCE_ALLOWLIST,
    )
