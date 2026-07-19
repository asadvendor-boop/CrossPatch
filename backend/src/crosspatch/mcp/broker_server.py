"""Private one-tool Bailiff MCP surface."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from crosspatch.mcp.auth import AuthPolicy
from crosspatch.mcp.published import (
    BrokerExecutor,
    PublishedMCP,
    mcp_result,
    publish_server,
    require_auth_zone,
    transport_security,
)

BROKER_TOOL_ALLOWLIST = ("execute_warrant",)


def build_broker_mcp(broker: BrokerExecutor, *, auth: AuthPolicy) -> PublishedMCP:
    require_auth_zone(
        auth,
        audience="crosspatch-broker",
        zone="broker",
        subjects=frozenset({"Bailiff"}),
    )
    server = FastMCP(
        "crosspatch-broker",
        instructions="Execute one already-approved warrant identifier.",
        stateless_http=False,
        json_response=True,
        transport_security=transport_security(auth),
    )

    @server.tool()
    async def execute_warrant(id: str):
        if not id or len(id) > 128:
            raise ValueError("invalid warrant identifier")
        return mcp_result(
            operation="execute_warrant",
            data=await broker.execute_warrant(id),
        )

    return publish_server(
        name="crosspatch-broker",
        server=server,
        auth=auth,
        tool_names=BROKER_TOOL_ALLOWLIST,
    )
