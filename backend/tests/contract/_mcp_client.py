from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


@asynccontextmanager
async def connected_mcp_client(
    surface,
    *,
    token: str,
    host: str,
    origin: str,
    manage_lifespan: bool = True,
) -> AsyncIterator[ClientSession]:
    @asynccontextmanager
    async def connect() -> AsyncIterator[ClientSession]:
        transport = httpx.ASGITransport(app=surface.app)
        headers = {
            "authorization": f"Bearer {token}",
            "origin": origin,
        }
        async with httpx.AsyncClient(
            transport=transport,
            base_url=f"http://{host}",
            headers=headers,
        ) as http_client:
            async with streamable_http_client(
                f"http://{host}/mcp",
                http_client=http_client,
            ) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    yield session

    if manage_lifespan:
        async with surface.inner_app.router.lifespan_context(surface.inner_app):
            async with connect() as session:
                yield session
    else:
        async with connect() as session:
            yield session
