"""Test-only TCP driver for the standalone Docker oracle regression.

Production candidate execution is Unix-socket-only. This fixture preserves the
older host-published black-box regression without adding a TCP fallback to the
production candidate driver.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import uvicorn
from crosspatch.runner.candidate_service import _validate_linux_sandbox_status


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or "\x00" in value:
        raise RuntimeError(f"{name} is required")
    return value


async def serve() -> int:
    candidate_uid = int(_required("CROSSPATCH_CANDIDATE_UID"))
    if os.geteuid() != candidate_uid:
        raise RuntimeError("standalone candidate UID changed")
    _validate_linux_sandbox_status(
        Path("/proc/self/status").read_text(encoding="ascii"),
        expected_uid=candidate_uid,
        expected_gid=candidate_uid,
    )

    candidate_source = Path(_required("CROSSPATCH_CANDIDATE_WORKSPACE")) / "victim/src"
    if not candidate_source.is_dir():
        raise RuntimeError("standalone candidate source is unavailable")
    import sys

    sys.path.insert(0, str(candidate_source))
    from victim.app import create_app
    from victim.db import Database

    port = int(_required("CROSSPATCH_CANDIDATE_PORT"))
    run_seconds = float(_required("CROSSPATCH_CANDIDATE_RUN_SECONDS"))
    if not 1 <= port <= 65535 or not 2 <= run_seconds <= 30:
        raise RuntimeError("standalone candidate bounds changed")
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(
                database=Database(_required("CROSSPATCH_CANDIDATE_DATABASE_URL")),
                signing_secret=_required("CROSSPATCH_CANDIDATE_WEBHOOK_SECRET"),
            ),
            host="0.0.0.0",
            port=port,
            access_log=False,
            log_level="warning",
        )
    )

    async def stop_at_deadline() -> None:
        await asyncio.sleep(run_seconds)
        server.should_exit = True

    deadline = asyncio.create_task(stop_at_deadline())
    try:
        await server.serve()
    finally:
        deadline.cancel()
        await asyncio.gather(deadline, return_exceptions=True)
    return 0 if server.started else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(serve()))
