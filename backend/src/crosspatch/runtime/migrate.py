"""Owner-only control database migration entrypoint."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping

from sqlalchemy.engine import make_url

from crosspatch.runtime.database import RuntimeDatabase

_ROLE_PASSWORDS = {
    "api_password": "CROSSPATCH_API_POSTGRES_PASSWORD",
    "broker_password": "CROSSPATCH_BROKER_POSTGRES_PASSWORD",
    "evidence_password": "CROSSPATCH_EVIDENCE_POSTGRES_PASSWORD",
    "judge_password": "CROSSPATCH_JUDGE_POSTGRES_PASSWORD",
}


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if len(value) < 24 or "\x00" in value:
        raise RuntimeError(f"{name} must contain at least 24 characters")
    return value


def _release_mode(environment: Mapping[str, str]) -> bool:
    value = environment.get("CROSSPATCH_RELEASE_MODE", "0").strip().casefold()
    if value in {"1", "true", "yes"}:
        return True
    if value in {"0", "false", "no", ""}:
        return False
    raise RuntimeError("CROSSPATCH_RELEASE_MODE must be a boolean value")


async def migrate(environment: Mapping[str, str] | None = None) -> None:
    values = dict(os.environ if environment is None else environment)
    database_url = values.get("CROSSPATCH_DATABASE_URL", "")
    if not database_url or "\x00" in database_url:
        raise RuntimeError("CROSSPATCH_DATABASE_URL is required")
    parsed = make_url(database_url)
    if parsed.get_backend_name() != "postgresql":
        raise RuntimeError("control migration requires PostgreSQL")
    passwords = {
        argument: _required(values, environment_name)
        for argument, environment_name in _ROLE_PASSWORDS.items()
    }
    configured = list(passwords.values())
    owner_password = parsed.password or ""
    if len(set(configured)) != len(configured) or owner_password in configured:
        raise RuntimeError("control database authority zones require distinct passwords")
    if _release_mode(values):
        all_passwords = [owner_password, *configured]
        if any(
            len(password) < 32 or password.startswith("crosspatch-local-")
            for password in all_passwords
        ):
            raise RuntimeError(
                "release mode requires independent random control database passwords"
            )

    database = RuntimeDatabase(database_url)
    try:
        await database.migrate_control_schema(**passwords)
    finally:
        await database.close()


def main() -> None:
    asyncio.run(migrate())


if __name__ == "__main__":
    main()
