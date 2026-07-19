"""Small portable DDL helpers used before Alembic owns deployment migrations."""

import re

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

_ROLE_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")

_API_INSERT_TABLES = (
    "incidents",
    "timeline_events",
    "mutation_authority",
    "mutation_warrants",
    "evidence",
    "agent_runs",
    "patch_candidates",
    "verdicts",
    "control_warrants",
    "api_principals",
    "api_incident_grants",
    "live_trial_credentials",
    "live_trial_budget",
    "live_trial_reservations",
    "judge_tokens",
    "judge_token_audit_events",
    "published_cases",
    "test_runs",
    "runtime_work",
)

_API_UPDATE_COLUMNS = {
    "incidents": (
        "state",
        "pending_warrant_id",
        "next_event_sequence",
        "event_chain_head",
        "updated_at",
    ),
    "mutation_authority": ("snapshot_json", "version", "updated_at"),
    "control_warrants": ("status", "approval_id", "updated_at"),
    "api_principals": (
        "bearer_sha256",
        "role",
        "csrf_sha256",
        "step_up_sha256",
        "expires_at",
        "step_up_expires_at",
        "revoked",
        "updated_at",
    ),
    "judge_tokens": ("revoked", "revoked_at"),
    "published_cases": (
        "revision",
        "published",
        "projection",
        "manifest_sha256",
        "updated_at",
    ),
    "live_trial_credentials": (
        "rate_window_started_at",
        "rate_count",
        "revoked_at",
        "revoked_by",
        "updated_at",
    ),
    "live_trial_budget": (
        "spent_microusd",
        "reserved_microusd",
        "updated_at",
    ),
    "live_trial_reservations": (
        "incident_id",
        "actual_microusd",
        "status",
        "settled_at",
    ),
    "runtime_work": (
        "status",
        "owner_id",
        "attempt_count",
        "updated_at",
        "completed_at",
    ),
}

_EVIDENCE_READER_TABLES = (
    "incidents",
    "evidence",
    "test_runs",
    "published_cases",
)

_JUDGE_READER_TABLES = (
    "published_cases",
    "judge_tokens",
)


async def ensure_published_case_boundary(connection: AsyncConnection) -> None:
    """Add and backfill the operator-only Judge-publication boundary."""
    if connection.dialect.name == "sqlite":
        incident_columns = {
            row[1]
            for row in (await connection.execute(text("PRAGMA table_info(incidents)")))
        }
        if "live_trial" not in incident_columns:
            await connection.execute(
                text(
                    "ALTER TABLE incidents ADD COLUMN live_trial BOOLEAN "
                    "NOT NULL DEFAULT FALSE"
                )
            )
        if "owner_subject" not in incident_columns:
            await connection.execute(
                text("ALTER TABLE incidents ADD COLUMN owner_subject VARCHAR(128)")
            )
        columns = {
            row[1]
            for row in (
                await connection.execute(text("PRAGMA table_info(published_cases)"))
            )
        }
        if "published" not in columns:
            await connection.execute(
                text(
                    "ALTER TABLE published_cases ADD COLUMN published BOOLEAN "
                    "NOT NULL DEFAULT FALSE"
                )
            )
        await connection.execute(
            text(
                "UPDATE published_cases SET published = CASE "
                "WHEN json_extract(projection, '$.incident.state') = 'VERIFIED' "
                "AND NOT EXISTS (SELECT 1 FROM incidents "
                "WHERE incidents.id = published_cases.incident_id "
                "AND incidents.live_trial = TRUE) "
                "THEN 1 ELSE 0 END"
            )
        )
        return
    if connection.dialect.name == "postgresql":
        await connection.execute(
            text(
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS "
                "live_trial BOOLEAN NOT NULL DEFAULT FALSE"
            )
        )
        await connection.execute(
            text(
                "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS "
                "owner_subject VARCHAR(128)"
            )
        )
        await connection.execute(
            text(
                "ALTER TABLE published_cases ADD COLUMN IF NOT EXISTS "
                "published BOOLEAN NOT NULL DEFAULT FALSE"
            )
        )
        await connection.execute(
            text(
                "UPDATE published_cases SET published = "
                "COALESCE(projection -> 'incident' ->> 'state' = 'VERIFIED', FALSE) "
                "AND NOT EXISTS (SELECT 1 FROM incidents "
                "WHERE incidents.id = published_cases.incident_id "
                "AND incidents.live_trial = TRUE)"
            )
        )
        return
    raise RuntimeError("published-case migration requires SQLite or PostgreSQL")


async def _grant_database_connect(connection: AsyncConnection, quoted_role: str) -> None:
    database_name = await connection.scalar(text("SELECT current_database()"))
    if not isinstance(database_name, str) or not database_name:
        raise RuntimeError("PostgreSQL did not report the current database")
    quoted_database = connection.dialect.identifier_preparer.quote(database_name)
    await connection.execute(
        text(f"GRANT CONNECT ON DATABASE {quoted_database} TO {quoted_role}")
    )


async def ensure_login_role(
    connection: AsyncConnection,
    *,
    role_name: str,
    password: str,
) -> None:
    """Create or rotate one non-owner runtime login without interpolating its secret."""
    if connection.dialect.name != "postgresql":
        raise RuntimeError("control database roles are supported only on PostgreSQL")
    if not _ROLE_NAME.fullmatch(role_name):
        raise ValueError("unsafe PostgreSQL role name")
    if len(password) < 24 or "\x00" in password:
        raise ValueError("PostgreSQL runtime role passwords require at least 24 characters")
    exists = await connection.scalar(
        text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role_name)"),
        {"role_name": role_name},
    )
    if not exists:
        await connection.execute(
            text(
                f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB '
                "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
            )
        )
    statement = await connection.scalar(
        text(
            "SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER "
            "NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', "
            "CAST(:role_name AS text), CAST(:password AS text))"
        ),
        {"role_name": role_name, "password": password},
    )
    if not isinstance(statement, str):
        raise RuntimeError("PostgreSQL failed to render a role rotation statement")
    await connection.execute(text(statement))


async def configure_control_roles(
    connection: AsyncConnection,
    *,
    api_password: str,
    broker_password: str,
    evidence_password: str,
    judge_password: str,
) -> None:
    """Install the fixed production authority zones after owner-only DDL."""
    roles = {
        "crosspatch_api": api_password,
        "crosspatch_broker": broker_password,
        "crosspatch_evidence": evidence_password,
        "crosspatch_judge": judge_password,
    }
    for role_name, password in roles.items():
        await ensure_login_role(connection, role_name=role_name, password=password)

    database_name = await connection.scalar(text("SELECT current_database()"))
    if not isinstance(database_name, str) or not database_name:
        raise RuntimeError("PostgreSQL did not report the current database")
    quoted_database = connection.dialect.identifier_preparer.quote(database_name)
    await connection.execute(text(f"REVOKE CONNECT ON DATABASE {quoted_database} FROM PUBLIC"))
    await connection.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
    await connection.execute(text("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC"))

    await grant_api_control_privileges(connection, role_name="crosspatch_api")
    await grant_broker_warrant_privileges(connection, role_name="crosspatch_broker")
    await grant_evidence_reader_privileges(
        connection, role_name="crosspatch_evidence"
    )
    await grant_judge_reader_privileges(connection, role_name="crosspatch_judge")


async def install_judge_token_guards(connection: AsyncConnection) -> None:
    """Bind revocation to an immutable audit event and forbid lifecycle rewrites."""
    if connection.dialect.name != "postgresql":
        raise RuntimeError("judge token database guards require PostgreSQL")
    await connection.execute(
        text(
            """
            CREATE OR REPLACE FUNCTION crosspatch_guard_judge_token_mutation()
            RETURNS trigger LANGUAGE plpgsql AS $$
            DECLARE
                has_matching_audit boolean;
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'judge token identities cannot be deleted';
                END IF;

                IF OLD.token_sha256 IS DISTINCT FROM NEW.token_sha256
                    OR OLD.jti IS DISTINCT FROM NEW.jti
                    OR OLD.expires_at IS DISTINCT FROM NEW.expires_at
                    OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
                    RAISE EXCEPTION 'judge token identity and expiry are immutable';
                END IF;

                IF OLD.revoked THEN
                    IF NOT NEW.revoked
                        OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
                        RAISE EXCEPTION 'judge token revocation is irreversible';
                    END IF;
                    RETURN NEW;
                END IF;

                IF NOT NEW.revoked THEN
                    IF NEW.revoked_at IS NOT NULL THEN
                        RAISE EXCEPTION 'active judge tokens cannot have a revocation time';
                    END IF;
                    RETURN NEW;
                END IF;

                IF NEW.revoked_at IS NULL THEN
                    RAISE EXCEPTION 'judge token revocation time is required';
                END IF;
                SELECT EXISTS (
                    SELECT 1
                    FROM judge_token_audit_events audit
                    WHERE audit.token_id = NEW.jti
                        AND audit.action = 'REVOKED'
                        AND audit.created_at = NEW.revoked_at
                ) INTO has_matching_audit;
                IF NOT has_matching_audit THEN
                    RAISE EXCEPTION
                        'judge token revocation requires matching append-only REVOKED audit';
                END IF;
                RETURN NEW;
            END
            $$
            """
        )
    )
    await connection.execute(
        text("DROP TRIGGER IF EXISTS judge_tokens_guard ON judge_tokens")
    )
    await connection.execute(
        text(
            """
            CREATE TRIGGER judge_tokens_guard
            BEFORE UPDATE OR DELETE ON judge_tokens
            FOR EACH ROW EXECUTE FUNCTION crosspatch_guard_judge_token_mutation()
            """
        )
    )


async def install_append_only_guards(connection: AsyncConnection) -> None:
    """Forbid update/delete of timeline rows at the database authority boundary."""
    dialect = connection.dialect.name
    if dialect == "sqlite":
        await connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS timeline_events_no_update
                BEFORE UPDATE ON timeline_events
                BEGIN
                    SELECT RAISE(ABORT, 'timeline_events are append-only');
                END
                """
            )
        )
        await connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS timeline_events_no_delete
                BEFORE DELETE ON timeline_events
                BEGIN
                    SELECT RAISE(ABORT, 'timeline_events are append-only');
                END
                """
            )
        )
        await connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS judge_token_audit_events_no_update
                BEFORE UPDATE ON judge_token_audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'judge token audit events are append-only');
                END
                """
            )
        )
        await connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS judge_token_audit_events_no_delete
                BEFORE DELETE ON judge_token_audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'judge token audit events are append-only');
                END
                """
            )
        )
        await connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS incidents_verified_terminal
                BEFORE UPDATE OF state ON incidents
                WHEN OLD.state = 'VERIFIED' AND NEW.state != 'VERIFIED'
                BEGIN
                    SELECT RAISE(ABORT, 'VERIFIED incidents are terminal');
                END
                """
            )
        )
        await connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS published_cases_operator_verified_insert
                BEFORE INSERT ON published_cases
                WHEN NEW.published = 1 AND NOT EXISTS (
                    SELECT 1 FROM incidents
                    WHERE incidents.id = NEW.incident_id
                    AND incidents.live_trial = 0
                    AND incidents.state = 'VERIFIED'
                )
                BEGIN
                    SELECT RAISE(ABORT, 'publication requires a verified operator incident');
                END
                """
            )
        )
        await connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS published_cases_operator_verified_update
                BEFORE UPDATE OF published ON published_cases
                WHEN NEW.published = 1 AND NOT EXISTS (
                    SELECT 1 FROM incidents
                    WHERE incidents.id = NEW.incident_id
                    AND incidents.live_trial = 0
                    AND incidents.state = 'VERIFIED'
                )
                BEGIN
                    SELECT RAISE(ABORT, 'publication requires a verified operator incident');
                END
                """
            )
        )
        return
    if dialect == "postgresql":
        await connection.execute(
            text(
                """
                CREATE OR REPLACE FUNCTION crosspatch_reject_event_mutation()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'timeline_events are append-only';
                END
                $$
                """
            )
        )
        await connection.execute(
            text("DROP TRIGGER IF EXISTS timeline_events_no_mutation ON timeline_events")
        )
        await connection.execute(
            text(
                """
                CREATE TRIGGER timeline_events_no_mutation
                BEFORE UPDATE OR DELETE ON timeline_events
                FOR EACH ROW EXECUTE FUNCTION crosspatch_reject_event_mutation()
                """
            )
        )
        await connection.execute(
            text(
                "DROP TRIGGER IF EXISTS judge_token_audit_events_no_mutation "
                "ON judge_token_audit_events"
            )
        )
        await connection.execute(
            text(
                """
                CREATE TRIGGER judge_token_audit_events_no_mutation
                BEFORE UPDATE OR DELETE ON judge_token_audit_events
                FOR EACH ROW EXECUTE FUNCTION crosspatch_reject_event_mutation()
                """
            )
        )
        await install_judge_token_guards(connection)
        await connection.execute(
            text(
                """
                CREATE OR REPLACE FUNCTION crosspatch_guard_verified_terminal()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF OLD.state = 'VERIFIED' AND NEW.state <> 'VERIFIED' THEN
                        RAISE EXCEPTION 'VERIFIED incidents are terminal';
                    END IF;
                    RETURN NEW;
                END
                $$
                """
            )
        )
        await connection.execute(
            text(
                "DROP TRIGGER IF EXISTS incidents_verified_terminal ON incidents"
            )
        )
        await connection.execute(
            text(
                """
                CREATE TRIGGER incidents_verified_terminal
                BEFORE UPDATE OF state ON incidents
                FOR EACH ROW EXECUTE FUNCTION crosspatch_guard_verified_terminal()
                """
            )
        )
        await connection.execute(
            text(
                """
                CREATE OR REPLACE FUNCTION crosspatch_guard_case_publication()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.published AND NOT EXISTS (
                        SELECT 1 FROM incidents
                        WHERE incidents.id = NEW.incident_id
                        AND incidents.live_trial = FALSE
                        AND incidents.state = 'VERIFIED'
                    ) THEN
                        RAISE EXCEPTION
                            'publication requires a verified operator incident';
                    END IF;
                    RETURN NEW;
                END
                $$
                """
            )
        )
        await connection.execute(
            text(
                "DROP TRIGGER IF EXISTS published_cases_operator_verified "
                "ON published_cases"
            )
        )
        await connection.execute(
            text(
                """
                CREATE TRIGGER published_cases_operator_verified
                BEFORE INSERT OR UPDATE OF published ON published_cases
                FOR EACH ROW EXECUTE FUNCTION crosspatch_guard_case_publication()
                """
            )
        )
        return
    raise RuntimeError(f"unsupported database dialect for append-only guards: {dialect}")


async def grant_runtime_event_privileges(
    connection: AsyncConnection,
    *,
    role_name: str = "crosspatch_runtime",
) -> None:
    """Grant the runtime role only the event permissions needed to append."""
    if connection.dialect.name != "postgresql":
        raise RuntimeError("runtime database roles are supported only on PostgreSQL")
    if not _ROLE_NAME.fullmatch(role_name):
        raise ValueError("unsafe PostgreSQL role name")
    quoted = f'"{role_name}"'
    await connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {quoted}"))
    await connection.execute(text(f"GRANT SELECT, INSERT, UPDATE ON incidents TO {quoted}"))
    await connection.execute(text(f"GRANT SELECT, INSERT ON timeline_events TO {quoted}"))
    await connection.execute(text(f"REVOKE UPDATE, DELETE ON timeline_events FROM {quoted}"))


async def grant_api_control_privileges(
    connection: AsyncConnection,
    *,
    role_name: str = "crosspatch_api",
) -> None:
    """Grant the API its durable control-plane writes without owner/delete authority."""
    if connection.dialect.name != "postgresql":
        raise RuntimeError("control database roles are supported only on PostgreSQL")
    if not _ROLE_NAME.fullmatch(role_name):
        raise ValueError("unsafe PostgreSQL role name")
    await ensure_published_case_boundary(connection)
    quoted = f'"{role_name}"'
    insert_tables = ", ".join(_API_INSERT_TABLES)
    await _grant_database_connect(connection, quoted)
    await connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {quoted}"))
    await connection.execute(
        text(f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {quoted}")
    )
    await connection.execute(text(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {quoted}"))
    await connection.execute(text(f"GRANT INSERT ON {insert_tables} TO {quoted}"))
    for table_name, columns in _API_UPDATE_COLUMNS.items():
        column_list = ", ".join(columns)
        await connection.execute(
            text(f"GRANT UPDATE ({column_list}) ON {table_name} TO {quoted}")
        )


async def _grant_readonly_tables(
    connection: AsyncConnection,
    *,
    role_name: str,
    table_names: tuple[str, ...],
) -> None:
    """Grant one MCP role only the persisted projections it actually consumes."""
    if connection.dialect.name != "postgresql":
        raise RuntimeError("control database roles are supported only on PostgreSQL")
    if not _ROLE_NAME.fullmatch(role_name):
        raise ValueError("unsafe PostgreSQL role name")
    if not table_names or any(not _ROLE_NAME.fullmatch(name) for name in table_names):
        raise ValueError("unsafe PostgreSQL table allowlist")
    quoted = f'"{role_name}"'
    tables = ", ".join(table_names)
    await _grant_database_connect(connection, quoted)
    await connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {quoted}"))
    await connection.execute(
        text(f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {quoted}")
    )
    await connection.execute(text(f"GRANT SELECT ON {tables} TO {quoted}"))


async def grant_evidence_reader_privileges(
    connection: AsyncConnection,
    *,
    role_name: str = "crosspatch_evidence",
) -> None:
    """Grant the internal Evidence MCP only sanitized evidence projections."""
    await _grant_readonly_tables(
        connection,
        role_name=role_name,
        table_names=_EVIDENCE_READER_TABLES,
    )


async def grant_judge_reader_privileges(
    connection: AsyncConnection,
    *,
    role_name: str = "crosspatch_judge",
) -> None:
    """Grant Judge MCP published cases plus its bearer revocation registry."""
    await _grant_readonly_tables(
        connection,
        role_name=role_name,
        table_names=_JUDGE_READER_TABLES,
    )


async def install_warrant_guards(connection: AsyncConnection) -> None:
    """Make approval bindings immutable and warrant states one-way in PostgreSQL."""
    if connection.dialect.name != "postgresql":
        raise RuntimeError("warrant database guards require PostgreSQL")
    await connection.execute(
        text(
            """
            CREATE OR REPLACE FUNCTION crosspatch_guard_warrant_mutation()
            RETURNS trigger LANGUAGE plpgsql AS $$
            DECLARE
                table_owner name;
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    SELECT pg_get_userbyid(c.relowner) INTO table_owner
                    FROM pg_class c
                    WHERE c.oid = TG_RELID;
                    IF current_user = table_owner THEN
                        RETURN OLD;
                    END IF;
                    RAISE EXCEPTION 'mutation warrants cannot be deleted by runtime roles';
                END IF;

                IF OLD.id IS DISTINCT FROM NEW.id
                    OR OLD.incident_id IS DISTINCT FROM NEW.incident_id
                    OR OLD.nonce_sha256 IS DISTINCT FROM NEW.nonce_sha256
                    OR OLD.document_json IS DISTINCT FROM NEW.document_json
                    OR OLD.approval_json IS DISTINCT FROM NEW.approval_json
                    OR OLD.expires_at IS DISTINCT FROM NEW.expires_at
                    OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
                    RAISE EXCEPTION 'approved warrant bindings are immutable';
                END IF;

                IF OLD.state = 'APPROVED' AND NEW.state = 'CONSUMING' THEN
                    IF NEW.claimed_at IS NULL
                        OR NEW.nonce_consumed_at IS NULL
                        OR NEW.claimed_at IS DISTINCT FROM NEW.nonce_consumed_at
                        OR NEW.result_json IS NOT NULL
                        OR NEW.finished_at IS NOT NULL THEN
                        RAISE EXCEPTION 'invalid warrant claim transition';
                    END IF;
                    RETURN NEW;
                END IF;
                IF OLD.state = 'APPROVED' AND NEW.state IN ('REJECTED', 'EXPIRED') THEN
                    IF NEW.claimed_at IS NOT NULL
                        OR NEW.nonce_consumed_at IS NOT NULL
                        OR NEW.result_json IS NOT NULL
                        OR NEW.finished_at IS NOT NULL THEN
                        RAISE EXCEPTION 'invalid warrant rejection transition';
                    END IF;
                    RETURN NEW;
                END IF;
                IF OLD.state = 'CONSUMING' AND NEW.state = 'CONSUMED' THEN
                    IF NEW.claimed_at IS DISTINCT FROM OLD.claimed_at
                        OR NEW.nonce_consumed_at IS DISTINCT FROM OLD.nonce_consumed_at
                        OR NEW.result_json IS NULL
                        OR NEW.finished_at IS NULL THEN
                        RAISE EXCEPTION 'invalid warrant completion transition';
                    END IF;
                    RETURN NEW;
                END IF;
                RAISE EXCEPTION 'warrant state transitions are irreversible';
            END
            $$
            """
        )
    )
    await connection.execute(
        text("DROP TRIGGER IF EXISTS mutation_warrants_guard ON mutation_warrants")
    )
    await connection.execute(
        text(
            """
            CREATE TRIGGER mutation_warrants_guard
            BEFORE UPDATE OR DELETE ON mutation_warrants
            FOR EACH ROW EXECUTE FUNCTION crosspatch_guard_warrant_mutation()
            """
        )
    )


async def grant_broker_warrant_privileges(
    connection: AsyncConnection,
    *,
    role_name: str = "crosspatch_broker",
) -> None:
    """Grant the broker claim/readback rights but no authority or binding writes."""
    if connection.dialect.name != "postgresql":
        raise RuntimeError("broker database roles are supported only on PostgreSQL")
    if not _ROLE_NAME.fullmatch(role_name):
        raise ValueError("unsafe PostgreSQL role name")
    quoted = f'"{role_name}"'
    await _grant_database_connect(connection, quoted)
    await connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {quoted}"))
    await connection.execute(
        text(f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {quoted}")
    )
    await connection.execute(text(f"GRANT SELECT ON mutation_authority TO {quoted}"))
    await connection.execute(text(f"GRANT SELECT ON mutation_warrants TO {quoted}"))
    await connection.execute(
        text(
            "GRANT UPDATE (state, claimed_at, nonce_consumed_at, finished_at, "
            f"result_json, updated_at) ON mutation_warrants TO {quoted}"
        )
    )
    await connection.execute(
        text(f"REVOKE INSERT, DELETE, TRUNCATE ON mutation_warrants FROM {quoted}")
    )
    await connection.execute(
        text(f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON mutation_authority FROM {quoted}")
    )
