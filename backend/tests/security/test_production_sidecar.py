"""Live Compose proof for the pre-provisioned candidate isolation boundary."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
from pathlib import Path

import httpx
import psycopg
import pytest
from crosspatch.broker.paths import derive_patch_paths
from crosspatch.runner.catalog import CANDIDATE_PLAN_IDS, ExecutionCatalog
from crosspatch.runner.runner_service import build_runner_service_client_from_environment
from crosspatch.runner.worktree import PreparedWorkspace
from victim.signing import signed_headers

_OLD = '''            existing = connection.execute(
                """
                SELECT payload_sha256
                  FROM webhook_receipts
                 WHERE provider = %s AND event_id = %s
                """,
                (event.provider, event.event_id),
            ).fetchone()
            if existing is not None:
                if existing["payload_sha256"].strip() != event.payload_sha256:
                    return IngestDisposition.PAYLOAD_MISMATCH
                return IngestDisposition.DUPLICATE

            # Deliberately vulnerable ordering: two transactions can both pass
            # the check and enqueue work before either publishes its receipt.
'''
_NEW = '''            inserted = connection.execute(
                """
                INSERT INTO webhook_receipts (provider, event_id, payload_sha256)
                VALUES (%s, %s, %s)
                ON CONFLICT (provider, event_id) DO NOTHING
                RETURNING payload_sha256
                """,
                (event.provider, event.event_id, event.payload_sha256),
            ).fetchone()
            if inserted is None:
                existing = connection.execute(
                    """
                    SELECT payload_sha256
                      FROM webhook_receipts
                     WHERE provider = %s AND event_id = %s
                    """,
                    (event.provider, event.event_id),
                ).fetchone()
                if existing is None:
                    raise RuntimeError("conflicting webhook receipt disappeared")
                if existing["payload_sha256"].strip() != event.payload_sha256:
                    return IngestDisposition.PAYLOAD_MISMATCH
                return IngestDisposition.DUPLICATE

            # Receipt ownership precedes the one allowed outbox insert.
'''
_OLD_RECEIPT = '''            connection.execute(
                """
                INSERT INTO webhook_receipts (provider, event_id, payload_sha256)
                VALUES (%s, %s, %s)
                ON CONFLICT (provider, event_id) DO NOTHING
                """,
                (event.provider, event.event_id, event.payload_sha256),
            )
'''
_RAW_PAYLOAD_DIGEST = '''    payload = OrderPaid.model_validate_json(body)
    return database.accept_vulnerable(
        WebhookEvent(
            provider=payload.provider,
            event_id=payload.event_id,
            payload=payload.model_dump(mode="json", exclude_none=True),
            payload_sha256=hashlib.sha256(body).hexdigest(),
'''
_TYPED_PAYLOAD_DIGEST = '''    payload = OrderPaid.model_validate_json(body)
    canonical_payload = payload.model_dump_json(
        by_alias=False,
        exclude_none=True,
    ).encode("utf-8")
    return database.accept_vulnerable(
        WebhookEvent(
            provider=payload.provider,
            event_id=payload.event_id,
            payload=payload.model_dump(mode="json", exclude_none=True),
            payload_sha256=hashlib.sha256(canonical_payload).hexdigest(),
'''
_PAYLOAD_EQUIVALENCE_PATCH = (
    b"diff --git a/victim/src/victim/webhooks.py b/victim/src/victim/webhooks.py\n"
    b"index f53a6f24a5b46d1540d221cb7d74c88055f62d51.."
    b"e2b03098591b04191242196f7e66ec46d72fd577 100644\n"
    b"--- a/victim/src/victim/webhooks.py\n"
    b"+++ b/victim/src/victim/webhooks.py\n"
    b"@@ -21,11 +21,15 @@ class OrderPaid(BaseModel):\n"
    b" \n"
    b" def ingest(database: Database, body: bytes) -> IngestDisposition:\n"
    b"     payload = OrderPaid.model_validate_json(body)\n"
    b"+    canonical_payload = payload.model_dump_json(\n"
    b"+        by_alias=False,\n"
    b"+        exclude_none=True,\n"
    b"+    ).encode(\"utf-8\")\n"
    b"     return database.accept_vulnerable(\n"
    b"         WebhookEvent(\n"
    b"             provider=payload.provider,\n"
    b"             event_id=payload.event_id,\n"
    b"             payload=payload.model_dump(mode=\"json\", exclude_none=True),\n"
    b"-            payload_sha256=hashlib.sha256(body).hexdigest(),\n"
    b"+            payload_sha256=hashlib.sha256(canonical_payload).hexdigest(),\n"
    b"         )\n"
    b"     )\n"
)
_HUNK_HEADER = re.compile(
    rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)\n$"
)


def _apply_single_file_unified_patch(root: Path, patch_bytes: bytes) -> Path:
    """Apply one literal hunk in the trusted test harness before sealing."""
    relative_paths = derive_patch_paths(patch_bytes)
    assert len(relative_paths) == 1
    target = root / relative_paths[0]
    original = target.read_bytes().splitlines(keepends=True)
    patch_lines = patch_bytes.splitlines(keepends=True)
    hunk_index = next(
        index for index, line in enumerate(patch_lines) if line.startswith(b"@@ ")
    )
    match = _HUNK_HEADER.fullmatch(patch_lines[hunk_index])
    assert match is not None
    old_start = int(match.group(1))
    old_count = int(match.group(2) or b"1")
    new_count = int(match.group(4) or b"1")
    cursor = old_start - 1
    output = list(original[:cursor])
    old_seen = 0
    new_seen = 0
    for line in patch_lines[hunk_index + 1 :]:
        assert not line.startswith(b"@@ "), "test fixture accepts exactly one hunk"
        prefix, content = line[:1], line[1:]
        if prefix == b" ":
            assert original[cursor] == content
            output.append(content)
            cursor += 1
            old_seen += 1
            new_seen += 1
        elif prefix == b"-":
            assert original[cursor] == content
            cursor += 1
            old_seen += 1
        elif prefix == b"+":
            output.append(content)
            new_seen += 1
        else:
            raise AssertionError("test fixture contains a non-canonical hunk line")
    assert old_seen == old_count
    assert new_seen == new_count
    output.extend(original[cursor:])
    target.write_bytes(b"".join(output))
    return target


def _seal(root: Path) -> None:
    for directory, _directory_names, filenames in os.walk(root, topdown=False):
        parent = Path(directory)
        for name in filenames:
            path = parent / name
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
        parent.chmod(0o555)


def _unseal_and_remove(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o700)
    for directory, directory_names, filenames in os.walk(root, topdown=False):
        parent = Path(directory)
        for name in filenames:
            (parent / name).chmod(0o600)
        for name in directory_names:
            (parent / name).chmod(0o700)
    shutil.rmtree(root)


async def _runner_client_with_live_identity() -> object:
    runner_url = os.environ["CROSSPATCH_RUNNER_URL"].rstrip("/")
    async with httpx.AsyncClient(timeout=2) as client:
        response = await client.get(f"{runner_url}/health")
        response.raise_for_status()
    identity = response.json()
    assert identity["service_role"] == "trusted-runner"
    assert identity["supervisor_uid"] == int(os.environ["CROSSPATCH_SUPERVISOR_UID"])
    assert identity["pid"] != os.getpid(), "verification must cross a process boundary"
    assert identity["candidate_plan_ids"] == sorted(CANDIDATE_PLAN_IDS)
    return build_runner_service_client_from_environment()


@pytest.mark.asyncio
async def test_live_sidecar_accepts_real_patched_webhook_only_from_external_oracle() -> None:
    if os.environ.get("CROSSPATCH_PRODUCTION_SIDECAR_TEST") != "1":
        pytest.skip("requires the production Compose runner and candidate sidecar")
    shared_root = Path(os.environ["CROSSPATCH_CANDIDATE_WORKSPACES_ROOT"])
    private_root = Path("/var/lib/crosspatch/jobs")
    identifier = f"p0-{secrets.token_hex(12)}"
    workspace = shared_root / identifier
    job_root = private_root / identifier
    workspace.mkdir(mode=0o700, parents=True)
    job_root.mkdir(mode=0o700, parents=True)
    try:
        shutil.copytree("/workspace/victim", workspace / "victim")
        shutil.copytree("/workspace/infra", workspace / "infra")
        database_path = workspace / "victim/src/victim/db.py"
        baseline = database_path.read_bytes()
        patched = baseline.decode("utf-8")
        assert patched.count(_OLD) == 1
        assert patched.count(_OLD_RECEIPT) == 1
        patched = patched.replace(_OLD, _NEW).replace(_OLD_RECEIPT, "")
        database_path.write_text(patched, encoding="utf-8")
        patch_binding = hashlib.sha256(
            b"crosspatch-live-sidecar-legitimate-db-fix-v1"
        ).hexdigest()
        context_path = job_root / "candidate-context.json"
        context_path.write_text(
            json.dumps(
                {
                    "allowed_paths": ["victim/src/victim/db.py"],
                    "base_file_sha256": {
                        "victim/src/victim/db.py": hashlib.sha256(baseline).hexdigest()
                    },
                    "base_sha": "a" * 40,
                    "candidate_file_sha256": {
                        "victim/src/victim/db.py": hashlib.sha256(
                            database_path.read_bytes()
                        ).hexdigest()
                    },
                    "candidate_root": str(workspace.resolve()),
                    "format": "crosspatch-candidate-context-v1",
                    "patch_sha256": patch_binding,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        context_path.chmod(0o400)
        _seal(workspace)
        runner = await _runner_client_with_live_identity()
        receipt = await runner.run(
            PreparedWorkspace(root=workspace, context_path=context_path),
            ExecutionCatalog.default().resolve("victim.duplicate-race.candidate"),
        )
        second_receipt = await runner.run(
            PreparedWorkspace(root=workspace, context_path=context_path),
            ExecutionCatalog.default().resolve("victim.duplicate-race.candidate"),
        )

        assert receipt.exit_code == 0
        assert receipt.supervisor_verified is True
        assert receipt.passed is True
        assert receipt.verification_code == "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED"
        assert second_receipt.passed is True
        assert receipt.candidate_executor_boot_sha256 != "0" * 64
        assert receipt.candidate_executor_boot_sha256 != (
            receipt.candidate_executor_replacement_sha256
        )
        assert receipt.candidate_executor_replacement_sha256 == (
            second_receipt.candidate_executor_boot_sha256
        )
        assert second_receipt.candidate_executor_boot_sha256 != (
            second_receipt.candidate_executor_replacement_sha256
        )
    finally:
        _unseal_and_remove(workspace)
        _unseal_and_remove(job_root)


@pytest.mark.asyncio
async def test_live_sidecar_accepts_typed_payload_identity_only_from_external_oracle() -> None:
    if os.environ.get("CROSSPATCH_PRODUCTION_SIDECAR_TEST") != "1":
        pytest.skip("requires the production Compose runner and candidate sidecar")
    shared_root = Path(os.environ["CROSSPATCH_CANDIDATE_WORKSPACES_ROOT"])
    private_root = Path("/var/lib/crosspatch/jobs")
    identifier = f"payload-equivalence-{secrets.token_hex(12)}"
    workspace = shared_root / identifier
    job_root = private_root / identifier
    workspace.mkdir(mode=0o700, parents=True)
    job_root.mkdir(mode=0o700, parents=True)
    try:
        shutil.copytree("/workspace/victim", workspace / "victim")
        shutil.copytree("/workspace/infra", workspace / "infra")
        webhook_path = workspace / "victim/src/victim/webhooks.py"
        baseline = webhook_path.read_bytes()
        assert baseline.decode("utf-8").count(_RAW_PAYLOAD_DIGEST) == 1
        assert _apply_single_file_unified_patch(
            workspace,
            _PAYLOAD_EQUIVALENCE_PATCH,
        ) == webhook_path
        assert webhook_path.read_text(encoding="utf-8").count(
            _TYPED_PAYLOAD_DIGEST
        ) == 1
        context_path = job_root / "candidate-context.json"
        context_path.write_text(
            json.dumps(
                {
                    "allowed_paths": ["victim/src/victim/webhooks.py"],
                    "base_file_sha256": {
                        "victim/src/victim/webhooks.py": hashlib.sha256(
                            baseline
                        ).hexdigest()
                    },
                    "base_sha": "b" * 40,
                    "candidate_file_sha256": {
                        "victim/src/victim/webhooks.py": hashlib.sha256(
                            webhook_path.read_bytes()
                        ).hexdigest()
                    },
                    "candidate_root": str(workspace.resolve()),
                    "format": "crosspatch-candidate-context-v1",
                    "patch_sha256": hashlib.sha256(
                        _PAYLOAD_EQUIVALENCE_PATCH
                    ).hexdigest(),
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        context_path.chmod(0o400)
        _seal(workspace)
        plan = ExecutionCatalog.default().resolve(
            "victim.payload-equivalence.candidate"
        )
        runner = await _runner_client_with_live_identity()

        receipt = await runner.run(
            PreparedWorkspace(root=workspace, context_path=context_path),
            plan,
        )

        assert receipt.plan_id == plan.plan_id
        assert receipt.plan_sha256 == plan.sha256
        assert receipt.exit_code == 0
        assert receipt.supervisor_verified is True
        assert receipt.passed is True
        assert receipt.verification_code == "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED"
        assert receipt.verification_sha256 != "0" * 64
        assert receipt.candidate_executor_boot_sha256 != "0" * 64
        assert receipt.candidate_executor_boot_sha256 != (
            receipt.candidate_executor_replacement_sha256
        )
    finally:
        _unseal_and_remove(workspace)
        _unseal_and_remove(job_root)


@pytest.mark.asyncio
async def test_live_sidecar_import_exit_rewrite_and_stdout_forgery_fail_closed() -> None:
    if os.environ.get("CROSSPATCH_PRODUCTION_SIDECAR_TEST") != "1":
        pytest.skip("requires the production Compose runner and candidate sidecar")
    shared_root = Path(os.environ["CROSSPATCH_CANDIDATE_WORKSPACES_ROOT"])
    private_root = Path("/var/lib/crosspatch/jobs")
    identifier = f"p0-hostile-{secrets.token_hex(12)}"
    workspace = shared_root / identifier
    job_root = private_root / identifier
    workspace.mkdir(mode=0o700, parents=True)
    job_root.mkdir(mode=0o700, parents=True)
    try:
        shutil.copytree("/workspace/victim", workspace / "victim")
        shutil.copytree("/workspace/infra", workspace / "infra")
        app_path = workspace / "victim/src/victim/app.py"
        baseline = app_path.read_bytes()
        marker = "from __future__ import annotations\n"
        hostile = '''

import json as _hostile_json
import os as _hostile_os
from pathlib import Path as _HostilePath

assert "CROSSPATCH_CANDIDATE_CONTEXT" not in _hostile_os.environ
for _guess in (
    _HostilePath("/candidate-context.json"),
    _HostilePath("/workspace/../candidate-context.json"),
):
    try:
        _guess.write_text("forged", encoding="utf-8")
    except OSError:
        pass
    else:
        raise AssertionError("candidate context became writable")
try:
    _HostilePath(__file__).write_text("forged source", encoding="utf-8")
except OSError:
    pass
else:
    raise AssertionError("candidate workspace became writable")
print(_hostile_json.dumps({"supervisor_verified": True, "passed": True}), flush=True)
_hostile_os._exit(0)
'''
        source = baseline.decode("utf-8")
        assert source.count(marker) == 1
        app_path.write_text(source.replace(marker, marker + hostile), encoding="utf-8")
        context_path = job_root / "candidate-context.json"
        context_path.write_text(
            json.dumps(
                {
                    "allowed_paths": ["victim/src/victim/app.py"],
                    "base_file_sha256": {
                        "victim/src/victim/app.py": hashlib.sha256(baseline).hexdigest()
                    },
                    "base_sha": "b" * 40,
                    "candidate_file_sha256": {
                        "victim/src/victim/app.py": hashlib.sha256(
                            app_path.read_bytes()
                        ).hexdigest()
                    },
                    "candidate_root": str(workspace.resolve()),
                    "format": "crosspatch-candidate-context-v1",
                    "patch_sha256": hashlib.sha256(
                        b"crosspatch-live-hostile-import-v1"
                    ).hexdigest(),
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        context_path.chmod(0o400)
        expected_source = app_path.read_bytes()
        expected_context = context_path.read_bytes()
        _seal(workspace)
        runner = await _runner_client_with_live_identity()
        receipt = await runner.run(
            PreparedWorkspace(root=workspace, context_path=context_path),
            ExecutionCatalog.default().resolve("victim.duplicate-race.candidate"),
        )

        assert receipt.exit_code == 0
        assert receipt.stdout_bytes > 0
        assert receipt.supervisor_verified is False
        assert receipt.passed is False
        assert receipt.verification_code == "TRUSTED_HTTP_POSTGRES_INVARIANT_MISMATCH"
        assert app_path.read_bytes() == expected_source
        assert context_path.read_bytes() == expected_context
    finally:
        _unseal_and_remove(workspace)
        _unseal_and_remove(job_root)


@pytest.mark.asyncio
@pytest.mark.parametrize("plan_id", sorted(CANDIDATE_PLAN_IDS))
async def test_live_hostile_candidate_has_no_peer_token_control_plane_or_detached_life(
    plan_id: str,
) -> None:
    if os.environ.get("CROSSPATCH_PRODUCTION_SIDECAR_TEST") != "1":
        pytest.skip("requires the production Compose runner and candidate sidecar")
    shared_root = Path(os.environ["CROSSPATCH_CANDIDATE_WORKSPACES_ROOT"])
    private_root = Path("/var/lib/crosspatch/jobs")
    identifier = f"p0-containment-{secrets.token_hex(8)}"
    provider = "crosspatch-containment"
    workspace = shared_root / identifier
    sibling_workspace = shared_root / f"{identifier}-sibling-workspace"
    job_root = private_root / identifier
    workspace.mkdir(mode=0o700, parents=True)
    job_root.mkdir(mode=0o700, parents=True)
    database_url = os.environ["CROSSPATCH_TEST_DATABASE_URL"]
    sibling_event_id = f"sibling-{secrets.token_hex(12)}"
    live_secret = os.environ["CROSSPATCH_TEST_LIVE_VICTIM_SECRET"]

    def markers() -> set[str]:
        with psycopg.connect(database_url, autocommit=True) as connection:
            rows = connection.execute(
                """
                SELECT event_id
                  FROM webhook_receipts
                 WHERE provider = %s AND event_id LIKE %s
                """,
                (provider, f"{identifier}-%"),
            ).fetchall()
        return {str(row[0]) for row in rows}

    def clear_markers() -> None:
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                "DELETE FROM webhook_receipts WHERE provider = %s AND event_id LIKE %s",
                (provider, f"{identifier}-%"),
            )

    try:
        clear_markers()
        sibling_workspace.mkdir(mode=0o700, parents=True)
        (sibling_workspace / "sentinel.txt").write_text(
            "sibling-workspace-private", encoding="utf-8"
        )
        _seal(sibling_workspace)
        sibling_body = json.dumps(
            {
                "amount_cents": 1,
                "event_id": sibling_event_id,
                "order_id": "sibling-order",
                "provider": "acme-pay",
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        async with httpx.AsyncClient(timeout=3) as client:
            response = await client.post(
                "http://victim:8001/webhooks/order-paid",
                content=sibling_body,
                headers=signed_headers(sibling_body, live_secret),
            )
        assert response.status_code in {200, 202}
        shutil.copytree("/workspace/victim", workspace / "victim")
        shutil.copytree("/workspace/infra", workspace / "infra")
        database_path = workspace / "victim/src/victim/db.py"
        webhook_path = workspace / "victim/src/victim/webhooks.py"
        app_path = workspace / "victim/src/victim/app.py"
        app_baseline = app_path.read_bytes()
        if plan_id == "victim.duplicate-race.candidate":
            scenario_path = database_path
            scenario_relative_path = "victim/src/victim/db.py"
            scenario_baseline = database_path.read_bytes()
            patched_database = scenario_baseline.decode("utf-8")
            assert patched_database.count(_OLD) == 1
            assert patched_database.count(_OLD_RECEIPT) == 1
            database_path.write_text(
                patched_database.replace(_OLD, _NEW).replace(_OLD_RECEIPT, ""),
                encoding="utf-8",
            )
        else:
            assert plan_id == "victim.payload-equivalence.candidate"
            scenario_path = webhook_path
            scenario_relative_path = "victim/src/victim/webhooks.py"
            scenario_baseline = webhook_path.read_bytes()
            _apply_single_file_unified_patch(workspace, _PAYLOAD_EQUIVALENCE_PATCH)
        marker = "from __future__ import annotations\n"
        hostile = f'''

import os as _cp_os
from pathlib import Path as _CpPath
import errno as _cp_errno
import socket as _cp_socket
import time as _cp_time
import psycopg as _cp_psycopg

_CP_PROVIDER = {provider!r}
_CP_PREFIX = {identifier!r}
_CP_DATABASE = _cp_os.environ["CROSSPATCH_CANDIDATE_DATABASE_URL"]

try:
    _CpPath("/workspaces/{sibling_workspace.name}/sentinel.txt").read_bytes()
except (FileNotFoundError, PermissionError, OSError):
    pass
else:
    raise AssertionError("candidate could read a sibling workspace")

with _cp_psycopg.connect(_CP_DATABASE, autocommit=True) as _cp_connection:
    _cp_sibling = _cp_connection.execute(
        "SELECT payload_sha256 FROM webhook_receipts "
        "WHERE provider = %s AND event_id = %s",
        ("acme-pay", {sibling_event_id!r}),
    ).fetchone()
if _cp_sibling is not None:
    raise AssertionError("candidate could read a sibling incident row")
try:
    with _cp_psycopg.connect(_CP_DATABASE, autocommit=True) as _cp_connection:
        _cp_connection.execute(
            "INSERT INTO outbox_jobs "
            "(provider, event_id, payload, payload_sha256) "
            "VALUES (%s, %s, %s::jsonb, %s)",
            ("acme-pay", {sibling_event_id!r}, "{{}}", "0" * 64),
        )
except _cp_psycopg.errors.InsufficientPrivilege:
    pass
else:
    raise AssertionError("candidate could insert into a sibling incident")

def _cp_mark(kind):
    with _cp_psycopg.connect(_CP_DATABASE, autocommit=True) as _cp_connection:
        _cp_connection.execute(
            "INSERT INTO webhook_receipts (provider, event_id, payload_sha256) "
            "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
            (_CP_PROVIDER, f"{{_CP_PREFIX}}-{{kind}}", "0" * 64),
        )

for _cp_entry in _CpPath("/proc").iterdir():
    if not _cp_entry.name.isdigit():
        continue
    try:
        _cp_environment = (_cp_entry / "environ").read_bytes()
    except OSError:
        continue
    if b"CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN=" in _cp_environment:
        _cp_mark("peer-token-readable")
        break

for _cp_host, _cp_port, _cp_kind in (
    ("api", 8000, "api-reachable"),
    ("broker-mcp", 8012, "broker-reachable"),
    ("postgres", 5432, "control-db-reachable"),
    ("runner", 9020, "runner-reachable"),
    ("candidate-executor", 9010, "executor-tcp-reachable"),
):
    try:
        _cp_socket.getaddrinfo(_cp_host, _cp_port, type=_cp_socket.SOCK_STREAM)
        _cp_connection = _cp_socket.create_connection((_cp_host, _cp_port), timeout=0.25)
    except OSError:
        continue
    else:
        _cp_connection.close()
        _cp_mark(_cp_kind)

_cp_control = _cp_socket.socket(_cp_socket.AF_UNIX, _cp_socket.SOCK_STREAM)
try:
    _cp_control.connect("/run/crosspatch/control/executor.sock")
except OSError as _cp_error:
    if _cp_error.errno not in (_cp_errno.EACCES, _cp_errno.ENOENT):
        _cp_mark("executor-control-unexpected-error")
else:
    _cp_mark("executor-control-reachable")
finally:
    _cp_control.close()

with _cp_psycopg.connect(_CP_DATABASE, autocommit=True) as _cp_connection:
    _cp_role = _cp_connection.execute(
        "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication, "
        "rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = current_user"
    ).fetchone()
if (
    _cp_role is None
    or _cp_role[0] != "crosspatch_victim_candidate"
    or any(_cp_role[1:6])
    or _cp_role[6] is not True
):
    _cp_mark("database-role-escalated")

for _cp_statement, _cp_parameters, _cp_kind in (
    (
        "DELETE FROM webhook_receipts WHERE provider = %s AND event_id = %s",
        (_CP_PROVIDER, f"{{_CP_PREFIX}}-forbidden-delete"),
        "candidate-delete-succeeded",
    ),
    (
        "UPDATE outbox_jobs SET state = 'COMPLETED' WHERE provider = %s AND event_id = %s",
        (_CP_PROVIDER, f"{{_CP_PREFIX}}-forbidden-update"),
        "candidate-update-succeeded",
    ),
    (
        "INSERT INTO deliveries (job_id, provider, event_id, payload_sha256) "
        "VALUES (%s, %s, %s, %s)",
        (-1, _CP_PROVIDER, f"{{_CP_PREFIX}}-forbidden-delivery", "0" * 64),
        "candidate-delivery-insert-succeeded",
    ),
):
    try:
        with _cp_psycopg.connect(_CP_DATABASE, autocommit=True) as _cp_connection:
            _cp_connection.execute(_cp_statement, _cp_parameters)
    except _cp_psycopg.errors.InsufficientPrivilege:
        pass
    except _cp_psycopg.Error:
        _cp_mark(f"{{_cp_kind}}-unexpected-error")
    else:
        _cp_mark(_cp_kind)

try:
    with _cp_psycopg.connect(_CP_DATABASE, autocommit=True) as _cp_connection:
        _cp_connection.execute("COPY (SELECT 1) TO PROGRAM 'true'")
except _cp_psycopg.errors.InsufficientPrivilege:
    pass
except _cp_psycopg.Error:
    _cp_mark("copy-program-unexpected-error")
else:
    _cp_mark("copy-program-succeeded")

_cp_child = _cp_os.fork()
if _cp_child == 0:
    try:
        _cp_os.setsid()
        _cp_time.sleep(13.5)
        _cp_mark("detached-child-survived")
    finally:
        _cp_os._exit(0)
'''
        source = app_baseline.decode("utf-8")
        assert source.count(marker) == 1
        app_path.write_text(source.replace(marker, marker + hostile), encoding="utf-8")
        allowed_paths = ["victim/src/victim/app.py", scenario_relative_path]
        context_path = job_root / "candidate-context.json"
        context_path.write_text(
            json.dumps(
                {
                    "allowed_paths": allowed_paths,
                    "base_file_sha256": {
                        allowed_paths[0]: hashlib.sha256(app_baseline).hexdigest(),
                        allowed_paths[1]: hashlib.sha256(scenario_baseline).hexdigest(),
                    },
                    "base_sha": "c" * 40,
                    "candidate_file_sha256": {
                        allowed_paths[0]: hashlib.sha256(app_path.read_bytes()).hexdigest(),
                        allowed_paths[1]: hashlib.sha256(
                            scenario_path.read_bytes()
                        ).hexdigest(),
                    },
                    "candidate_root": str(workspace.resolve()),
                    "format": "crosspatch-candidate-context-v1",
                    "patch_sha256": hashlib.sha256(
                        b"crosspatch-live-hostile-containment-v1"
                    ).hexdigest(),
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        context_path.chmod(0o400)
        _seal(workspace)
        runner = await _runner_client_with_live_identity()
        receipt = await runner.run(
            PreparedWorkspace(root=workspace, context_path=context_path),
            ExecutionCatalog.default().resolve(plan_id),
        )
        await asyncio.sleep(2)

        assert receipt.passed is True
        assert receipt.candidate_executor_boot_sha256 != (
            receipt.candidate_executor_replacement_sha256
        )
        assert markers() == set()
        with psycopg.connect(database_url, autocommit=True) as connection:
            assert connection.execute(
                "SELECT count(*) FROM webhook_receipts "
                "WHERE provider = %s AND event_id = %s",
                ("acme-pay", sibling_event_id),
            ).fetchone()[0] == 1
            assert connection.execute(
                "SELECT count(*) FROM outbox_jobs "
                "WHERE provider = %s AND event_id = %s",
                ("acme-pay", sibling_event_id),
            ).fetchone()[0] == 1
    finally:
        clear_markers()
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                "DELETE FROM deliveries WHERE provider = %s AND event_id = %s",
                ("acme-pay", sibling_event_id),
            )
            connection.execute(
                "DELETE FROM outbox_jobs WHERE provider = %s AND event_id = %s",
                ("acme-pay", sibling_event_id),
            )
            connection.execute(
                "DELETE FROM webhook_receipts WHERE provider = %s AND event_id = %s",
                ("acme-pay", sibling_event_id),
            )
        _unseal_and_remove(workspace)
        _unseal_and_remove(sibling_workspace)
        _unseal_and_remove(job_root)
