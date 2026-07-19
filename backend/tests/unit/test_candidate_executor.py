from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import stat
from datetime import UTC, datetime
from pathlib import Path

import crosspatch.runner.candidate_executor as candidate_executor
import crosspatch.runner.candidate_executor_service as candidate_service
import crosspatch.runner.candidate_service as candidate_runtime_service
import httpx
import pytest
from crosspatch.domain.hashing import canonical_json
from crosspatch.runner.candidate_executor import (
    SidecarCandidateExecutor,
    SidecarPolicyViolation,
    build_production_supervisor_from_environment,
)
from crosspatch.runner.candidate_executor_service import (
    _candidate_environment,
    _open_candidate_listener,
    _prepare_candidate_process,
    _resolve_candidate_plan_binding,
)
from crosspatch.runner.candidate_service import _validate_linux_sandbox_status
from crosspatch.runner.catalog import CANDIDATE_PLAN_IDS, ExecutionCatalog


def _boot_mac(token: str, boot_id: str, candidate_uid: int = 10002) -> str:
    return hmac.new(
        token.encode("utf-8"),
        b"crosspatch-candidate-executor-boot-v1\x00"
        + canonical_json(
            {
                "boot_id": boot_id,
                "candidate_uid": candidate_uid,
                "service_role": "candidate-executor",
            }
        ),
        hashlib.sha256,
    ).hexdigest()


def _short_unix_path(name: str) -> Path:
    return Path.home().resolve() / f".cp-{secrets.token_hex(6)}-{name}"


@pytest.mark.parametrize("plan_id", sorted(CANDIDATE_PLAN_IDS))
def test_candidate_executor_service_resolves_only_exact_candidate_bindings(
    plan_id: str,
) -> None:
    plan = ExecutionCatalog.default().resolve(plan_id)

    assert _resolve_candidate_plan_binding(plan.plan_id, plan.sha256) == plan
    with pytest.raises(ValueError, match="candidate execution plan binding"):
        _resolve_candidate_plan_binding(plan.plan_id, "0" * 64)


def test_candidate_executor_service_rejects_non_candidate_binding() -> None:
    plan = ExecutionCatalog.default().resolve("victim.single-delivery")

    with pytest.raises(ValueError, match="candidate execution plan binding"):
        _resolve_candidate_plan_binding(plan.plan_id, plan.sha256)


@pytest.mark.asyncio
@pytest.mark.parametrize("plan_id", sorted(CANDIDATE_PLAN_IDS))
async def test_sidecar_executor_sends_only_a_workspace_key_and_catalog_binding(
    tmp_path: Path,
    plan_id: str,
) -> None:
    shared_root = tmp_path / "shared-workspaces"
    workspace = shared_root / "war-123"
    workspace.mkdir(parents=True)
    (workspace / "candidate.py").write_text("print('candidate')", encoding="utf-8")
    handoff_root = tmp_path / "candidate-handoff"
    handoff_root.mkdir()
    captured: dict[str, object] = {}
    now = datetime.now(UTC).isoformat()
    token = "t" * 32
    old_boot = "cpb-" + "1" * 32
    new_boot = "cpb-" + "2" * 32
    health_calls = 0

    async def respond(request: httpx.Request) -> httpx.Response:
        nonlocal health_calls
        if request.url.path == "/health":
            health_calls += 1
            boot_id = old_boot if health_calls == 1 else new_boot
            return httpx.Response(
                200,
                json={
                    "boot_id": boot_id,
                    "boot_mac_sha256": _boot_mac(token, boot_id),
                    "candidate_uid": 10002,
                    "service_role": "candidate-executor",
                },
            )
        captured["headers"] = dict(request.headers)
        captured["payload"] = json.loads(request.content)
        staged = handoff_root / captured["payload"]["workspace_key"]
        assert staged.is_dir()
        assert (staged / "candidate.py").read_text(encoding="utf-8") == "print('candidate')"
        return httpx.Response(
            200,
            json={
                "plan_id": plan_id,
                "runtime_id": captured["payload"]["runtime_id"],
                "exit_code": 0,
                "timed_out": False,
                "started_at": now,
                "finished_at": now,
                "stdout_sha256": "1" * 64,
                "stderr_sha256": "2" * 64,
                "stdout_bytes": 17,
                "stderr_bytes": 0,
                "executor_boot_id": old_boot,
                "executor_boot_mac_sha256": _boot_mac(token, old_boot),
            },
        )

    executor = SidecarCandidateExecutor(
        control_url="http://candidate-executor:9010",
        auth_token=token,
        shared_workspace_root=shared_root,
        handoff_workspace_root=handoff_root,
        candidate_uid=10002,
        transport=httpx.MockTransport(respond),
    )
    plan = ExecutionCatalog.default().resolve(plan_id)

    attempt = await executor.execute(workspace, plan, {})

    payload = captured["payload"]
    assert payload["workspace_key"] == payload["runtime_id"]
    assert payload["plan_id"] == plan.plan_id
    assert payload["plan_sha256"] == plan.sha256
    assert payload["environment"] == {}
    rendered = json.dumps(payload, sort_keys=True)
    assert str(workspace) not in rendered
    assert "candidate-context" not in rendered
    assert captured["headers"]["authorization"] == f"Bearer {token}"
    assert attempt.candidate_uid == 10002
    assert attempt.pid_namespace_isolated is True
    assert attempt.workspace_read_only is True
    assert attempt.context_capability_absent is True
    assert attempt.external_receipt_authority is True
    assert attempt.teardown_verified is True
    assert attempt.executor_boot_sha256 == hashlib.sha256(old_boot.encode()).hexdigest()
    assert attempt.replacement_boot_sha256 == hashlib.sha256(new_boot.encode()).hexdigest()
    assert health_calls >= 2
    assert list(handoff_root.iterdir()) == [handoff_root / ".execution.lock"]


@pytest.mark.asyncio
async def test_sidecar_executor_rejects_non_candidate_before_workspace_or_transport(
    tmp_path: Path,
) -> None:
    shared_root = tmp_path / "shared-workspaces"
    handoff_root = tmp_path / "candidate-handoff"
    shared_root.mkdir()
    handoff_root.mkdir()
    transport_calls = 0

    def reject_transport(_request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        pytest.fail("non-candidate plan reached the sidecar transport")

    executor = SidecarCandidateExecutor(
        control_url="http://candidate-executor:9010",
        auth_token="t" * 32,
        shared_workspace_root=shared_root,
        handoff_workspace_root=handoff_root,
        candidate_uid=10002,
        transport=httpx.MockTransport(reject_transport),
    )
    non_candidate = ExecutionCatalog.default().resolve("victim.single-delivery")

    with pytest.raises(SidecarPolicyViolation, match="trusted candidate sidecar"):
        await executor.execute(shared_root / "missing", non_candidate, {})

    assert transport_calls == 0
    assert list(handoff_root.iterdir()) == [handoff_root / ".execution.lock"]


@pytest.mark.asyncio
async def test_sidecar_executor_rejects_a_replayed_boot_identity_after_execute(
    tmp_path: Path,
) -> None:
    shared_root = tmp_path / "shared-workspaces"
    workspace = shared_root / "war-123"
    workspace.mkdir(parents=True)
    handoff_root = tmp_path / "candidate-handoff"
    handoff_root.mkdir()
    token = "t" * 32
    boot_id = "cpb-" + "1" * 32
    now = datetime.now(UTC).isoformat()

    async def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(
                200,
                json={
                    "boot_id": boot_id,
                    "boot_mac_sha256": _boot_mac(token, boot_id),
                    "candidate_uid": 10002,
                    "service_role": "candidate-executor",
                },
            )
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "plan_id": payload["plan_id"],
                "runtime_id": payload["runtime_id"],
                "exit_code": 0,
                "timed_out": False,
                "started_at": now,
                "finished_at": now,
                "stdout_sha256": "1" * 64,
                "stderr_sha256": "2" * 64,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "executor_boot_id": boot_id,
                "executor_boot_mac_sha256": _boot_mac(token, boot_id),
            },
        )

    executor = SidecarCandidateExecutor(
        control_url="http://candidate-executor:9010",
        auth_token=token,
        shared_workspace_root=shared_root,
        handoff_workspace_root=handoff_root,
        candidate_uid=10002,
        transport=httpx.MockTransport(respond),
        lifecycle_timeout_seconds=0.05,
    )

    with pytest.raises(SidecarPolicyViolation, match="replacement boot"):
        await executor.execute(
            workspace,
            ExecutionCatalog.default().resolve("victim.duplicate-race.candidate"),
            {},
        )


@pytest.mark.asyncio
async def test_sidecar_executor_rejects_workspace_outside_shared_mount(
    tmp_path: Path,
) -> None:
    shared_root = tmp_path / "shared"
    shared_root.mkdir()
    handoff_root = tmp_path / "handoff"
    handoff_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    executor = SidecarCandidateExecutor(
        control_url="http://candidate-executor:9010",
        auth_token="t" * 32,
        shared_workspace_root=shared_root,
        handoff_workspace_root=handoff_root,
        candidate_uid=10002,
        transport=httpx.MockTransport(
            lambda _request: pytest.fail("invalid workspace reached the sidecar")
        ),
    )

    with pytest.raises(SidecarPolicyViolation, match="shared workspace root"):
        await executor.execute(
            outside,
            ExecutionCatalog.default().resolve("victim.duplicate-race.candidate"),
            {},
        )


def test_production_supervisor_factory_fails_closed_without_complete_isolation_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("crosspatch.runner.candidate_executor.os.geteuid", lambda: 10001)

    with pytest.raises(SidecarPolicyViolation, match="required"):
        build_production_supervisor_from_environment({})


def test_production_supervisor_factory_rejects_wrong_runtime_uid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("crosspatch.runner.candidate_executor.os.geteuid", lambda: 10002)
    environment = {
        "CROSSPATCH_CANDIDATE_EXECUTOR_URL": "http://candidate-executor:9010",
        "CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN": "t" * 32,
        "CROSSPATCH_CANDIDATE_TARGET_URL": "http://candidate-executor:8002",
        "CROSSPATCH_CANDIDATE_UID": "10002",
        "CROSSPATCH_SUPERVISOR_UID": "10001",
        "CROSSPATCH_CANDIDATE_HANDOFF_ROOT": str(tmp_path),
        "CROSSPATCH_CANDIDATE_WORKSPACES_ROOT": str(tmp_path),
        "CROSSPATCH_TEST_DATABASE_URL": (
            "postgresql://crosspatch_victim_oracle@oracle.invalid/crosspatch"
        ),
        "CROSSPATCH_WORKER_DATABASE_URL": (
            "postgresql://crosspatch_victim_worker@worker.invalid/crosspatch"
        ),
    }

    with pytest.raises(SidecarPolicyViolation, match="supervisor UID"):
        build_production_supervisor_from_environment(environment)


def test_production_supervisor_requires_executor_and_candidate_unix_sockets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("crosspatch.runner.candidate_executor.os.geteuid", lambda: 10001)
    environment = {
        "CROSSPATCH_CANDIDATE_EXECUTOR_URL": "http://candidate-executor",
        "CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN": "t" * 32,
        "CROSSPATCH_CANDIDATE_TARGET_URL": "http://candidate",
        "CROSSPATCH_CANDIDATE_UID": "10002",
        "CROSSPATCH_SUPERVISOR_UID": "10001",
        "CROSSPATCH_CANDIDATE_HANDOFF_ROOT": str(tmp_path),
        "CROSSPATCH_CANDIDATE_WORKSPACES_ROOT": str(tmp_path),
        "CROSSPATCH_TEST_DATABASE_URL": (
            "postgresql://crosspatch_victim_oracle@oracle.invalid/crosspatch"
        ),
        "CROSSPATCH_WORKER_DATABASE_URL": (
            "postgresql://crosspatch_victim_worker@worker.invalid/crosspatch"
        ),
    }

    with pytest.raises(
        SidecarPolicyViolation, match="CROSSPATCH_CANDIDATE_EXECUTOR_SOCKET"
    ):
        build_production_supervisor_from_environment(environment)

    environment["CROSSPATCH_CANDIDATE_EXECUTOR_SOCKET"] = (
        "/run/crosspatch/control/executor.sock"
    )
    with pytest.raises(
        SidecarPolicyViolation, match="CROSSPATCH_CANDIDATE_TARGET_SOCKET"
    ):
        build_production_supervisor_from_environment(environment)


def test_sidecar_explicit_test_transport_takes_precedence_over_unix_socket(
    tmp_path: Path,
) -> None:
    shared_root = tmp_path / "workspaces"
    shared_root.mkdir()
    handoff_root = tmp_path / "handoff"
    handoff_root.mkdir()
    socket_path = _short_unix_path("executor.sock")

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    transport = httpx.MockTransport(lambda _request: httpx.Response(200))
    try:
        executor = SidecarCandidateExecutor(
            control_url="http://candidate-executor",
            auth_token="t" * 32,
            shared_workspace_root=shared_root,
            handoff_workspace_root=handoff_root,
            candidate_uid=10002,
            control_socket=socket_path,
            transport=transport,
        )

        assert executor._request_transport() is transport
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)


def test_sidecar_builds_httpx_unix_socket_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared_root = tmp_path / "workspaces"
    shared_root.mkdir()
    handoff_root = tmp_path / "handoff"
    handoff_root.mkdir()
    socket_path = _short_unix_path("executor.sock")

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    captured: dict[str, str] = {}
    expected = httpx.MockTransport(lambda _request: httpx.Response(200))
    monkeypatch.setattr(
        candidate_executor.httpx,
        "AsyncHTTPTransport",
        lambda *, uds: captured.update(uds=uds) or expected,
    )
    try:
        executor = SidecarCandidateExecutor(
            control_url="http://candidate-executor",
            auth_token="t" * 32,
            shared_workspace_root=shared_root,
            handoff_workspace_root=handoff_root,
            candidate_uid=10002,
            control_socket=socket_path,
        )

        assert executor._request_transport() is expected
        assert captured == {"uds": str(socket_path)}
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)


def test_candidate_process_imports_runtime_only_from_the_immutable_image_path() -> None:
    workspace = Path("/workspaces/candidate-123")
    app_socket = Path("/run/crosspatch/app/candidate.sock")

    environment = _candidate_environment(
        database_url="postgresql://candidate.invalid/crosspatch",
        workspace=workspace,
        candidate_app_socket=app_socket,
        candidate_socket_fd=9,
        candidate_uid=10002,
        executor_uid=10003,
        executor_pid=321,
        run_seconds=12,
        challenge={
            "CROSSPATCH_VERIFICATION_SCOPE_EVENT_ID": "cpv-" + "a" * 32,
            "CROSSPATCH_VERIFICATION_SCOPE_PROVIDER": "acme-pay",
            "CROSSPATCH_VERIFICATION_SIGNING_SECRET": "ephemeral-" + "s" * 40,
        },
    )

    assert environment["PYTHONPATH"] == "/opt/crosspatch/src"
    assert str(workspace) not in environment["PYTHONPATH"]
    assert environment["CROSSPATCH_CANDIDATE_UID"] == "10002"
    assert environment["CROSSPATCH_CANDIDATE_APP_SOCKET"] == str(app_socket)
    assert environment["CROSSPATCH_CANDIDATE_SOCKET_FD"] == "9"
    assert environment["CROSSPATCH_CANDIDATE_WEBHOOK_SECRET"] == (
        "ephemeral-" + "s" * 40
    )
    assert environment["CROSSPATCH_EXECUTOR_UID"] == "10003"
    assert environment["CROSSPATCH_EXECUTOR_PID"] == "321"
    assert "CROSSPATCH_CANDIDATE_PORT" not in environment
    assert "CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN" not in environment
    assert "CROSSPATCH_VERIFICATION_SCOPE_EVENT_ID" not in environment
    assert "CROSSPATCH_VERIFICATION_SCOPE_PROVIDER" not in environment
    assert "CROSSPATCH_VERIFICATION_SIGNING_SECRET" not in environment


def test_candidate_listener_requires_and_preserves_exact_setgid_socket_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_root = _short_unix_path("app")
    app_root.mkdir()
    app_root.chmod(0o2770)
    runtime_gid = app_root.stat().st_gid
    monkeypatch.setattr(candidate_service, "_CANDIDATE_RUNTIME_GID", runtime_gid)
    socket_path = app_root / "candidate.sock"

    listener = _open_candidate_listener(socket_path)
    try:
        metadata = socket_path.lstat()
        assert listener.family == socket.AF_UNIX
        assert metadata.st_uid == os.geteuid()
        assert metadata.st_gid == runtime_gid
        assert stat.S_IMODE(metadata.st_mode) == 0o660
        candidate_runtime_service._validate_candidate_listener(
            listener,
            socket_path=socket_path,
        )
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)
        app_root.rmdir()


def test_candidate_listener_rejects_non_setgid_runtime_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_root = _short_unix_path("app")
    app_root.mkdir(mode=0o770)
    app_root.chmod(0o770)
    monkeypatch.setattr(
        candidate_service, "_CANDIDATE_RUNTIME_GID", app_root.stat().st_gid
    )

    try:
        with pytest.raises(RuntimeError, match="parent policy"):
            _open_candidate_listener(app_root / "candidate.sock")
    finally:
        app_root.rmdir()


def test_candidate_identity_is_dropped_before_child_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        candidate_service,
        "_drop_candidate_identity",
        lambda *, candidate_uid, candidate_gid: calls.append(
            ("identity", candidate_uid, candidate_gid)
        ),
    )
    monkeypatch.setattr(
        candidate_service,
        "_apply_child_limits",
        lambda timeout, output: calls.append(("limits", timeout, output)),
    )

    _prepare_candidate_process(10002, 10002, 120)

    assert calls == [
        ("identity", 10002, 10002),
        ("limits", 120, 2 * 1024 * 1024),
    ]


def test_candidate_child_irreversibly_drops_groups_ids_and_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    state = {"uid": (10003, 10003, 10003), "gid": (10003, 10003, 10003)}

    monkeypatch.setattr(
        candidate_service.os,
        "setgroups",
        lambda groups: calls.append(("groups", tuple(groups))),
    )

    def setresgid(real: int, effective: int, saved: int) -> None:
        state["gid"] = (real, effective, saved)
        calls.append(("gid", real, effective, saved))

    def setresuid(real: int, effective: int, saved: int) -> None:
        state["uid"] = (real, effective, saved)
        calls.append(("uid", real, effective, saved))

    monkeypatch.setattr(candidate_service.os, "setresgid", setresgid, raising=False)
    monkeypatch.setattr(candidate_service.os, "setresuid", setresuid, raising=False)
    monkeypatch.setattr(
        candidate_service.os,
        "getresgid",
        lambda: state["gid"],
        raising=False,
    )
    monkeypatch.setattr(
        candidate_service.os,
        "getresuid",
        lambda: state["uid"],
        raising=False,
    )
    monkeypatch.setattr(candidate_service.os, "getgroups", lambda: [])
    monkeypatch.setattr(
        candidate_service,
        "_drop_capability_sets",
        lambda: calls.append(("capabilities",)),
        raising=False,
    )
    monkeypatch.setattr(
        candidate_service,
        "_set_no_new_privileges",
        lambda: calls.append(("no-new-privileges",)),
        raising=False,
    )

    drop = getattr(candidate_service, "_drop_candidate_identity")
    drop(candidate_uid=10002, candidate_gid=10002)

    assert ("groups", ()) in calls
    assert ("gid", 10002, 10002, 10002) in calls
    assert ("uid", 10002, 10002, 10002) in calls
    assert ("capabilities",) in calls
    assert ("no-new-privileges",) in calls
    assert calls.index(("capabilities",)) < calls.index(("no-new-privileges",))
    assert state == {"uid": (10002, 10002, 10002), "gid": (10002, 10002, 10002)}


def test_candidate_runtime_requires_zero_capabilities_and_no_new_privileges() -> None:
    status = """\
Uid:\t10002\t10002\t10002\t10002
Gid:\t10002\t10002\t10002\t10002
Groups:\t
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t00000000000000e0
CapAmb:\t0000000000000000
NoNewPrivs:\t1
"""

    _validate_linux_sandbox_status(status, expected_uid=10002, expected_gid=10002)
    _validate_linux_sandbox_status(
        status.replace("Groups:\t", "Groups:\t10002"),
        expected_uid=10002,
        expected_gid=10002,
    )

    with pytest.raises(RuntimeError, match="capabilities"):
        _validate_linux_sandbox_status(
            status.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000080"),
            expected_uid=10002,
            expected_gid=10002,
        )
