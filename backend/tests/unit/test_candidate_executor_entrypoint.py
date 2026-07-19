from __future__ import annotations

import importlib.util
import inspect
import stat
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
ENTRYPOINT = ROOT / "infra" / "runner" / "candidate_executor_entrypoint.py"


@pytest.fixture
def entrypoint() -> ModuleType:
    assert ENTRYPOINT.is_file(), "the executor must use a root-owned Python bootstrap"
    spec = importlib.util.spec_from_file_location("candidate_executor_entrypoint", ENTRYPOINT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _status(
    *,
    uid: int,
    gid: int,
    groups: tuple[int, ...],
    effective: int,
    permitted: int,
    bounding: int,
    inheritable: int = 0,
    ambient: int = 0,
    no_new_privileges: int,
) -> str:
    ids = "\t".join((str(uid),) * 4)
    group_values = " ".join(str(group) for group in groups)
    return "\n".join(
        (
            f"Uid:\t{ids}",
            f"Gid:\t{'\t'.join((str(gid),) * 4)}",
            f"Groups:\t{group_values}",
            f"CapInh:\t{inheritable:016x}",
            f"CapPrm:\t{permitted:016x}",
            f"CapEff:\t{effective:016x}",
            f"CapBnd:\t{bounding:016x}",
            f"CapAmb:\t{ambient:016x}",
            f"NoNewPrivs:\t{no_new_privileges}",
        )
    )


def test_main_orders_root_preparation_demotion_verification_and_uvicorn(
    entrypoint: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        entrypoint, "_assert_root_start", lambda: calls.append("verify-root")
    )
    monkeypatch.setattr(
        entrypoint, "_prepare_runtime", lambda: calls.append("prepare-runtime")
    )
    monkeypatch.setattr(
        entrypoint.os, "umask", lambda mode: calls.append(("umask", mode))
    )
    monkeypatch.setattr(
        entrypoint, "_demote_executor", lambda: calls.append("demote-executor")
    )
    monkeypatch.setattr(
        entrypoint,
        "_set_no_new_privileges",
        lambda: calls.append("no-new-privileges"),
    )
    monkeypatch.setattr(
        entrypoint,
        "_assert_executor_status",
        lambda: calls.append("verify-executor"),
    )
    monkeypatch.setattr(
        entrypoint,
        "_run_uvicorn",
        lambda environment: calls.append(("uvicorn", environment)) or 0,
    )

    assert entrypoint.main([], environment={"SAFE": "value"}) == 0
    assert calls == [
        "verify-root",
        "prepare-runtime",
        ("umask", 0o117),
        "demote-executor",
        "no-new-privileges",
        "verify-executor",
        ("uvicorn", {"SAFE": "value"}),
    ]


def test_executor_demotion_retains_only_the_required_caps_in_order(
    entrypoint: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        entrypoint.os, "setgroups", lambda groups: calls.append(("groups", groups))
    )
    monkeypatch.setattr(
        entrypoint,
        "_set_keep_capabilities",
        lambda enabled: calls.append(("keep-caps", enabled)),
    )
    monkeypatch.setattr(
        entrypoint.os,
        "setresgid",
        lambda real, effective, saved: calls.append(
            ("gid", real, effective, saved)
        ),
        raising=False,
    )
    monkeypatch.setattr(
        entrypoint.os,
        "setresuid",
        lambda real, effective, saved: calls.append(
            ("uid", real, effective, saved)
        ),
        raising=False,
    )
    monkeypatch.setattr(
        entrypoint,
        "_set_executor_capabilities",
        lambda: calls.append("capset-exact"),
    )

    entrypoint._demote_executor()

    assert calls == [
        ("groups", [10004]),
        ("keep-caps", True),
        ("gid", 10003, 10003, 10003),
        ("uid", 10003, 10003, 10003),
        "capset-exact",
        ("keep-caps", False),
    ]


def test_status_validation_requires_root_then_exact_demoted_authority(
    entrypoint: ModuleType,
) -> None:
    mask = entrypoint.REQUIRED_CAPABILITY_MASK
    entrypoint._validate_root_status(
        _status(
            uid=0,
            gid=0,
            groups=(0,),
            effective=mask,
            permitted=mask,
            bounding=mask,
            no_new_privileges=0,
        )
    )
    entrypoint._validate_executor_status(
        _status(
            uid=10003,
            gid=10003,
            groups=(10004,),
            effective=mask,
            permitted=mask,
            bounding=mask,
            no_new_privileges=1,
        )
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("effective", 0),
        ("permitted", 0x1E0),
        ("bounding", 0x1E0),
        ("inheritable", 0xE0),
        ("ambient", 0xE0),
        ("no_new_privileges", 0),
    ),
)
def test_demoted_status_rejects_missing_extra_or_reacquirable_authority(
    entrypoint: ModuleType, field: str, value: int
) -> None:
    mask = entrypoint.REQUIRED_CAPABILITY_MASK
    values = {
        "uid": 10003,
        "gid": 10003,
        "groups": (10004,),
        "effective": mask,
        "permitted": mask,
        "bounding": mask,
        "inheritable": 0,
        "ambient": 0,
        "no_new_privileges": 1,
    }
    values[field] = value

    with pytest.raises(RuntimeError, match="executor process status"):
        entrypoint._validate_executor_status(_status(**values))


def test_runtime_preparation_installs_and_cleans_both_setgid_directories(
    entrypoint: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime_root = tmp_path / "crosspatch"
    (runtime_root / "control").mkdir(parents=True)
    (runtime_root / "control" / "stale.sock").write_text("stale", encoding="utf-8")
    (runtime_root / "app").mkdir()
    (runtime_root / "app" / "stale.sock").write_text("stale", encoding="utf-8")
    calls: list[object] = []
    monkeypatch.setattr(
        entrypoint.os,
        "setgroups",
        lambda groups: calls.append(("groups", groups)),
    )
    monkeypatch.setattr(entrypoint, "_validate_runtime_root", lambda _path: None)

    def create_executor_directory(path: Path) -> None:
        calls.append(("create", path))
        path.mkdir(mode=0o770)
        path.chmod(0o2770)

    monkeypatch.setattr(
        entrypoint, "_create_executor_directory", create_executor_directory
    )

    entrypoint._prepare_runtime(runtime_root)

    assert calls == [
        ("groups", [0, 10004]),
        ("create", runtime_root / "control"),
        ("create", runtime_root / "app"),
    ]
    assert stat.S_IMODE(runtime_root.stat().st_mode) == 0o755
    for name in ("control", "app"):
        directory = runtime_root / name
        assert stat.S_IMODE(directory.stat().st_mode) == 0o2770
        assert list(directory.iterdir()) == []


def test_runtime_preparation_does_not_require_cap_chown(entrypoint: ModuleType) -> None:
    assert "os.chown" not in inspect.getsource(entrypoint._prepare_runtime)
    assert "os.chown" not in inspect.getsource(entrypoint._create_executor_directory)


def test_uvicorn_uses_the_exact_prebound_control_socket_in_process(
    entrypoint: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []

    class FakeSocket:
        def close(self) -> None:
            calls.append("close")

    listener = FakeSocket()
    monkeypatch.setattr(
        entrypoint,
        "_open_control_socket",
        lambda path: calls.append(("bind", path)) or listener,
    )

    class FakeServer:
        started = True

        def __init__(self, config: object) -> None:
            calls.append(("server", config))

        def run(self, *, sockets: list[object]) -> None:
            calls.append(("run", sockets))

    fake_uvicorn = SimpleNamespace(
        Config=lambda app, **kwargs: (app, kwargs),
        Server=FakeServer,
    )
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    monkeypatch.setattr(entrypoint.Path, "unlink", lambda *_args, **_kwargs: None)

    result = entrypoint._run_uvicorn(
        {
            "CROSSPATCH_CANDIDATE_EXECUTOR_SOCKET": (
                "/run/crosspatch/control/executor.sock"
            )
        }
    )

    assert result == 0
    assert calls[0] == ("bind", Path("/run/crosspatch/control/executor.sock"))
    assert calls[1][0] == "server"
    app, options = calls[1][1]
    assert app == "crosspatch.runner.candidate_executor_service:create_app"
    assert options["factory"] is True
    assert calls[2] == ("run", [listener])
    assert calls[3] == "close"


def test_runner_image_installs_python_bootstrap_without_file_capability_xattrs() -> None:
    dockerfile = (ROOT / "infra" / "runner" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "candidate_executor_entrypoint.py" in dockerfile
    assert "crosspatch-candidate-executor-entrypoint" in dockerfile
    assert "security.capability" not in dockerfile
    assert "os.setxattr" not in dockerfile
