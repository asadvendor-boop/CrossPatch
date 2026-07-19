from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from crosspatch.runner.secrets import INSECURE_VICTIM_DATABASE_PASSWORDS

ROOT = Path(__file__).resolve().parents[3]


def _module() -> ModuleType:
    path = ROOT / "infra" / "victim-worker.py"
    spec = importlib.util.spec_from_file_location("crosspatch_victim_worker", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("password", sorted(INSECURE_VICTIM_DATABASE_PASSWORDS))
def test_worker_release_startup_rejects_every_repository_known_database_password(
    monkeypatch: pytest.MonkeyPatch,
    password: str,
) -> None:
    module = _module()
    monkeypatch.setenv("CROSSPATCH_RELEASE_MODE", "1")
    monkeypatch.setenv(
        "VICTIM_DATABASE_URL",
        f"postgresql://crosspatch_victim:{password}@victim-postgres:5432/crosspatch_victim",
    )

    with pytest.raises(ValueError, match="release mode"):
        module._validated_database_url()


def test_worker_release_startup_accepts_a_random_database_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    value = (
        "postgresql://crosspatch_victim:Strong-DB-pass-A1b2C3d4E5f6@"
        "victim-postgres:5432/crosspatch_victim"
    )
    monkeypatch.setenv("CROSSPATCH_RELEASE_MODE", "1")
    monkeypatch.setenv("VICTIM_DATABASE_URL", value)

    assert module._validated_database_url() == value


def test_worker_uses_the_preprovisioned_least_privilege_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    calls: list[object] = []

    class FakeDatabase:
        def __init__(self, dsn: str) -> None:
            calls.append(("database", dsn))

    class FakeWorker:
        def __init__(self, database: object) -> None:
            calls.append(("worker", database))

    monkeypatch.setattr(module, "_validated_database_url", lambda: "postgresql://app")
    monkeypatch.setattr(module, "Database", FakeDatabase)
    monkeypatch.setattr(module, "DeliveryWorker", FakeWorker)
    monkeypatch.setattr(module.signal, "signal", lambda *_args: None)
    module.running = False

    assert module.main() == 0
    assert calls[0] == ("database", "postgresql://app")
    assert calls[1][0] == "worker"
