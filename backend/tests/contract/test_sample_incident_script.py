from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _module() -> ModuleType:
    path = ROOT / "scripts" / "setup_sample_incident.py"
    spec = importlib.util.spec_from_file_location("setup_sample_incident", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sample_script_uses_documented_default_only_for_loopback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _module()
    monkeypatch.delenv("CROSSPATCH_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("CROSSPATCH_TOKEN", raising=False)
    monkeypatch.setattr(module, "ROOT", tmp_path)

    assert module.token_value(local=True) == module.LOCAL_COMPOSE_OPERATOR_TOKEN
    with pytest.raises(RuntimeError, match="CROSSPATCH_OPERATOR_TOKEN"):
        module.token_value(local=False)


def test_sample_script_prefers_an_explicit_operator_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _module()
    monkeypatch.setenv("CROSSPATCH_OPERATOR_TOKEN", "explicit-operator-token")
    monkeypatch.setattr(module, "ROOT", tmp_path)

    assert module.token_value(local=False) == "explicit-operator-token"


def test_loopback_compose_ignores_a_stale_generated_runtime_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _module()
    monkeypatch.delenv("CROSSPATCH_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("CROSSPATCH_TOKEN", raising=False)
    secret = tmp_path / ".crosspatch" / "secrets" / "operator-token"
    secret.parent.mkdir(parents=True)
    secret.write_text("stale-direct-runtime-token", encoding="utf-8")
    monkeypatch.setattr(module, "ROOT", tmp_path)

    assert module.token_value(local=True) == module.LOCAL_COMPOSE_OPERATOR_TOKEN
