import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest
from crosspatch.config import (
    DEFAULT_JUDGE_TOKEN_EXPIRY,
    MIN_JUDGE_TOKEN_EXPIRY,
    Settings,
    _load_or_create_judge_token_at,
    validate_judge_token_expiry,
)
from pydantic import ValidationError


def test_rejects_expiry_before_required_judge_window():
    with pytest.raises(ValueError, match="2026-08-13T07:00:00Z"):
        validate_judge_token_expiry(datetime(2026, 8, 13, 6, 59, tzinfo=UTC))


def test_accepts_expiry_at_required_judge_window():
    assert validate_judge_token_expiry(MIN_JUDGE_TOKEN_EXPIRY) == MIN_JUDGE_TOKEN_EXPIRY


def test_default_expiry_has_operational_margin():
    assert Settings().judge_token_expires_at == datetime(2026, 9, 1, 7, tzinfo=UTC)
    assert DEFAULT_JUDGE_TOKEN_EXPIRY == datetime(2026, 9, 1, 7, tzinfo=UTC)


def test_settings_only_allow_responses_api():
    assert Settings().openai_api == "responses"

    with pytest.raises(ValidationError):
        Settings(openai_api="chat_completions")


def test_generated_judge_token_is_unpredictable_and_persistent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CROSSPATCH_JUDGE_TOKEN", raising=False)

    first = Settings(_env_file=None).judge_token.get_secret_value()
    second = Settings(_env_file=None).judge_token.get_secret_value()
    token_file = Path(".crosspatch/secrets/judge-token")

    assert first == second
    assert len(first) >= 64
    assert token_file.read_text(encoding="utf-8").strip() == first
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600

    other_runtime = tmp_path / "other-runtime"
    other_runtime.mkdir()
    monkeypatch.chdir(other_runtime)
    other = Settings(_env_file=None).judge_token.get_secret_value()

    assert other != first


def test_blank_configured_judge_token_is_rejected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CROSSPATCH_JUDGE_TOKEN", "   ")

    with pytest.raises(ValidationError, match="judge token must not be blank"):
        Settings(_env_file=None)

    assert not Path(".crosspatch/secrets/judge-token").exists()


def test_existing_judge_token_permissions_are_tightened(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CROSSPATCH_JUDGE_TOKEN", raising=False)
    token_file = Path(".crosspatch/secrets/judge-token")
    token_file.parent.mkdir(parents=True)
    token_file.write_text("operator-provided-token\n", encoding="utf-8")
    token_file.chmod(0o644)

    token = Settings(_env_file=None).judge_token.get_secret_value()

    assert token == "operator-provided-token"
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600


def test_parallel_startup_publishes_one_complete_lock_backed_token(tmp_path):
    token_file = tmp_path / "secrets" / "judge-token"

    def load_token(_):
        return _load_or_create_judge_token_at(token_file).get_secret_value()

    with ThreadPoolExecutor(max_workers=12) as pool:
        tokens = list(pool.map(load_token, range(24)))

    assert len(set(tokens)) == 1
    assert token_file.read_text(encoding="utf-8").strip() == tokens[0]
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert not list(token_file.parent.glob("*.tmp"))
