from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import httpx
import pytest
from crosspatch.cli.client import CrossPatchClient, StreamEvent
from crosspatch.cli.main import app
from typer.testing import CliRunner


@pytest.mark.parametrize(
    "base_url",
    (
        "http://localhost.evidence.invalid",
        "http://127.0.0.1.evidence.invalid",
        "http://localhost@evidence.invalid",
    ),
)
def test_http_client_rejects_loopback_prefix_hosts_before_bearer_configuration(
    base_url: str,
) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        CrossPatchClient(
            base_url=base_url,
            token="must-not-leave-loopback",
            origin="https://localhost",
        )


class _FakeClient:
    def __init__(self) -> None:
        self.approved: list[tuple[str, str]] = []
        self.rejected: list[tuple[str, str]] = []
        self.opened: list[str] = []
        self.rotated = False
        self.revoked_token_ids: list[str] = []

    def get_warrant(self, warrant_id: str) -> dict[str, object]:
        document = '{"id":"war_1"}'
        return {
            "id": warrant_id,
            "incident_id": "inc-a",
            "status": "PENDING_APPROVAL",
            "canonical_document": document,
            "warrant_sha256": hashlib.sha256(document.encode("ascii")).hexdigest(),
        }

    def approve_warrant(self, warrant_id: str, warrant_sha256: str) -> dict[str, object]:
        self.approved.append((warrant_id, warrant_sha256))
        return {"status": "APPROVED"}

    def reject_warrant(self, warrant_id: str, warrant_sha256: str) -> dict[str, object]:
        self.rejected.append((warrant_id, warrant_sha256))
        return {"status": "REJECTED"}

    def open_incident(self, scenario: str) -> dict[str, object]:
        self.opened.append(scenario)
        return {"id": "inc-new", "scenario": scenario, "state": "OPEN"}

    def stream_room(self, incident_id: str, last_event_id: str | None = None):
        assert incident_id == "inc-a"
        assert last_event_id is None
        yield StreamEvent(id="1", event="INCIDENT_OPENED", data={"summary": "Opened"})

    def export_case(self, incident_id: str) -> bytes:
        assert incident_id == "inc-a"
        return b"PK-case"

    def rotate_judge_token(self, incident_id: str) -> dict[str, object]:
        assert incident_id == "inc-a"
        self.rotated = True
        return {"token": "judge-token", "expires_at": "2099-01-01T00:00:00Z"}

    def list_judge_tokens(self) -> dict[str, object]:
        return {
            "tokens": [
                {
                    "token_id": "judge-runtime-jti-1",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "revoked": False,
                }
            ]
        }

    def revoke_judge_token(self, token_id: str) -> dict[str, object]:
        self.revoked_token_ids.append(token_id)
        return {"token_id": token_id, "revoked": True}


def test_cli_approval_requires_explicit_confirmation() -> None:
    client = _FakeClient()
    result = CliRunner().invoke(
        app,
        ["warrant", "approve", "war_1"],
        input="no\n",
        obj=client,
    )

    assert result.exit_code == 1
    assert "Approval cancelled" in result.stdout
    assert client.approved == []


def test_cli_renders_exact_warrant_and_binds_approval_to_its_hash() -> None:
    client = _FakeClient()
    result = CliRunner().invoke(
        app,
        ["warrant", "approve", "war_1"],
        input="yes\n",
        obj=client,
    )

    assert result.exit_code == 0
    assert '{"id":"war_1"}' in result.stdout
    expected_hash = hashlib.sha256(b'{"id":"war_1"}').hexdigest()
    assert client.approved == [("war_1", expected_hash)]


def test_cli_refuses_mismatched_canonical_warrant_hash() -> None:
    client = _FakeClient()

    def mismatched(_: str) -> dict[str, object]:
        return {
            "id": "war_1",
            "incident_id": "inc-a",
            "status": "PENDING_APPROVAL",
            "canonical_document": '{"id":"war_1"}',
            "warrant_sha256": "0" * 64,
        }

    client.get_warrant = mismatched  # type: ignore[method-assign]
    result = CliRunner().invoke(
        app,
        ["warrant", "approve", "war_1"],
        input="yes\n",
        obj=client,
    )

    assert result.exit_code != 0
    assert client.approved == []


def test_cli_exposes_exact_command_tree_and_uses_http_not_database() -> None:
    runner = CliRunner()
    for command in ("incident", "room", "warrant", "case", "judge-token"):
        assert command in runner.invoke(app, ["--help"]).stdout
    assert "open" in runner.invoke(app, ["incident", "--help"]).stdout
    assert "stream" in runner.invoke(app, ["room", "--help"]).stdout
    warrant_help = runner.invoke(app, ["warrant", "--help"]).stdout
    assert "approve" in warrant_help and "reject" in warrant_help
    assert "export" in runner.invoke(app, ["case", "--help"]).stdout
    judge_token_help = runner.invoke(app, ["judge-token", "--help"]).stdout
    assert all(command in judge_token_help for command in ("list", "rotate", "revoke"))

    import crosspatch.cli.client as client_module

    assert "crosspatch.db" not in inspect.getsource(client_module)


def test_cli_defaults_to_the_only_public_caddy_endpoint(monkeypatch) -> None:
    import crosspatch.cli.main as main_module

    captured: dict[str, object] = {}

    def build_client(**kwargs):
        captured.update(kwargs)
        return _FakeClient()

    for name in (
        "CROSSPATCH_API_URL",
        "CROSSPATCH_ORIGIN",
        "CROSSPATCH_CSRF_TOKEN",
        "CROSSPATCH_STEP_UP_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CROSSPATCH_TOKEN", "local-operator-token")
    monkeypatch.setattr(main_module, "CrossPatchClient", build_client)

    result = CliRunner().invoke(app, ["incident", "open", "webhook-race"])

    assert result.exit_code == 0
    assert captured["base_url"] == "https://localhost"
    assert captured["origin"] == "https://localhost"
    assert "127.0.0.1:8000" not in json.dumps(captured)


def test_cli_open_stream_export_and_rotate_use_shared_http_client(tmp_path: Path) -> None:
    client = _FakeClient()
    runner = CliRunner()

    opened = runner.invoke(app, ["incident", "open", "webhook-race"], obj=client)
    streamed = runner.invoke(app, ["room", "stream", "inc-a"], obj=client)
    output = tmp_path / "case.zip"
    exported = runner.invoke(
        app,
        ["case", "export", "inc-a", "--output", str(output)],
        obj=client,
    )
    rotated = runner.invoke(
        app,
        ["judge-token", "rotate", "inc-a"],
        input="yes\n",
        obj=client,
    )

    assert opened.exit_code == streamed.exit_code == exported.exit_code == rotated.exit_code == 0
    assert json.loads(opened.stdout)["id"] == "inc-new"
    assert "Opened" in streamed.stdout
    assert output.read_bytes() == b"PK-case"
    assert client.rotated is True


def test_cli_lists_and_explicitly_revokes_judge_token_by_id() -> None:
    client = _FakeClient()
    runner = CliRunner()

    listed = runner.invoke(app, ["judge-token", "list"], obj=client)
    cancelled = runner.invoke(
        app,
        ["judge-token", "revoke", "judge-runtime-jti-1"],
        input="no\n",
        obj=client,
    )
    revoked = runner.invoke(
        app,
        ["judge-token", "revoke", "judge-runtime-jti-1"],
        input="yes\n",
        obj=client,
    )

    assert listed.exit_code == 0
    assert "judge-runtime-jti-1" in listed.stdout
    assert cancelled.exit_code == 1
    assert revoked.exit_code == 0
    assert client.revoked_token_ids == ["judge-runtime-jti-1"]


def test_http_client_judge_token_lifecycle_uses_approval_controls() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"tokens": []})
        return httpx.Response(
            200,
            json={
                "token_id": "judge-runtime-jti-1",
                "expires_at": "2099-01-01T00:00:00Z",
                "revoked": True,
                "created_at": "2026-07-14T12:00:00Z",
                "revoked_at": "2026-07-14T12:01:00Z",
            },
        )

    client = CrossPatchClient(
        base_url="https://crosspatch.test",
        token="approver-token",
        origin="https://crosspatch.test",
        csrf_token="csrf-value",
        step_up_token="step-value",
        transport=httpx.MockTransport(handler),
    )

    client.rotate_judge_token("inc-a")
    client.list_judge_tokens()
    client.revoke_judge_token("judge-runtime-jti-1")

    assert captured[0].url.path == "/api/judge-tokens/rotate"
    assert captured[0].read() == b'{"confirmation":"ROTATE","incident_id":"inc-a"}'
    assert captured[1].url.path == "/api/judge-tokens"
    assert captured[2].url.path == "/api/judge-tokens/judge-runtime-jti-1/revoke"
    assert captured[2].headers["origin"] == "https://crosspatch.test"
    assert captured[2].headers["x-csrf-token"] == "csrf-value"
    assert captured[2].headers["x-crosspatch-step-up"] == "step-value"


def test_http_client_sends_bearer_origin_csrf_and_step_up_headers() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "id": "war_1",
                    "incident_id": "inc-a",
                    "status": "PENDING_APPROVAL",
                    "canonical_document": "{}",
                    "warrant_sha256": "a" * 64,
                },
            )
        return httpx.Response(200, json={"status": "APPROVED"})

    client = CrossPatchClient(
        base_url="https://crosspatch.test",
        token="operator-token",
        origin="https://crosspatch.test",
        csrf_token="csrf-value",
        step_up_token="step-value",
        transport=httpx.MockTransport(handler),
    )
    client.get_warrant("war_1")
    client.approve_warrant("war_1", "a" * 64)

    assert captured[0].headers["authorization"] == "Bearer operator-token"
    assert "operator-token" not in str(captured[0].url)
    assert captured[1].headers["origin"] == "https://crosspatch.test"
    assert captured[1].headers["x-csrf-token"] == "csrf-value"
    assert captured[1].headers["x-crosspatch-step-up"] == "step-value"


def test_http_room_stream_is_lazy_and_yields_before_connection_closes() -> None:
    consumed: list[int] = []

    class RecordingStream(httpx.SyncByteStream):
        def __iter__(self):
            consumed.append(1)
            yield b'id: 1\nevent: TEST\ndata: {"summary":"first"}\n\n'
            consumed.append(2)
            yield b'id: 2\nevent: TEST\ndata: {"summary":"second"}\n\n'

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=RecordingStream())

    client = CrossPatchClient(
        base_url="https://crosspatch.test",
        token="reader-token",
        origin="https://crosspatch.test",
        transport=httpx.MockTransport(handler),
    )
    events = client.stream_room("inc-a")

    assert consumed == []
    assert next(iter(events)).id == "1"
    assert consumed == [1]
