from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = ROOT / "compose.yaml"
SEALED_ARCHIVE = (
    ROOT
    / "artifacts/verification/paced-batches/paced-20260714T103240Z/run-04"
    / "real-model-cases/inc_e032c6cde04f44b8a5dc6371c8c6f690.zip"
)


def _render_replay_compose() -> dict[str, Any]:
    docker = shutil.which("docker")
    assert docker is not None
    result = subprocess.run(
        [
            docker,
            "compose",
            "--env-file",
            "/dev/null",
            "--profile",
            "replay",
            "-f",
            str(COMPOSE_FILE),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env={**os.environ, "OPENAI_API_KEY": ""},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def _environment(service: dict[str, Any]) -> dict[str, str]:
    value = service.get("environment", {})
    return {str(key): str(item) for key, item in value.items()}


def _render_authority_surface(service: dict[str, Any]) -> str:
    build = service.get("build")
    repository_root = ""
    if isinstance(build, dict) and isinstance(build.get("context"), str):
        repository_root = build["context"].rstrip("/")

    def normalize(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, str) and repository_root and (
            value == repository_root or value.startswith(f"{repository_root}/")
        ):
            return f"<repository>{value[len(repository_root):]}"
        return value

    authority_surface = normalize(service)
    return json.dumps(authority_surface, sort_keys=True).lower()


def test_replay_authority_scan_excludes_only_the_host_checkout_path() -> None:
    service = {
        "build": {
            "context": "/home/runner/work/CrossPatch/CrossPatch",
            "dockerfile": "Dockerfile",
            "target": "replay-python-runtime",
        },
        "environment": {"FORBIDDEN_SHELL_ACCESS": "1"},
        "volumes": [
            {
                "source": "/home/runner/work/CrossPatch/CrossPatch/infra/Caddyfile.replay",
                "target": "/etc/caddy/Caddyfile",
                "type": "bind",
            }
        ],
    }

    rendered = _render_authority_surface(service)

    assert "/home/runner/work/CrossPatch/CrossPatch" not in rendered
    assert "<repository>/infra/caddyfile.replay" in rendered
    assert "replay-python-runtime" in rendered
    assert "forbidden_shell_access" in rendered


def test_replay_profile_is_keyless_read_only_and_authority_free() -> None:
    compose = _render_replay_compose()
    replay = {
        name: service
        for name, service in compose["services"].items()
        if service.get("profiles") == ["replay"]
    }
    assert set(replay) == {"replay-api", "replay-web", "replay-caddy"}

    for name, service in replay.items():
        assert service.get("read_only") is True, name
        rendered = _render_authority_surface(service)
        for forbidden in (
            "openai_api_key",
            "broker",
            "approval",
            "candidate-executor",
            "runner",
            "victim",
            "shell",
            "/var/run/docker.sock",
        ):
            assert forbidden not in rendered, (name, forbidden)

    api_environment = _environment(replay["replay-api"])
    assert api_environment == {
        "CROSSPATCH_REPLAY_DATABASE_URL": (
            "sqlite+aiosqlite:///file:/app/replay/replay.db?mode=ro&uri=true"
        )
    }
    assert not replay["replay-api"].get("volumes")
    assert not replay["replay-web"].get("volumes")
    assert replay["replay-caddy"]["build"]["target"] == "replay-caddy-runtime"
    assert set(replay["replay-api"]["networks"]) == {"replay"}
    assert set(replay["replay-web"]["networks"]) == {"replay"}
    assert set(replay["replay-caddy"]["networks"]) == {"replay", "replay-edge"}
    assert compose["networks"]["replay"]["internal"] is True
    assert compose["networks"]["replay-edge"].get("internal", False) is False


def test_only_replay_caddy_publishes_the_local_replay_port() -> None:
    compose = _render_replay_compose()
    replay = {
        name: service
        for name, service in compose["services"].items()
        if service.get("profiles") == ["replay"]
    }
    published = {
        name: service.get("ports", []) for name, service in replay.items() if service.get("ports")
    }
    assert set(published) == {"replay-caddy"}
    assert published["replay-caddy"] == [
        {
            "mode": "ingress",
            "target": 8080,
            "published": "8088",
            "protocol": "tcp",
            "host_ip": "127.0.0.1",
        }
    ]
    caddy = (ROOT / "infra/Caddyfile.replay").read_text(encoding="utf-8")
    assert "@published path /api/public/cases /api/public/cases/*" in caddy
    assert "handle @published" in caddy
    assert (
        "@live_only path /overview /overview/* /open-incident /open-incident/* "
        "/approvals /approvals/* /artifacts /artifacts/* /incidents /incidents/*"
        in caddy
    )
    assert "handle @live_only" in caddy
    assert caddy.count("redir * /cases 302") == 2
    assert "handle /api/*" in caddy
    assert "reverse_proxy replay-api:8000" in caddy
    assert "reverse_proxy replay-web:3000" in caddy


def test_make_replay_is_keyless_and_targets_only_the_replay_graph() -> None:
    result = subprocess.run(
        ["make", "-n", "replay"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    commands = result.stdout
    assert "replay: export OPENAI_API_KEY :=" not in commands
    assert "OPENAI_API_KEY=" in commands
    assert "--env-file /dev/null" in commands
    assert "--profile replay" in commands
    assert "up --build --detach --wait replay-caddy" in commands
    assert "python3 scripts/verify_replay.py" in commands
    assert "api broker-mcp" not in commands


def test_replay_image_is_bound_to_the_sealed_run_04_export() -> None:
    assert SEALED_ARCHIVE.is_file()
    assert SEALED_ARCHIVE.read_bytes()
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    relative = SEALED_ARCHIVE.relative_to(ROOT).as_posix()
    assert relative in dockerfile
    assert "python -m crosspatch.replay.importer" in dockerfile
    assert "chmod 0555 /app/replay" in dockerfile
    assert "FROM ${PYTHON_IMAGE} AS replay-python-base" in dockerfile
    assert "FROM replay-python-base AS replay-python-runtime" in dockerfile
    assert "ENTRYPOINT [\"/usr/local/bin/crosspatch-replay-entrypoint\"]" in dockerfile
    assert "COPY --chmod=0555 infra/replay-entrypoint.sh" in dockerfile
    assert "AS replay-caddy-runtime" in dockerfile
    assert "cp /usr/bin/caddy /usr/local/bin/caddy" in dockerfile
    assert "NEXT_PUBLIC_CROSSPATCH_REPLAY_MODE=1" in (ROOT / "compose.yaml").read_text(
        encoding="utf-8"
    )


def test_web_image_copies_the_exact_doctrine_registries_used_by_the_build() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    registry_copy = "COPY docs/CLAIM_MAP.json docs/DOCTRINE.json ./docs/"
    assert registry_copy in dockerfile
    assert dockerfile.index(registry_copy) < dockerfile.index("COPY web ./web")


def test_readme_documents_the_keyless_replay_banner_and_command() -> None:
    source = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "make replay" in source
    assert "RECORDED REPLAY — signed export, no model calls" in source
    assert "http://localhost:8088/cases" in source
