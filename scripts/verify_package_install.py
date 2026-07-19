#!/usr/bin/env python3
"""Build CrossPatch and prove the wheel works from a clean temporary environment."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        raise RuntimeError(f"clean package check failed: {argv!r}")
    return result


def main() -> int:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("UV_PROJECT_ENVIRONMENT", None)

    try:
        with tempfile.TemporaryDirectory(prefix="crosspatch-package-") as temporary:
            workspace = Path(temporary)
            distribution = workspace / "dist"
            _run(
                [
                    sys.executable,
                    "-m",
                    "build",
                    "--sdist",
                    "--wheel",
                    "--no-isolation",
                    "--outdir",
                    str(distribution),
                ],
                cwd=ROOT,
                environment=environment,
            )
            wheels = tuple(distribution.glob("crosspatch-*.whl"))
            sdists = tuple(distribution.glob("crosspatch-*.tar.gz"))
            if len(wheels) != 1 or len(sdists) != 1:
                raise RuntimeError("package build did not create exactly one wheel and one sdist")
            wheel = wheels[0]

            virtual_environment = workspace / "venv"
            sync_environment = environment | {
                "UV_PROJECT_ENVIRONMENT": str(virtual_environment)
            }
            _run(
                ["uv", "sync", "--frozen", "--no-install-project"],
                cwd=ROOT,
                environment=sync_environment,
            )
            python_relative = "Scripts/python.exe" if os.name == "nt" else "bin/python"
            python = virtual_environment / python_relative
            install = [
                "uv",
                "pip",
                "install",
                "--python",
                str(python),
                "--no-deps",
                str(wheel),
            ]
            _run(install, cwd=workspace, environment=environment)
            executable_relative = (
                "Scripts/crosspatch.exe" if os.name == "nt" else "bin/crosspatch"
            )
            executable = virtual_environment / executable_relative
            smoke = ["crosspatch", "--help"]
            # Execute the installed absolute path while recording the portable command name.
            result = _run([str(executable), "--help"], cwd=workspace, environment=environment)
            if b"Usage:" not in result.stdout or b"incident" not in result.stdout:
                raise RuntimeError("installed crosspatch --help output is incomplete")

            payload = {
                "schema_version": 1,
                "machine_generated": True,
                "wheel": wheel.name,
                "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                "sdist": sdists[0].name,
                "smoke_command": smoke,
                "smoke_output_sha256": hashlib.sha256(result.stdout).hexdigest(),
                "status": "PASS",
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
    except (OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
