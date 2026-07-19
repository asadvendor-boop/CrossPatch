#!/usr/bin/env bash
set -euo pipefail

# Canonical artifact: artifacts/verification/hosted-acceptance.json
# Required authority: CROSSPATCH_PUBLIC_URL and CROSSPATCH_JUDGE_TOKEN.
# Required availability window: 2026-08-13T07:00:00Z.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec uv run --frozen --extra dev python scripts/hosted_verifier.py "$@"
