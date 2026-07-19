#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
  echo "recorded replay does not accept alternate service commands" >&2
  exit 64
fi

exec python -m uvicorn crosspatch.replay.app:create_replay_app \
  --factory --host 0.0.0.0 --port 8000
