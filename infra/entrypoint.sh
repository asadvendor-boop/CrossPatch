#!/bin/sh
set -eu

service="${1:-}"
if [ "$#" -gt 0 ]; then
  shift
fi

case "$service" in
  migrate-control)
    exec python -m crosspatch.runtime.migrate "$@"
    ;;
  api)
    exec python -m uvicorn crosspatch.runtime.factories:create_control_app \
      --factory --host 0.0.0.0 --port 8000 "$@"
    ;;
  evidence-mcp)
    exec python -m uvicorn crosspatch.runtime.factories:create_evidence_mcp_app \
      --factory --host 0.0.0.0 --port 8011 "$@"
    ;;
  broker-mcp)
    exec python -m uvicorn crosspatch.runtime.factories:create_broker_mcp_app \
      --factory --host 0.0.0.0 --port 8012 "$@"
    ;;
  judge-mcp)
    exec python -m uvicorn crosspatch.runtime.factories:create_judge_mcp_app \
      --factory --host 0.0.0.0 --port 8013 "$@"
    ;;
  victim-worker)
    exec python /app/infra/victim-worker.py "$@"
    ;;
  *)
    echo "unknown CrossPatch service: $service" >&2
    exit 64
    ;;
esac
