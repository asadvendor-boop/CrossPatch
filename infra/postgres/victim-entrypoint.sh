#!/bin/sh
set -eu

release_mode=$(printf '%s' "${CROSSPATCH_RELEASE_MODE:-0}" | tr '[:upper:]' '[:lower:]')

case "$release_mode" in
  1|true|yes)
    admin_secret=${CROSSPATCH_VICTIM_POSTGRES_ADMIN_PASSWORD:-}
    app_secret=${CROSSPATCH_VICTIM_APP_PASSWORD:-}
    candidate_secret=${CROSSPATCH_VICTIM_CANDIDATE_PASSWORD:-}
    worker_secret=${CROSSPATCH_VICTIM_WORKER_PASSWORD:-}
    oracle_secret=${CROSSPATCH_VICTIM_ORACLE_PASSWORD:-}
    scope_secret=${CROSSPATCH_VICTIM_SCOPE_PASSWORD:-}
    export LC_ALL=C
    if [ -z "$admin_secret" ] || [ "${#admin_secret}" -lt 32 ]; then
      echo "release mode requires a 32-byte CROSSPATCH_VICTIM_POSTGRES_ADMIN_PASSWORD" >&2
      exit 78
    fi
    case "$admin_secret" in
      crosspatch-local-*|crosspatch-victim-admin-local-only)
        echo "release mode rejects the local victim PostgreSQL admin password" >&2
        exit 78
        ;;
    esac

    validate_runtime_secret() {
      secret_name=$1
      secret_value=$2
      if [ -z "$secret_value" ] || [ "${#secret_value}" -lt 32 ]; then
        echo "release mode requires a 32-byte $secret_name" >&2
        exit 78
      fi
      case "$secret_value" in
        crosspatch-local-*|crosspatch-victim-*-local-only)
          echo "release mode rejects the local $secret_name" >&2
          exit 78
          ;;
      esac
    }
    validate_runtime_secret CROSSPATCH_VICTIM_APP_PASSWORD "$app_secret"
    validate_runtime_secret CROSSPATCH_VICTIM_CANDIDATE_PASSWORD "$candidate_secret"
    validate_runtime_secret CROSSPATCH_VICTIM_WORKER_PASSWORD "$worker_secret"
    validate_runtime_secret CROSSPATCH_VICTIM_ORACLE_PASSWORD "$oracle_secret"
    validate_runtime_secret CROSSPATCH_VICTIM_SCOPE_PASSWORD "$scope_secret"

    if [ "$(printf '%s\n' "$admin_secret" "$app_secret" "$candidate_secret" "$worker_secret" "$oracle_secret" "$scope_secret" | sort -u | wc -l | tr -d ' ')" -ne 6 ]; then
      echo "victim PostgreSQL authority-zone passwords must be independent" >&2
      exit 78
    fi
    if [ "${POSTGRES_PASSWORD:-}" != "$admin_secret" ]; then
      echo "POSTGRES_PASSWORD must match the named victim PostgreSQL admin secret" >&2
      exit 78
    fi
    ;;
  0|false|no|'')
    ;;
  *)
    echo "CROSSPATCH_RELEASE_MODE must be a boolean value" >&2
    exit 64
    ;;
esac

exec /usr/local/bin/docker-entrypoint.sh "$@"
