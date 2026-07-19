# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.13.7-slim-bookworm@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d
ARG NODE_IMAGE=node:22.20.0-bookworm-slim@sha256:b21fe589dfbe5cc39365d0544b9be3f1f33f55f3c86c87a76ff65a02f8f5848e
ARG CADDY_IMAGE=caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d

FROM ghcr.io/astral-sh/uv:0.10.12@sha256:72ab0aeb448090480ccabb99fb5f52b0dc3c71923bffb5e2e26517a1c27b7fec AS uv

FROM ${PYTHON_IMAGE} AS python-dependencies
ENV UV_COMPILE_BYTECODE=1 \
    UV_CONCURRENT_DOWNLOADS=2 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/crosspatch/venv
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY backend ./backend
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev \
    && chmod -R a-w /opt/crosspatch

FROM ${PYTHON_IMAGE} AS python-runtime
ARG SOURCE_DATE_EPOCH=946684800
ENV HOME=/tmp/crosspatch \
    PATH=/opt/crosspatch/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PYTHONNOUSERSITE=1 \
    PYTHONPATH=/app/backend/src:/app/victim/src \
    PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 crosspatch \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp/crosspatch crosspatch \
    && mkdir -p /app/.crosspatch/secrets \
                /app/repository \
                /var/lib/crosspatch/agent-sessions \
                /var/lib/crosspatch/artifacts \
    && chown -R 10001:10001 /app/.crosspatch /var/lib/crosspatch
COPY --from=python-dependencies --chown=root:root /opt/crosspatch/venv/ /opt/crosspatch/venv/
COPY --chown=root:root backend/ /app/backend/
COPY --chown=root:root victim/ /app/victim/
COPY --chown=root:root infra/postgres/ /app/infra/postgres/
COPY --chown=root:root backend/ /app/repository/backend/
COPY --chown=root:root victim/ /app/repository/victim/
COPY --chown=root:root infra/postgres/ /app/repository/infra/postgres/
COPY --chmod=0555 infra/entrypoint.sh /usr/local/bin/crosspatch-entrypoint
COPY --chmod=0444 infra/victim-worker.py /app/infra/victim-worker.py
RUN git init --initial-branch=main /app/repository \
    && git -C /app/repository config user.name "CrossPatch Build" \
    && git -C /app/repository config user.email "build@crosspatch.invalid" \
    && git -C /app/repository add --all \
    && GIT_AUTHOR_DATE="@$SOURCE_DATE_EPOCH +0000" \
       GIT_COMMITTER_DATE="@$SOURCE_DATE_EPOCH +0000" \
       git -C /app/repository commit --quiet -m "CrossPatch runtime snapshot" \
    && git config --system --add safe.directory /app/repository \
    && chmod -R a-w /app/backend /app/victim /app/infra /app/repository
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/crosspatch-entrypoint"]
CMD ["api"]

FROM ${PYTHON_IMAGE} AS replay-python-base
ENV HOME=/tmp/crosspatch \
    PATH=/opt/crosspatch/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PYTHONNOUSERSITE=1 \
    PYTHONPATH=/app/backend/src \
    PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 crosspatch \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp/crosspatch crosspatch \
    && mkdir -p /app/replay
COPY --from=python-dependencies --chown=root:root /opt/crosspatch/venv/ /opt/crosspatch/venv/
COPY --chown=root:root backend/ /app/backend/
COPY --chmod=0555 infra/replay-entrypoint.sh /usr/local/bin/crosspatch-replay-entrypoint
RUN chmod -R a-w /app/backend
WORKDIR /app

FROM replay-python-base AS replay-database-build
USER root
COPY --chown=root:root artifacts/verification/paced-batches/paced-20260714T103240Z/run-04/real-model-cases/inc_e032c6cde04f44b8a5dc6371c8c6f690.zip /tmp/crosspatch-replay/case.zip
COPY --chown=root:root artifacts/verification/paced-batches/paced-20260714T103240Z/local-export-public-key.json /tmp/crosspatch-replay/public-key.json
RUN python -m crosspatch.replay.importer \
      --archive /tmp/crosspatch-replay/case.zip \
      --public-key /tmp/crosspatch-replay/public-key.json \
      --database /tmp/crosspatch-replay/replay.db \
    && test "$(stat -c '%a' /tmp/crosspatch-replay/replay.db)" = "444"

FROM replay-python-base AS replay-python-runtime
USER root
COPY --from=replay-database-build --chown=root:root --chmod=0444 /tmp/crosspatch-replay/replay.db /app/replay/replay.db
RUN chmod 0555 /app/replay \
    && test "$(stat -c '%a' /app/replay)" = "555" \
    && test "$(stat -c '%a' /app/replay/replay.db)" = "444"
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/crosspatch-replay-entrypoint"]

FROM ${NODE_IMAGE} AS web-build
ARG CROSSPATCH_PUBLIC_URL=https://localhost
ARG NEXT_PUBLIC_CROSSPATCH_REPLAY_MODE=0
ENV NEXT_TELEMETRY_DISABLED=1
ENV CROSSPATCH_PUBLIC_URL=${CROSSPATCH_PUBLIC_URL}
ENV NEXT_PUBLIC_CROSSPATCH_REPLAY_MODE=${NEXT_PUBLIC_CROSSPATCH_REPLAY_MODE}
WORKDIR /build
COPY package.json package-lock.json ./
COPY web/package.json ./web/package.json
RUN NPM_VERSION="$(node -p "require('./package.json').packageManager.replace(/^npm@/, '')")" \
    && npm install --global "npm@${NPM_VERSION}" --ignore-scripts --no-audit --no-fund \
    && test "$(npm --version)" = "${NPM_VERSION}" \
    && npm ci --ignore-scripts --no-audit --no-fund
COPY docs/CLAIM_MAP.json docs/DOCTRINE.json ./docs/
COPY web ./web
RUN npm --workspace @crosspatch/web run build

FROM ${NODE_IMAGE} AS web-runtime
ENV HOME=/tmp/crosspatch \
    HOSTNAME=0.0.0.0 \
    NEXT_TELEMETRY_DISABLED=1 \
    NODE_ENV=production \
    PORT=3000
RUN groupadd --gid 10001 crosspatch \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp/crosspatch crosspatch
WORKDIR /app/web
COPY --from=web-build --chown=root:root /build/web/.next/standalone/ /app/
COPY --from=web-build --chown=root:root /build/web/.next/static/ /app/web/.next/static/
COPY --from=web-build --chown=root:root /build/web/public/ /app/web/public/
USER 10001:10001
CMD ["node", "server.js"]

FROM ${CADDY_IMAGE} AS replay-caddy-runtime
USER root
RUN cp /usr/bin/caddy /usr/local/bin/caddy \
    && chmod 0555 /usr/local/bin/caddy \
    && test -z "$(getcap /usr/local/bin/caddy)"
USER 10001:10001
