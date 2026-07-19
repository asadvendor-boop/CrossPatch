# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.13.7-slim-bookworm@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d

FROM ghcr.io/astral-sh/uv:0.10.12@sha256:72ab0aeb448090480ccabb99fb5f52b0dc3c71923bffb5e2e26517a1c27b7fec AS uv

FROM ${PYTHON_IMAGE} AS dependencies

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/crosspatch/venv

COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --extra dev --no-install-project --no-cache

FROM ${PYTHON_IMAGE} AS runner

ENV HOME=/tmp/crosspatch \
    PATH=/opt/crosspatch/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/workspace/backend/src:/workspace/victim/src \
    PYTHONUNBUFFERED=1 \
    PYTEST_ADDOPTS=-p\ no:cacheprovider

RUN groupadd --gid 10001 crosspatch \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp/crosspatch crosspatch \
    && groupadd --gid 10002 crosspatch-candidate \
    && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /tmp/crosspatch-candidate crosspatch-candidate \
    && groupadd --gid 10003 crosspatch-executor \
    && useradd --uid 10003 --gid 10003 --no-create-home --home-dir /tmp/crosspatch-executor crosspatch-executor \
    && groupadd --gid 10004 crosspatch-candidate-control \
    && mkdir -p /opt/crosspatch/tests/backend \
                /opt/crosspatch/tests/victim \
                /opt/crosspatch/src \
                /var/lib/crosspatch/candidate-workspaces \
                /var/lib/crosspatch/candidate-handoff \
                /var/lib/crosspatch/jobs \
                /workspaces \
                /workspace/backend/src \
                /workspace/infra/postgres \
                /workspace/victim/src \
    && chown -R root:root /opt/crosspatch \
    && chown -R crosspatch:crosspatch /var/lib/crosspatch \
    && chown crosspatch:crosspatch /workspaces \
    && chmod 0755 /var/lib/crosspatch/candidate-workspaces \
    && chmod 0700 /var/lib/crosspatch/jobs \
    && chmod 0755 /workspaces \
    && chown -R crosspatch:crosspatch /workspace

COPY --from=dependencies --chown=root:root /opt/crosspatch/venv/ /opt/crosspatch/venv/

# Candidate source lives under /workspace. The fixed tests are kept outside that
# tree so a patch cannot rewrite the assertions that authorize acceptance.
COPY --chown=crosspatch:crosspatch backend/src/ /workspace/backend/src/
COPY --chown=crosspatch:crosspatch victim/src/ /workspace/victim/src/
COPY --chown=crosspatch:crosspatch infra/postgres/ /workspace/infra/postgres/
COPY --chown=root:root backend/tests/ /opt/crosspatch/tests/backend/
COPY --chown=root:root victim/tests/ /opt/crosspatch/tests/victim/
COPY --chown=root:root backend/src/crosspatch/ /opt/crosspatch/src/crosspatch/
COPY --chown=root:root backend/src/crosspatch/runner/candidate_service.py /opt/crosspatch/candidate_service.py
COPY --chown=root:root --chmod=0555 infra/runner/candidate_executor_entrypoint.py /usr/local/bin/crosspatch-candidate-executor-entrypoint
RUN chown -R root:root /opt/crosspatch && chmod -R a-w /opt/crosspatch

WORKDIR /workspace
USER crosspatch

RUN /opt/crosspatch/venv/bin/python -c "from pathlib import Path; from crosspatch.runner.catalog import CANDIDATE_PLAN_IDS, ExecutionCatalog; plans = tuple(ExecutionCatalog.default().plans.values()); assert len(plans) == 13, 'the production image must contain exactly 13 catalog nodes'; candidates = tuple(plan for plan in plans if plan.plan_id in CANDIDATE_PLAN_IDS); assert len(candidates) == 2, 'the production image must contain exactly two candidate plans'; assert all(plan.argv == ('/opt/crosspatch/venv/bin/python', '/opt/crosspatch/candidate_service.py') for plan in candidates); assert Path(candidates[0].argv[1]).is_file(), 'missing immutable candidate sidecar driver'; node_paths = tuple(plan.argv[4].partition('::')[0] for plan in plans if plan.plan_id not in CANDIDATE_PLAN_IDS); missing = tuple(path for path in node_paths if not Path(path).is_file()); assert not missing, f'missing immutable catalog test files: {missing}'"

ENTRYPOINT ["/opt/crosspatch/venv/bin/python"]
CMD ["-c", "import signal; signal.pause()"]
