.PHONY: bootstrap test test-e2e lint typecheck build judge eval replay clean

bootstrap:
	uv sync --frozen --extra dev
	npm ci --ignore-scripts --no-audit --no-fund

test:
	uv run --frozen --extra dev python -m pytest
	npm --workspace @crosspatch/web test -- --run

test-e2e:
	npm --workspace @crosspatch/web run test:e2e

lint:
	uv run --frozen --extra dev ruff check backend victim
	npm run lint

typecheck:
	npm run typecheck

build:
	uv run --frozen --extra dev python -m build --sdist --wheel
	npm run build

judge: export OPENAI_API_KEY :=
judge: bootstrap
	docker compose --env-file /dev/null build runner
	OPENAI_API_KEY= uv run --frozen --extra dev python -m pytest -m 'not real_model'
	npm run lint
	npm run typecheck
	npm --workspace @crosspatch/web test -- --run
	npm run build
	docker compose --env-file /dev/null config --quiet
	uv run --frozen --extra dev python scripts/verify_capture_integrity.py
	uv run --frozen --extra dev python scripts/verify_claim_map.py --check

eval: export OPENAI_API_KEY :=
eval:
	@OPENAI_API_KEY= uv run --frozen --extra dev python scripts/reproducible_adversarial_eval.py --check

replay: export OPENAI_API_KEY :=
replay:
	OPENAI_API_KEY= docker compose --env-file /dev/null --profile replay up --build --detach --wait replay-caddy
	python3 scripts/verify_replay.py --base-url "http://127.0.0.1:$${CROSSPATCH_REPLAY_PORT:-8088}"
	@echo "RECORDED REPLAY — signed export, no model calls"
	@echo "Open http://localhost:$${CROSSPATCH_REPLAY_PORT:-8088}/cases"

clean:
	rm -rf build dist .pytest_cache .ruff_cache web/.next web/coverage web/playwright-report web/test-results
