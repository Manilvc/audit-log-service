# Convenience targets. Everything runs through uv, so no activated virtualenv
# is needed and CI runs the identical commands.

.PHONY: help install up down bootstrap serve worker test lint fmt typecheck security check verify clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Install dependencies into .venv
	uv sync --all-extras

up:  ## Start Elasticsearch, Redis and MinIO
	docker compose up -d elasticsearch redis minio
	./scripts/init-minio.sh

down:  ## Stop the local stack (volumes are preserved)
	docker compose down

bootstrap:  ## Apply ILM policy, index templates, keyring index and data streams
	uv run audit-service bootstrap

serve:  ## Run the API
	uv run audit-service serve --reload

worker:  ## Run the ingest worker
	uv run audit-service worker

test:  ## Unit tests (no infrastructure required)
	uv run pytest -m "not integration"

test-all:  ## Every test, including integration (needs `make up`)
	uv run pytest

lint:  ## Lint and check formatting
	uv run ruff check .
	uv run ruff format --check .

fmt:  ## Auto-fix and format
	uv run ruff check --fix .
	uv run ruff format .

typecheck:  ## Strict type check
	uv run mypy app

security:  ## SAST + dependency CVE scan
	uv run bandit -c pyproject.toml -r app
	uv run pip-audit

# The gate CI should run. `security` is included deliberately: a dependency CVE
# in a service holding six years of audit evidence is a release blocker.
check: lint typecheck test security  ## Full compliance gate

verify:  ## Verify a tenant's hash chains (TENANT=<id>)
	uv run audit-service verify --tenant $(TENANT)

clean:
	rm -rf .venv .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
