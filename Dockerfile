# Multi-stage build for the audit log service.
#
# Dependencies are installed in a builder stage and the resulting virtualenv is
# copied into a slim runtime, so no compiler, no uv and no build cache reach the
# final image. That is both a size and an attack-surface decision.

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
FROM python:3.14-slim-bookworm AS builder

# uv comes from its own distroless image rather than being pip-installed: it is
# a pinned, verifiable artefact instead of whatever the index resolves to today.
COPY --from=ghcr.io/astral-sh/uv:0.9.7 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Manifests first, so the (slow) dependency layer is cached and only rebuilt
# when the manifests actually change - not on every source edit.
COPY pyproject.toml uv.lock README.md ./

# --frozen fails the build if uv.lock disagrees with pyproject.toml. A CI
# image must never silently resolve different versions than were tested.
# --no-install-project installs only dependencies at this stage.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY app ./app

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM python:3.14-slim-bookworm AS runtime

# curl is for the container healthcheck only. Everything else the base image
# ships is left alone; adding build tooling here would put a compiler in the
# production attack surface.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 audit \
 && useradd --uid 10001 --gid audit --no-create-home --shell /usr/sbin/nologin audit

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Fail fast on a corrupted install rather than silently running a partial one.
    PYTHONFAULTHANDLER=1

WORKDIR /app

COPY --from=builder --chown=audit:audit /build/.venv /app/.venv
COPY --chown=audit:audit app ./app
COPY --chown=audit:audit pyproject.toml README.md ./

# Non-root. The process needs no filesystem writes: logs go to stdout and all
# state lives in Elasticsearch, Redis and S3.
USER 10001:10001

EXPOSE 8020

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -fsS http://localhost:8020/health/live || exit 1

# `serve` and `worker` are both valid; docker-compose picks per service.
ENTRYPOINT ["audit-service"]
CMD ["serve"]
