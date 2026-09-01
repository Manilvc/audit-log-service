"""Command-line entrypoints.

Mirrors the main backend's click-based ``asgi.py``, so operators run this
service the way they already run the others.

    uv run audit-service serve             # API
    uv run audit-service worker            # ingest worker (separate process)
    uv run audit-service bootstrap         # apply cluster topology
    uv run audit-service generate-kek      # mint a PII master key
    uv run audit-service verify --tenant X # integrity check from the shell
    uv run audit-service backfill --file F # replay legacy NDJSON into ingest
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import sys

import click
import uvicorn

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger

logger = get_logger(__name__)


@click.group()
def cli() -> None:
    """EveryCRED audit log service."""


@cli.command()
@click.option("--host", default=None, help="Bind address (default: SERVER_HOST).")
@click.option("--port", default=None, type=int, help="Bind port (default: SERVER_PORT).")
@click.option("--reload", is_flag=True, help="Auto-reload. Never use in production.")
@click.option("--workers", default=1, type=int, help="Uvicorn worker processes.")
def serve(host: str | None, port: int | None, reload: bool, workers: int) -> None:
    """Run the HTTP API."""
    settings = get_settings()
    if reload and settings.is_production:
        raise click.ClickException("--reload is not permitted in production")

    uvicorn.run(
        "app.main:app",
        host=host or settings.SERVER_HOST,
        port=port or settings.SERVER_PORT,
        reload=reload,
        # `workers` and `reload` are mutually exclusive in uvicorn.
        workers=None if reload else workers,
        # Logging is configured by the app itself, so uvicorn's own config is
        # suppressed to keep a single structured stream.
        log_config=None,
        access_log=False,
        # Bounded: an audit event is small, and a larger body is either a
        # mistake or an attempt to exhaust memory.
        limit_concurrency=1000,
        timeout_keep_alive=15,
        # Never echo the framework version in the Server header.
        server_header=False,
        date_header=True,
    )


@cli.command()
@click.option("--name", default=None, help="Consumer name. Defaults to a random id.")
def worker(name: str | None) -> None:
    """Run the ingest worker.

    A separate process from the API on purpose: ingest throughput scales
    independently, and a slow WORM archive write never adds latency to an
    emitting service's request.
    """
    settings = get_settings()
    configure_logging(
        level="DEBUG" if settings.DEBUG else "INFO",
        json_output=settings.ENVIRONMENT.value != "local",
    )

    async def run() -> None:
        from app.api.container import build_container, build_worker

        container = build_container(settings)
        ingest_worker = build_worker(container)
        if name:
            ingest_worker._consumer = name

        loop = asyncio.get_running_loop()
        # Graceful shutdown: finish the in-flight batch so events are not left
        # pending and later reclaimed as stale.
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, ingest_worker.stop)

        try:
            await ingest_worker.run()
        finally:
            await container.aclose()

    asyncio.run(run())


@cli.command()
def bootstrap() -> None:
    """Apply the Elasticsearch topology (ILM, templates, streams, keyring)."""
    settings = get_settings()
    configure_logging(json_output=False)

    async def run() -> None:
        from app.api.container import build_container
        from app.search.bootstrap import bootstrap_cluster

        container = build_container(settings)
        try:
            summary = await bootstrap_cluster(container.es, settings, container.router)
            click.echo("Cluster bootstrap complete:")
            for key, value in summary.items():
                click.echo(f"  {key}: {value}")
        finally:
            await container.aclose()

    asyncio.run(run())


@cli.command("generate-kek")
def generate_kek() -> None:
    """Mint a PII master key-encryption key.

    Printed once and never stored by this command. Put it in the secret manager
    immediately: if the KEK is lost, every encrypted field in the audit log
    becomes permanently unreadable, and there is no recovery path by design.
    """
    from app.core.security.crypto import PiiCipher

    click.echo(PiiCipher.generate_master_kek())
    click.echo(
        "\nStore this as PII_MASTER_KEK in your secret manager now.\n"
        "Losing it makes every encrypted audit field unrecoverable.",
        err=True,
    )


@cli.command()
@click.option("--tenant", required=True, help="Tenant id to verify.")
@click.option("--chain", default=None, help="Specific chain id. Omit for all chains.")
@click.option("--max-events", default=10_000, type=int)
def verify(tenant: str, chain: str | None, max_events: int) -> None:
    """Verify a tenant's hash chains and print the report.

    Intended for a scheduled job as much as for ad-hoc use: continuous
    verification is what turns tamper *evidence* into tamper *detection*. A
    chain that is only checked when someone suspects a problem is not much of a
    control.

    Exits non-zero when a discontinuity is found, so a cron job or CI step
    fails loudly.
    """
    settings = get_settings()
    configure_logging(json_output=False)

    async def run() -> int:
        from app.api.container import build_container
        from app.core.security.auth import Principal
        from app.domain.enums import ActorType, Scope
        from app.schemas.api import IntegrityVerifyRequest

        container = build_container(settings)
        try:
            # A local operator principal: this runs on the host with access to
            # the cluster credentials already, so there is no token to present.
            operator = Principal(
                subject="cli-operator",
                actor_type=ActorType.SYSTEM,
                tenant_id=tenant,
                scopes=frozenset({Scope.VERIFY, Scope.READ}),
            )
            report = await container.integrity.verify(
                IntegrityVerifyRequest(chain_id=chain, max_events=max_events),
                principal=operator,
                tenant_id=tenant,
            )
            click.echo(f"tenant:           {report.tenant_id}")
            click.echo(f"chains checked:   {report.chains_checked}")
            click.echo(f"events verified:  {report.events_verified}")
            click.echo(f"intact:           {report.intact}")
            if report.checkpoint:
                click.echo(
                    f"last checkpoint:  seq={report.checkpoint.get('seq')} "
                    f"sealed={report.checkpoint.get('sealed_at')}"
                )
            else:
                click.echo("last checkpoint:  none (WORM archive disabled or empty)")
            for break_ in report.breaks:
                click.echo(f"  BREAK {break_['kind']} at seq {break_['seq']}: {break_['detail']}")
            return 0 if report.intact else 2
        finally:
            await container.aclose()

    sys.exit(asyncio.run(run()))


@cli.command("backfill")
@click.option(
    "--file",
    "ndjson_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="NDJSON export of legacy audit rows.",
)
@click.option(
    "--url",
    default=None,
    help="Audit API base URL (default: http://127.0.0.1:SERVER_PORT).",
)
@click.option("--api-key", default=None, help="Service API key (default: first SERVICE_API_KEYS).")
@click.option("--tenant", default=None, help="Default tenant_id when a row omits it.")
@click.option("--batch-size", default=100, type=int, show_default=True)
@click.option("--dry-run", is_flag=True, help="Map only; do not POST.")
def backfill(
    ndjson_path: str,
    url: str | None,
    api_key: str | None,
    tenant: str | None,
    batch_size: int,
    dry_run: bool,
) -> None:
    """Replay a legacy NDJSON export into the ingest API.

    Idempotent on ``event_id`` (the legacy row uuid). Safe to re-run after a
    partial failure — duplicates are rejected by Elasticsearch create-op.
    """
    from pathlib import Path

    from app.tools.backfill import run_backfill

    settings = get_settings()
    configure_logging(json_output=False)

    base_url = url or f"http://127.0.0.1:{settings.SERVER_PORT}"
    key = api_key
    if not key:
        if not settings.SERVICE_API_KEYS:
            raise click.ClickException("no --api-key and SERVICE_API_KEYS is empty")
        key = settings.SERVICE_API_KEYS[0].get_secret_value()

    stats = run_backfill(
        path=Path(ndjson_path),
        base_url=base_url,
        api_key=key,
        batch_size=batch_size,
        dry_run=dry_run,
        default_tenant=tenant,
    )
    click.echo(f"read:      {stats.read}")
    click.echo(f"mapped:    {stats.mapped}")
    click.echo(f"accepted:  {stats.accepted}")
    click.echo(f"rejected:  {stats.rejected}")
    for err in stats.errors[:20]:
        click.echo(f"  error: {err}", err=True)
    if len(stats.errors) > 20:
        click.echo(f"  … {len(stats.errors) - 20} more errors", err=True)
    if stats.rejected and not dry_run:
        sys.exit(1)


if __name__ == "__main__":
    cli()
