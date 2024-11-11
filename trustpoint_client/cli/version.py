"""Trustpoint-Client commands concerning its version."""
from __future__ import annotations

import importlib.metadata

import click

try:
    version_id = importlib.metadata.version('trustpoint_client')
except Exception as exception:
    raise click.ClickException(str(exception)) from exception


@click.command
def version() -> None:
    """Displays the version of Trustpoint-Client."""
    click.echo(f'\n\tTrustpoint Client Version: v{version_id}\n')
