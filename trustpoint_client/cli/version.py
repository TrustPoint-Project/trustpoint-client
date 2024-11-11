"""Trustpoint-Client commands concerning its version."""

from __future__ import annotations

import click

from trustpoint_client.cli import handle_exception, version_id


@click.command
@handle_exception
def version() -> None:
    """Displays the version of Trustpoint-Client."""
    click.echo(f'\n\tTrustpoint Client Version: v{version_id}\n')
