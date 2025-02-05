"""Trustpoint-Client commands concerning its version."""

from __future__ import annotations

import click

from trustpoint_client.cli import version_id


@click.command
def version() -> None:
    """Displays the version of Trustpoint-Client."""
    click.echo(f'{version_id}')
