from __future__ import annotations

import click
import importlib.metadata

try:
    version_id = importlib.metadata.version('trustpoint_client')
except Exception as exception:
    raise click.ClickException(str(exception)) from exception

@click.command
def version():
    """Displays the version of Trustpoint-Client."""
    click.echo(f'\n\tTrustpoint Client Version: v{version_id}\n')
