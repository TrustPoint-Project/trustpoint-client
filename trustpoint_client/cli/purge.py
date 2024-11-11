"""Trustpoint-Client commands concerning purging (deleting) all data."""

from __future__ import annotations

import click

from trustpoint_client.api import purge_working_dir_inventory_and_config
from trustpoint_client.cli import handle_exception


@click.command
@handle_exception
def purge() -> None:
    """Purges all data of the Trustpoint Client."""
    if click.confirm(
        '\n\tAre you sure you want to purge the Trustpoint Client?\n'
        '\tThis will remove all data, including all LDevID objects.\n\n'
    ):
        try:
            purge_working_dir_inventory_and_config()
            click.echo('\n\tSuccessfully purged the Trustpoint Client.\n')
        except Exception as exception:
            raise click.ClickException(str(exception)) from exception
    else:
        click.echo('\n\tAborted.\n')
