import click

from trustpoint_client.api import purge_working_dir_inventory_and_config
from trustpoint_client.cli import handle_cli_error


@click.command
@handle_cli_error
def purge() -> None:
    """Purges the Trustpoint Client."""
    if click.confirm(
            '\n\tAre you sure you want to purge the Trustpoint Client?\n'
            '\tThis will remove all data, including all LDevID objects.\n\n'):
        purge_working_dir_inventory_and_config()
        click.echo('\n\tSuccessfully purged the Trustpoint Client.\n')
    else:
        click.echo('\n\tAborted.\n')
