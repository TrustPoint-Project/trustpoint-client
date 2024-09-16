import click

from trustpoint_client.cli import get_trustpoint_client, handle_cli_error


@click.command
@handle_cli_error
def purge():
    """Purges the Trustpoint Client."""

    trustpoint_client = get_trustpoint_client()
    if click.confirm(
            '\n\tAre you sure you want to purge the Trustpoint Client?\n'
            '\tThis will remove all data, including all LDevID objects.\n\n'):
        trustpoint_client.purge()
        click.echo('\n\tSuccessfully purged the Trustpoint Client.\n')
    else:
        click.echo('\n\tAborted.\n')
