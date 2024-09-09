import click

from trustpoint_client.cli import get_trustpoint_client, handle_cli_error

@click.command
@handle_cli_error
def init():
    """Initializes the Trustpoint Client."""

    trustpoint_client = get_trustpoint_client()
    trustpoint_client.init()
    click.echo('\n\tSuccessfully initialized the Trustpoint Client.\n')