import click

from trustpoint_client.cli import draw_ascii_logo, get_trustpoint_client, handle_cli_error

@click.command
@handle_cli_error
def init():
    """Initializes the Trustpoint Client."""

    draw_ascii_logo()

    trustpoint_client = get_trustpoint_client()
    trustpoint_client.init()
    click.echo('\n\tSuccessfully initialized the Trustpoint Client.\n')