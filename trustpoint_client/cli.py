import click
from trustpoint_client.trustpoint_client import provision as _provision


@click.group()
def cli() -> None:
    """Trustpoint-Client program."""
    pass


@cli.command()
@click.option('--otp', '-o', required=True, type=str, help='The OTP for provisioning.')
@click.option('--salt', '-s', required=True, type=str, help='The salt for provisioning.')
@click.option('--url', '-u', required=True, type=str, help='The url endpoint for provisioning.')
def provision(otp: str, salt: str, url: str) -> None:
    """Provisions the Trustpoint-Client software."""
    try:
        _provision(otp, salt, url)
    except Exception as e:
        click.echo(f'Failed to provision the Trustpoint-Client.\n{e}')
        return
    click.echo('Successfully provisioned the Trustpoint-Client.')


if __name__ == '__main__':
    cli()
