"""Command-line interface for the Trustpoint-Client."""

from pathlib import Path

import click

from trustpoint_client.api import provision as _provision

version_id = '0.1.0'

TRUSTPOINT_LOGO = """\b
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@
    @@@@     @@ @   @@ @@@ @@@   @@@     @@@@
    @@@@@ @@@@@  @@@@@ @@@ @@ @@@ @@@ @@@@@@@
    @@@@@ @@@@@ @@@@@@ @@@ @@@  @@@@@ @@@@@@@
    @@@@@ @@ @@ @@@@@@ @@  @@@@@  @@@ @@ @@@@
    @@@@@@  @@@ @@@@@@@  @ @@    @@@@@  @@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    \b
                        @
                                     @
        @ @@    @@@   @@@    @ @@   @@@@@
        @@  @  @   @    @    @@  @   @
        @   @  @   @    @    @   @   @  @
        @@@@    @@@   @@@@@  @   @    @@
        @
        @
    """


class ProvisioningCLIError(Exception):
    """Raised for all errors in the onboarding / client provisioning process."""

    def __init__(self, message: str = 'An error occurred during provisioning.') -> None:
        """Initializes a new ProvisioningCLIError with a given message."""
        self.message = message
        super().__init__(self.message)


def _delete_file(file: str) -> None:
    """Deletes a file if it exists."""
    # this could be a security concern (deleting arbitrary files)
    # though it can't remove dirs so _delete_file('/') won't do an rm -rf / on you
    if Path(file).exists():
        # TODO(Air): Secure deletion (overwrite with random data)
        Path.unlink(file)
    else:
        click.echo(f'No {file} file found.')


def draw_ascii_logo() -> None:
    """Draws the Trustpoint ASCII logo."""
    click.echo(TRUSTPOINT_LOGO)

def draw_tp_client_description() -> None:
    """Draws the Trustpoint client description."""
    click.echo(f'\nWelcome to the Trustpoint Client Certificate Manager (tp-crt-mgr) - v{version_id}!')
    # draw_ascii_logo()
    click.echo('')


@click.group(help=draw_tp_client_description())
def cli() -> None:
    pass


@cli.command()
@click.option('--otp', '-o', required=True, type=str, help='The OTP for provisioning.')
@click.option('--salt', '-s', required=True, type=str, help='The salt for provisioning.')
@click.option('--url', '-u', required=True, type=str, help='The URL extension for the provisioning endpoint.')
@click.option('--host', '-h', required=False, type=str, help='The IP or domain address of the Trustpoint.')
@click.option('--tsotp', '-p', required=False, type=str, help='The OTP for deriving the trust store key.')
# TODO(Air): Analyze if OK to re-use or derive trust store salt from main (LDevID) salt
@click.option('--tssalt', '-z', required=False, type=str, help='The salt for deriving the trust store key.')
@click.option('--sn', '-n', required=False, type=str, help='The serial number of the device.')
def provision(      # noqa: PLR0913
        otp: str,
        salt: str,
        url: str,
        host: str = '127.0.0.1:5000',
        tsotp: str = '',
        tssalt: str = '',
        sn: str = '') -> None:
    """Provisions the Trustpoint-Client software."""
    try:
        _provision(otp, salt, url, host, tsotp, tssalt, sn)
    except Exception as e:
        exc_msg = 'Failed to provision the Trustpoint-Client.'
        raise ProvisioningCLIError(exc_msg) from e

    click.echo('Successfully provisioned the Trustpoint-Client.')


# TODO(Air): perhaps consider ACME for renewal (is quite complex though)
@cli.command()
@click.option(
    '--percentage',
    '-p',
    required=False,
    type=int,
    help='The percentage of certificate lifetime after which renewal should be attempted.',
)
@click.option(
    '--interval', '-i', required=False, type=int, help='The interval in seconds how often to check for expiration'
)
def auto_renew() -> None:
    """Monitors certificates for expiry and automatically requests new ones."""
    # Prerequisites: A currently valid LDevID and  Trustpoint server truststore
    click.echo('Auto-renewal is not yet implemented.')


@cli.command()
def version() -> None:
    """Displays the version of Trustpoint-Client."""
    draw_ascii_logo()
    click.echo(f'Welcome to the Trustpoint Client Certificate Manager (tp-crt-mgr) v {version_id}!')


@cli.command()
@click.option('--trust_store', '-t', is_flag=True, help='Add this flag to delete the HTTPs trust store.')
@click.option('--ldevid', '-l', is_flag=True, help='Add this flag to delete the LDevID certificate and chain.')
@click.option('--sn', '-s', is_flag=True, help='Add this flag to delete the device serial number.')
@click.option('--all', '-a', is_flag=True, help='Add this flag to delete all local files managed by Trustpoint-Client.')
def rm(*, trust_store: bool, ldevid: bool, sn: bool, all_: bool) -> None:
    """Removes local files managed by Trustpoint-Client."""
    click.echo('Secure Removal is not yet implemented.')
    if trust_store or all_:
        click.echo('Removing trust store')
        _delete_file('trust-store.pem')
    if ldevid or all_:
        click.echo('Removing LDevID certificate and chain')
        _delete_file('ldevid.pem')
        _delete_file('ldevid-private-key.pem')
        _delete_file('ldevid-certificate-chain.pem')
    if sn or all_:
        click.echo('Removing device serial number')
        _delete_file('tp-client-serial-no.txt')


if __name__ == '__main__':
    cli()
