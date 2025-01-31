"""Trustpoint-Client commands concerning onboarding processes."""

from __future__ import annotations

from pathlib import Path

import click
import prettytable
from trustpoint_devid_module.serializer import CredentialSerializer

from trustpoint_client.api import TrustpointClient
from trustpoint_client.api.mdns import find_services
from trustpoint_client.api.schema import PkiProtocol
from trustpoint_client.api.zero_touch_aoki import aoki_onboarding
from trustpoint_client.cli import handle_exception


def pretty_print_onboarding_results(data: dict[str, str]) -> None:
    """Echoes the results as PrettyTable to CLI (stdout).

    \b
    Args:
        data: Onboarding results.
    """     # noqa: D301
    click.echo('\nTrustpoint Client successfully onboarded.\n')
    table = prettytable.PrettyTable(['Property', 'Value'])
    table.add_rows([[key.capitalize(), value] for key, value in data.items()])
    table.align = 'l'
    click.echo(table)
    click.echo()


@click.group
def onboard() -> None:
    """Commands to onboard the Trustpoint Client."""


@onboard.command
@click.option('--otp', '-o', required=True, type=str, help='The One-Time Password to use.')
@click.option('--device', '-d', required=True, type=str, help='The device name.')
@click.option('--host', '-h', required=True, type=str, help='The domain name or IP address of the trustpoint.')
@click.option('--port', '-p', required=False, type=int, default=443, help='The port of the trustpoint if not 443.')
@handle_exception
def auto(otp: str, device: str, host: str, port: int) -> None:
    """Onboarding using the Trustpoint Client onboarding process."""
    trustpoint_client = TrustpointClient()

    try:
        if not port:
            port = 443
        if ':' in host:
            host, port = host.split(':')
        port = int(port)

        result = trustpoint_client.onboard_auto(otp, device, host, port)
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception

    pretty_print_onboarding_results(result)


@onboard.command
@click.option('--host', '-h', type=str, required=True, prompt=True, help='The trustpoint host name.')
@click.option('--port', '-p', type=int, required=True, prompt=True, help='The trustpoint port.')
@click.option(
    '--pki-protocol',
    '-pki',
    type=click.Choice([pki_protocol.value for pki_protocol in PkiProtocol]),
    required=True,
    prompt=True,
    help='The pki protocol.',
)
@click.option(
    '--domain-credential-pkcs12',
    '-pkcs12',
    type=click.Path(),
    default=None,
    help='PKCS#12 file path containing the full credential.',
)
@click.option(
    '--domain-credential-certificate',
    '-cert',
    type=click.Path(),
    default=None,
    help='Certificate file path (PEM format)',
)
@click.option(
    '--domain-credential-certificate-chain',
    '-chain',
    type=click.Path(),
    default=None,
    help='Certificate chain file path (PEM format).',
)
@click.option(
    '--domain-credential-private-key',
    '-key',
    type=click.Path(),
    default=None,
    help='Private key file path (PEM format).',
)
@click.option(
    '--password', '-pw', type=str, default=None, help='The password to decrypt the private key / PKCS#12 file.'
)
@handle_exception
def manual(  # noqa: PLR0913, C901
    host: str,
    port: int,
    pki_protocol: str,
    domain_credential_pkcs12: None | str,
    domain_credential_certificate: None | str,
    domain_credential_certificate_chain: None | str,
    domain_credential_private_key: None | str,
    password: None | str,
) -> None:
    """Creates a domain and injects the domain credential from file."""
    trustpoint_client = TrustpointClient()

    try:
        if not port:
            port = 443
        if ':' in host:
            host, port = host.split(':')
        port = int(port)

        if domain_credential_pkcs12:
            domain_credential_pkcs12 = Path(domain_credential_pkcs12).read_bytes()
            try:
                credential = CredentialSerializer(domain_credential_pkcs12, password=password)
            except Exception as exception:
                err_msg = 'Failed to parse the PKCS#12 file. Either malformed or wrong password.'
                raise click.ClickException(err_msg) from exception
        else:
            if domain_credential_certificate:
                domain_credential_certificate = Path(domain_credential_certificate).read_bytes()
            if domain_credential_certificate_chain:
                domain_credential_certificate_chain = Path(domain_credential_certificate_chain).read_bytes()
            if domain_credential_private_key:
                domain_credential_private_key = Path(domain_credential_private_key).read_bytes()
            if password:
                password = password.encode()
            try:
                credential = CredentialSerializer(
                    (domain_credential_private_key, domain_credential_certificate, domain_credential_certificate_chain),
                    password=password,
                )
            except Exception as exception:
                err_msg = 'Failed to parse given credential. Either malformed or wrong password.'
                raise click.ClickException(err_msg) from exception
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception

    try:
        pki_protocol = PkiProtocol(pki_protocol.upper())
        result = trustpoint_client.onboard_manual(
            trustpoint_host=host, trustpoint_port=port, pki_protocol=pki_protocol, credential=credential
        )
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception

    pretty_print_onboarding_results(result)


@onboard.command
@click.option(
    '--host',
    '-h',
    required=False,
    type=str,
    help='The domain or IP address of the Trustpoint. For testing without discovery.',
)
@click.option(
    '--port',
    '-p',
    required=False,
    type=int,
    default=443,
    help='The port of the Trustpoint if not 443. For testing without discovery.',
)
@handle_exception
def zero_touch(host: str, port: int) -> None:
    """Starts the AOKI demo zero-touch onboarding process."""
    try:
        # regular zero-touch onboarding with mDNS discovery
        if host is None:
            find_services(zero_touch=True)
            return

        # check if host contains a port
        if ':' in host:
            host, port = host.split(':')
            port = int(port)

        aoki_onboarding(host, port)
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception
