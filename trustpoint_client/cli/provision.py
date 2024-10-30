"""Command-line interface for the Trustpoint-Client."""
from __future__ import annotations

import click
import prettytable
from pathlib import Path


from trustpoint_client.api.mdns import find_services
from trustpoint_client.api.zero_touch_aoki import aoki_onboarding
from trustpoint_client.api import TrustpointClient
from trustpoint_client.api.schema import PkiProtocol




@click.group
def provision() -> None:
    """Commands to provision the Trustpoint Client."""

@provision.command
@click.option('--otp', '-o', required=True, type=str, help='The One-Time Password to use.')
@click.option('--device', '-d', required=True, type=str, help='The device name.')
@click.option('--host', '-h', required=True, type=str, help='The domain name or IP address of the trustpoint.')
@click.option('--port', '-p', required=False, type=int, default=443, help='The port of the trustpoint if not 443.')
def auto(otp: str, device: str, host: str, port: int) -> None:
    """Provisioning using the Trustpoint Client onboarding process."""
    trustpoint_client = TrustpointClient()

    if not port:
        port = 443
    if ':' in host:
        host, port = host.split(':')
    port = int(port)

    result = trustpoint_client.provision_auto(otp, device, host, port)

    click.echo('\nTrustpoint Client successfully provisioned.\n')
    table = prettytable.PrettyTable(['Property', 'Value'])
    table.add_rows([[key.capitalize(), value] for key, value in result.items()])
    table.align = 'l'
    click.echo(table)
    click.echo()


@provision.command
@click.option(
    '--trustpoint-host', '-th',
    type=str,
    required=True, prompt=True,
    help='The trustpoint host name.')
@click.option(
    '--trustpoint-port', '-tp',
    type=int,
    required=True, prompt=True,
    help='The trustpoint port.')
@click.option(
    '--pki-protocol', '-prot',
    type=click.Choice([pki_protocol.value for pki_protocol in PkiProtocol]),
    required=True, prompt=True,
    help='The pki protocol.')
@click.option(
    '--domain-credential-pkcs12', '-pkcs12',
    type=click.Path(),
    default=None,
    help='PKCS#12 file path containing the full credential.')
@click.option(
    '--domain-credential-certificate', '-cert',
    type=click.Path(),
    default=None,
    help='Certificate file path (PEM format)')
@click.option(
    '--domain-credential-certificate-chain', '-chain',
    type=click.Path(),
    default=None,
    help='Certificate chain file path (PEM format).')
@click.option(
    '--domain-credential-private-key', '-key',
    type=click.Path(),
    default=None,
    help='Private key file path (PEM format).')
@click.option(
    '--password', '-pw',
    type=str,
    default=None,
    help='The password to decrypt the private key / PKCS#12 file.')
def manual(
        trustpoint_host: str,
        trustpoint_port: int,
        pki_protocol: str,
        domain_credential_pkcs12: None | str,
        domain_credential_certificate: None | str,
        domain_credential_certificate_chain: None | str,
        domain_credential_private_key: None | str,
        password: None | str) -> None:
    """Creates a domain and injects the domain credential from file."""

    if domain_credential_pkcs12:
        domain_credential_pkcs12 = Path(domain_credential_pkcs12).read_bytes()
    if domain_credential_certificate:
        domain_credential_certificate = Path(domain_credential_certificate).read_bytes()
    if domain_credential_certificate_chain:
        domain_credential_certificate_chain = Path(domain_credential_certificate_chain).read_bytes()
    if domain_credential_private_key:
        domain_credential_private_key = Path(domain_credential_private_key).read_bytes()
    if password:
        password = password.encode()

    click.echo('\nNot yet implemented!\n')
    # trustpoint_client = TrustpointClient()
    # result = trustpoint_client.provision_manual(
    #     trustpoint_host=trustpoint_host,
    #     trustpoint_port=trustpoint_port,
    #     pki_protocol=pki_protocol,
    #     domain_credential_pkcs12=domain_credential_pkcs12,
    #     domain_credential_certificate=domain_credential_certificate,
    #     domain_credential_certificate_chain=domain_credential_certificate_chain,
    #     domain_credential_private_key=domain_credential_private_key,
    #     password=password
    # )



@provision.command
@click.option('--host', '-h', required=False, type=str,
              help='The domain or IP address of the Trustpoint. For testing without discovery.')
@click.option('--port', '-p', required=False, type=int, default=443,
              help='The port of the Trustpoint if not 443. For testing without discovery.')
def zero_touch(host: str, port: int):
    """Starts the AOKI demo zero-touch onboarding process."""

    if host is None:  # regular zero-touch onboarding with mDNS discovery
        find_services(zero_touch=True)
        return

    # check if host contains a port
    if ':' in host:
        host, port = host.split(':')
        port = int(port)

    aoki_onboarding(host, port)
