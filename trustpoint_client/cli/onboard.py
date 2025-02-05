"""Contains all commands concerned with onboarding the device into a domain."""
from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
import click
from trustpoint_client.oid import PublicKeyInfo, NamedCurve, PublicKeyAlgorithmOid
from typing import cast

from trustpoint_client.api.onboard import onboard_with_shared_secret

@click.group
def onboard() -> None:
    """Commands to onboard the device into a domain."""


@onboard.command(name='manual')
def onboard_manual() -> None:
    """Onboard by injecting the domain credential from file."""


@onboard.command(name='shared-secret')
@click.option('--host', '-h', required=True, type=str, help='The IPv4, IPv6 or hostname of the trustpoint.')
@click.option('--port', '-p', required=False, type=int, default=443, help='The port of the trustpoint.')
@click.option('--key-type', '-k', required=True, type=str, help='The key type of the new domain credential.')
@click.option('--domain', '-d', required=True, type=str, help='The domain to request a domain credential for.')
@click.option('--device-id', '-i', required=True, type=int, help='The reference used to identify the shared secret.')
@click.option('--shared-secret', '-s', required=True, type=str, help='The shared secret used to create the MAC.')
def onboard_shared_secret(
        host: str,
        key_type: str,
        domain: str,
        device_id: int,
        shared_secret: str,
        port: int = 443
) -> None:
    """Onboard the device using a shared secret."""

    # TODO(AlexHx8472): Validate if host is a valid hostname, IPv4 or IPv6 before passing the value.

    try:
        host = IPv4Address(host)
    except ValueError:
        try:
            host = IPv6Address(host)
        except ValueError:
            raise click.ClickException('Host currently only supports IPv4 or IPv6 addresses, but no hostnames.')

    # TODO(AlexHx8472): Proper validation
    if not domain.isidentifier():
        raise click.ClickException('The domain is not a valid Trustpoint domain name.')

    key_type_split = key_type.split('-')
    try:
        key_type_algorithm = cast(PublicKeyAlgorithmOid, PublicKeyAlgorithmOid[key_type_split[0].upper()])
    except KeyError:
        raise click.ClickException('...')

    if key_type_algorithm == PublicKeyAlgorithmOid.RSA:
        try:
            key_size = int(key_type_split[1])
            public_key_info = PublicKeyInfo(public_key_algorithm_oid=key_type_algorithm, key_size=key_size)
        except ValueError:
            raise click.ClickException('...')
    elif key_type_algorithm == PublicKeyAlgorithmOid.ECC:
        try:
            named_curve = cast(NamedCurve, NamedCurve[key_type_split[1].upper()])
            public_key_info = PublicKeyInfo(public_key_algorithm_oid=key_type_algorithm, named_curve=named_curve)
        except KeyError:
            raise click.ClickException('...')
    else:
        raise click.ClickException('...')

    try:
        onboard_with_shared_secret(
            host=host,
            domain=domain,
            device_id=device_id,
            shared_secret=shared_secret.encode(),
            public_key_info=public_key_info,
            port=port
        )
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception

    click.echo(f'\nSuccessfully onboarded into domain {domain}.')


@onboard.command(name='idevid')
def onboard_idevid() -> None:
    """Onboard the device using an available IDevID."""


@onboard.command(name='aoki')
def onboard_aoki() -> None:
    """Onboard the device using the AOKI protocol."""
