"""Contains all commands concerned with onboarding the device into a domain."""
from __future__ import annotations

import ipaddress
import click
from trustpoint_client import oid

from trustpoint_client.api.onboard import onboard_with_shared_secret, onboard_with_idevid

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
        host_address = ipaddress.ip_address(host)
    except ValueError as exception:
        err_msg = 'Host currently only supports IPv4 or IPv6 addresses, but no hostnames.'
        raise click.ClickException(err_msg) from exception

    # TODO(AlexHx8472): Proper validation
    if not domain.isidentifier():
        raise click.ClickException('The domain is not a valid Trustpoint domain name.')

    key_type_split = key_type.split('-')
    try:
        key_type_algorithm = oid.PublicKeyAlgorithmOid[key_type_split[0].upper()]
    except KeyError:
        raise click.ClickException('...')

    if key_type_algorithm == oid.PublicKeyAlgorithmOid.RSA:
        try:
            key_size = int(key_type_split[1])
            public_key_info = oid.PublicKeyInfo(public_key_algorithm_oid=key_type_algorithm, key_size=key_size)
        except ValueError:
            raise click.ClickException('...')
    elif key_type_algorithm == oid.PublicKeyAlgorithmOid.ECC:
        try:
            named_curve = oid.NamedCurve[key_type_split[1].upper()]
            public_key_info = oid.PublicKeyInfo(public_key_algorithm_oid=key_type_algorithm, named_curve=named_curve)
        except KeyError:
            raise click.ClickException('...')
    else:
        raise click.ClickException('...')

    try:
        onboard_with_shared_secret(
            host=host_address,
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
@click.option('--host', '-h', required=True, type=str, help='The IPv4, IPv6 or hostname of the trustpoint.')
@click.option('--port', '-p', required=False, type=int, default=443, help='The port of the trustpoint.')
@click.option('--domain', '-d', required=True, type=str, help='The domain to request a domain credential for.')
@click.option('--algorithm', '-a', type=click.Choice(['RSA', 'ECC']), default='RSA', help='The algorithm to use.')
@click.option('--named-curve', '-c', type=click.Choice([named_curve.verbose_name for named_curve in oid.NamedCurve]))
@click.option('--key-size', '-k', type=int, default=2048, help='The size of the key. Ignored for ECC.')
@click.option(
    '--hash-algorithm', '-ha',
    type=click.Choice(
    [
        hash_alg.verbose_name for hash_alg in oid.HashAlgorithm
        if hash_alg.verbose_name not in ['MD5', 'SHA1', 'Shake-128', 'Shake-256']
    ]),
    default=oid.HashAlgorithm.SHA256.verbose_name
)
def onboard_idevid(
        host: str,
        domain: str,
        algorithm: str,
        named_curve: str,
        key_size: int,
        hash_algorithm: str,
        port: int = 443) -> None:
    """Onboard the device using an available IDevID."""

    try:
        host_address = ipaddress.ip_address(host)
    except ValueError as exception:
        err_msg = 'Host currently only supports IPv4 or IPv6 addresses, but no hostnames.'
        raise click.ClickException(err_msg) from exception

    # TODO(AlexHx8472): Proper validation
    if not domain.isidentifier():
        raise click.ClickException('The domain is not a valid Trustpoint domain name.')

    try:
        key_type_algorithm = oid.PublicKeyAlgorithmOid[algorithm.upper()]
    except KeyError:
        raise click.ClickException('...')

    if key_type_algorithm == oid.PublicKeyAlgorithmOid.RSA:
        try:
            public_key_info = oid.PublicKeyInfo(public_key_algorithm_oid=key_type_algorithm, key_size=key_size)
        except ValueError:
            raise click.ClickException('...')
    elif key_type_algorithm == oid.PublicKeyAlgorithmOid.ECC:
        try:
            named_curve = oid.NamedCurve[named_curve.upper()]
            public_key_info = oid.PublicKeyInfo(public_key_algorithm_oid=key_type_algorithm, named_curve=named_curve)
        except KeyError:
            raise click.ClickException('...')
    else:
        raise click.ClickException('...')

    try:
        algorithm_identifier = oid.AlgorithmIdentifier.from_public_key_alg_and_hash_alg(
            public_key_info.public_key_algorithm_oid,
            oid.HashAlgorithm[hash_algorithm.upper()])
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception

    signature_suite = oid.SignatureSuite(public_key_info=public_key_info, algorithm_identifier=algorithm_identifier)

    try:
        onboard_with_idevid(
            host=host_address,
            domain=domain,
            signature_suite=signature_suite,
            port=port
        )
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception


@onboard.command(name='aoki')
def onboard_aoki() -> None:
    """Onboard the device using the AOKI protocol."""
