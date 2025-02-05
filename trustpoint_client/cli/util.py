"""Commands concerning utility and demo features."""
from __future__ import annotations

import click
from cryptography.hazmat.primitives import hashes

from trustpoint_client import oid
from trustpoint_client.api.util import create_idevid_hierarchy, delete_idevid_hierarchy
from typing import cast

from typing import Union
SupportedHashAlgorithms = Union[
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
    hashes.SHA3_224,
    hashes.SHA3_256,
    hashes.SHA3_384,
    hashes.SHA3_512
]


@click.group
def util() -> None:
    """Commands concerning utility and demo features."""


@util.group
def idevid() -> None:
    """Commands concerning the creation of IDevIDs for testing purposes."""

@idevid.command(name='create')
def idevid_create() -> None:
    """Create IDevID hierarchies and IDevID certificates."""

@idevid.command(name='list')
def idevid_list() -> None:
    """List IDevID hierarchies and IDevID certificates."""

@idevid.command(name='delete')
def idevid_delete() -> None:
    """Delete IDevID hierarchies and IDevID certificates."""

@idevid.group(name='hierarchy')
def idevid_hierarchy() -> None:
    """Commands concerning the creation of IDevID hierarchies."""

@idevid_hierarchy.command(name='create')
@click.option('--name', '-n', type=str, required=True, help='The handle for future use of the hierarchy.')
@click.option('--algorithm', '-a', type=click.Choice(['RSA', 'ECC']), default='RSA', help='The algorithm to use.')
@click.option('--named-curve', '-c', type=click.Choice([named_curve.verbose_name for named_curve in oid.NamedCurve]))
@click.option('--key-size', '-k', type=int, default=2048, help='The size of the key. Ignored for ECC.')
@click.option(
    '--hash-algorithm', '-h',
    type=click.Choice(
    [
        hash_alg.verbose_name for hash_alg in oid.HashAlgorithm
        if hash_alg.verbose_name not in ['MD5', 'SHA1', 'Shake-128', 'Shake-256']
    ]),
    default=oid.HashAlgorithm.SHA256.verbose_name
)
def idevid_hierarchy_create(name: str, algorithm: str, named_curve: str, key_size: int, hash_algorithm: str) -> None:
    """Create an IDevID hierarchy that is able to issue IDevID certificates."""

    public_key_algorithm_oid = cast(oid.PublicKeyAlgorithmOid, oid.PublicKeyAlgorithmOid[algorithm])
    hash_alg_enum = cast(oid.HashAlgorithm, oid.HashAlgorithm[hash_algorithm])

    if algorithm == 'ECC':
        if named_curve is None:
            raise click.ClickException('You must specify a named curve if using ECC.')
        else:
            named_curve_enum = cast(oid.NamedCurve[named_curve], oid.NamedCurve)
    else:
        named_curve_enum = None

    try:
        create_idevid_hierarchy(
            name=name,
            algorithm=public_key_algorithm_oid,
            hash_algorithm=hash_alg_enum,
            named_curve=named_curve_enum,
            key_size=key_size
        )
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception


@idevid_hierarchy.command(name='delete')
def idevid_hierarchy_delete(name: str) -> None:
    """Delete an IDevID hierarchy."""
    if click.confirm(
            f'Are you sure you want to delete the hierarchy {name}? '
            f'This will also delete all corresponding IDevIDs.'):
        try:
            delete_idevid_hierarchy(name=name)
        except Exception as exception:
            raise click.ClickException(str(exception)) from exception
    else:
        click.echo('Aborted.')
