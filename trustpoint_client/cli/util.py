"""Commands concerning utility and demo features."""
from __future__ import annotations

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from prettytable import PrettyTable
from pathlib import Path

from trustpoint_client import oid
from trustpoint_client.api import DemoIdevidContext
from trustpoint_client.api.util import (
    create_idevid_hierarchy,
    delete_idevid_hierarchy,
    delete_idevid,
    export_trust_store,
    export_idevid,
    create_idevid
)
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
@click.option('--hierarchy-name', '-n', type=str, required=True, help='The handle of the hierarchy to use.')
@click.option('--device-serial-number', '-d', type=str, required=True, help='The device serial number for the IDevID.')
def idevid_create(hierarchy_name: str, device_serial_number: str) -> None:
    """Creates an IDevID certificate under the selected hierarchy."""

    try:
        create_idevid(hierarchy_name=hierarchy_name, device_serial_number=device_serial_number)
        click.echo(
            f'IDevID with device serial number {device_serial_number} '
            f'created under the hierarchy {hierarchy_name}.')
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception

@idevid.command(name='create-hierarchy')
@click.option('--hierarchy-name', '-n', type=str, required=True, help='The handle for future use of the hierarchy.')
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
def idevid_create_hierarchy(hierarchy_name: str, algorithm: str, named_curve: str, key_size: int, hash_algorithm: str) -> None:
    """Create an IDevID hierarchy that is able to issue IDevID certificates."""

    public_key_algorithm_oid = oid.PublicKeyAlgorithmOid[algorithm]
    hash_alg_enum = oid.HashAlgorithm[hash_algorithm]

    if algorithm == 'ECC':
        if named_curve is None:
            raise click.ClickException('You must specify a named curve if using ECC.')
        else:
            named_curve_enum = oid.NamedCurve[named_curve]
    else:
        named_curve_enum = None

    try:
        create_idevid_hierarchy(
            hierarchy_name=hierarchy_name,
            algorithm=public_key_algorithm_oid,
            hash_algorithm=hash_alg_enum,
            named_curve=named_curve_enum,
            key_size=key_size)
        click.echo(f'IDevID hierarchy with name {hierarchy_name} created.')
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception

@idevid.command(name='list')
def idevid_list() -> None:
    """List IDevID hierarchies and IDevID certificates."""

    demo_idevid_model = DemoIdevidContext().demo_idevid_model
    if not demo_idevid_model.hierarchies:
        click.echo('No hierarchies found. Nothing to list.')
        return

    for name, hierarchy in demo_idevid_model.hierarchies.items():
        click.echo(f'IDevID Hierarchy: {name}.')
        click.echo(f'IDevIDs issued: {len(hierarchy.issued_idevids)}.')
        click.echo(f'Signature Suite: {hierarchy.signature_suite}.')
        if hierarchy.issued_idevids:
            table = PrettyTable(['IDevID Index', 'Device Serial Number'])
            for index, idevid_model in hierarchy.issued_idevids.items():
                table.add_row([str(index), idevid_model.device_serial_number])
            click.echo(table)
            click.echo()

@idevid.command(name='delete')
@click.option('--hierarchy-name', '-n', type=str, required=True, help='The handle of the hierarchy.')
@click.option('--device-serial-number', '-d', type=str, required=False, help='The device serial number of the IDevID to delete.')
@click.option('--index', '-i', type=int, required=False, help='The index of the IDevID to delete.')
def idevid_delete(hierarchy_name: str, device_serial_number: None | str, index: None | int) -> None:
    """Delete an IDevID hierarchy."""
    demo_idevid_model = DemoIdevidContext().demo_idevid_model
    if hierarchy_name not in demo_idevid_model.hierarchies:
        raise click.ClickException(f'No hierarchy found with name {hierarchy_name}. Nothing to delete.')
    if device_serial_number is None and index is None:
        raise click.ClickException('Either the device serial number or the index must be specified.')

    hierarchy = demo_idevid_model.hierarchies[hierarchy_name]
    if device_serial_number is not None:
        if device_serial_number not in hierarchy.device_serial_number_index_mapping:
            err_msg = (
                f'No IDevID found with device serial number {device_serial_number} for hierarchy {hierarchy_name}.')
            raise click.ClickException(err_msg)
        else:
            index = hierarchy.device_serial_number_index_mapping[device_serial_number]
    else:
        if index not in hierarchy.issued_idevids:
            err_msg = f'No IDevID found with index {index} for hierarchy {hierarchy_name}.'
            raise click.ClickException(err_msg)
        else:
            device_serial_number = hierarchy.issued_idevids[index].device_serial_number

    if click.confirm(
            f'Are you sure you want to delete the IDevID with index {index} '
            f'and device serial number {device_serial_number} in the {hierarchy_name} hierarchy? '):
        try:
            delete_idevid(
                hierarchy_name=hierarchy_name,
                index=index,
                device_serial_number=device_serial_number)
            click.echo(
                f'IDevID with index {index} and device serial number {device_serial_number} '
                f'for hierarchy {hierarchy_name} deleted.')
        except Exception as exception:
            raise click.ClickException(str(exception)) from exception
    else:
        click.echo('Aborted.')

@idevid.command(name='delete-hierarchy')
@click.option('--hierarchy-name', '-n', type=str, required=True, help='The handle of the hierarchy.')
def idevid_delete_hierarchy(hierarchy_name: str) -> None:
    """Delete IDevID hierarchies and IDevID certificates."""
    demo_idevid_model = DemoIdevidContext().demo_idevid_model
    if hierarchy_name not in demo_idevid_model.hierarchies:
        raise click.ClickException(f'No hierarchy found with name {hierarchy_name}. Nothing to delete.')

    if click.confirm(
            f'Are you sure you want to delete the {hierarchy_name} hierarchy? '
            f'This will also delete all IDevIDs issued by this hierarchy.'):
        try:
            delete_idevid_hierarchy(hierarchy_name=hierarchy_name)
            click.echo(
                f'Hierarchy {hierarchy_name} and all associated IDevIDs deleted.')
        except Exception as exception:
            raise click.ClickException(str(exception)) from exception
    else:
        click.echo('Aborted.')

@idevid.command(name='export')
@click.option('--hierarchy-name', '-n', type=str, required=True, help='The handle of the hierarchy.')
@click.option('--device-serial-number', '-d', type=str, required=False, help='The device serial number.')
@click.option('--index', '-i', type=int, required=False, help='The index of the IDevID to delete.')
@click.option('--file-path', '-f', type=str, required=True, help='File path to store the IDevID credential PKCS#12 file in.')
def idevid_export(hierarchy_name: str, device_serial_number: None | str, index: None | int, file_path: str) -> None:
    """Exports the IDevID credential as PKCS#12 file."""
    demo_idevid_model = DemoIdevidContext().demo_idevid_model
    if hierarchy_name not in demo_idevid_model.hierarchies:
        err_msg = f'No hierarchy found with name {hierarchy_name}. Nothing to delete.'
        raise click.ClickException(err_msg)

    hierarchy = demo_idevid_model.hierarchies[hierarchy_name]
    if device_serial_number is None and index is None:
        err_msg = f'Either provide the index or device serial number to identify the IDevID to export.'
        raise click.ClickException(err_msg)

    if device_serial_number:
        if device_serial_number not in hierarchy.device_serial_number_index_mapping:
            err_msg = f'No IDevID found for device serial number {device_serial_number}and hierarchy {hierarchy_name}.'
            raise click.ClickException(err_msg)
        index = hierarchy.device_serial_number_index_mapping[device_serial_number]

    if index:
        if index not in hierarchy.issued_idevids:
            err_msg = f'No IDevID found for index {index} and hierarchy {hierarchy_name}.'
            raise click.ClickException(err_msg)

    try:
        p12_bytes = export_idevid(
            hierarchy_name=hierarchy_name,
            index=index
        )

        if not file_path.endswith('.p12') or not file_path.endswith('.pfx'):
            file_path += '.p12'

        Path(file_path).write_bytes(p12_bytes)
        click.echo(f'IDevID credential exported to {file_path}.')
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception

@idevid.command(name='export-hierarchy')
@click.option('--hierarchy-name', '-n', type=str, required=True, help='The handle of the hierarchy.')
@click.option('--file-path', '-f', type=str, required=True, help='File path to store the trust-store in.')
def idevid_export_hierarchy(hierarchy_name: str, file_path: str) -> None:
    """Exports the Trust-Store of the hierarchy as file."""

    if not file_path.endswith('.pem'):
        file_path += '.pem'

    try:
        Path(file_path).write_text(export_trust_store(hierarchy_name))
        click.echo(f'Trust-Store of hierarchy {hierarchy_name} exported to {file_path}.')
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception
