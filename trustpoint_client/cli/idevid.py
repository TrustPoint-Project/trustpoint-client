from __future__ import annotations

import click
import uuid
from pathlib import Path

from trustpoint_client.api.schema import SignatureSuite
from trustpoint_client.api.trustpoint import TrustpointClient
from trustpoint_client.cli import handle_exception
import prettytable


# ------------------------------------------------------- IDevID -------------------------------------------------------

@click.group()
def idevid() -> None:
    """Commands concerning IDevIDs.

    \b
    Note:
        Many of these commands are for demonstration purposes only.
        In a real world application, IDevIDs would be integrated in an existing DevID-Module.
        The client would not be able to manipulate IDevIDs, but would only be able to use them.
    """


@idevid.command(name='generate')
@click.option('--unique-name', '-u', type=str, required=True)
@click.option('--hierarchy-unique-name', '-h', type=str, required=True)
@click.option('--serial-number', '-s', type=str)
# @handle_exception
def idevid_generate(unique_name: str, hierarchy_unique_name: str, serial_number: None | str) -> None:
    """Generates a new IDevID credential using a IDevID Hierarchy."""
    trustpoint_client = TrustpointClient()

    if serial_number is None:
        serial_number = str(uuid.uuid4())

    trustpoint_client.generate_idevid(
        unique_name=unique_name,
        serial_number=serial_number,
        idevid_hierarchy_unique_name=hierarchy_unique_name)

    click.echo(f'Successfully generated IDevID with unique name {unique_name}.')


@idevid.command(name='list')
@handle_exception
def idevid_list() -> None:
    """Lists all available IDevIDs."""
    trustpoint_client = TrustpointClient()

    table = prettytable.PrettyTable(['#', 'Unique Name', 'Serial Number', 'Not Valid Before', 'Not Valid After', 'Hierarchy'])
    for index, (unique_name, serial_number, not_valid_before, not_valid_after, idevid_hierarchy_) in enumerate(trustpoint_client.list_idevids()):
        table.add_row([index, unique_name, serial_number, not_valid_before, not_valid_after, idevid_hierarchy_])
    click.echo(table)



@idevid.group(name='export')
@handle_exception
def idevid_export() -> None:
    """Commands concerning IDevID exports."""


@idevid_export.command(name='certificate')
@click.option('--unique-name', '-u', type=str, required=True)
@click.argument('file-path', type=click.Path(exists=False))
@handle_exception
def idevid_export_certificate(unique_name: str, file_path: str) -> None:
    """Exports the certificate of the selected IDevID."""
    trustpoint_client = TrustpointClient()

    file_path = Path(file_path)
    if file_path.exists():
        raise click.ClickException(f'{file_path} already exists.')

    file_path.write_text(trustpoint_client.export_idevid_certificate_as_pem(unique_name=unique_name))
    click.echo(f'Successfully exported IDevID {unique_name} certificate {file_path}.')


@idevid_export.command(name='certificate-chain')
@click.option('--unique-name', '-u', type=str, required=True)
@click.argument('file-path', type=click.Path(exists=False))
@handle_exception
def idevid_export_certificate_chain(unique_name: str, file_path: str) -> None:
    """Exports the certificate chain of the selected IDevID."""
    trustpoint_client = TrustpointClient()

    file_path = Path(file_path)
    if file_path.exists():
        raise click.ClickException(f'{file_path} already exists.')

    file_path.write_text(''.join(trustpoint_client.export_idevid_certificate_chain_as_pem(unique_name=unique_name)))
    click.echo(f'Successfully exported IDevID {unique_name} certificate chain {file_path}.')

@idevid_export.command(name='public-key')
@click.option('--unique-name', '-u', type=str, required=True)
@click.argument('file-path', type=click.Path(exists=False))
@handle_exception
def idevid_export_public_key(unique_name: str, file_path: str) -> None:
    """Exports the public key of the selected IDevID."""
    trustpoint_client = TrustpointClient()

    file_path = Path(file_path)
    if file_path.exists():
        raise click.ClickException(f'{file_path} already exists.')

    file_path.write_text(trustpoint_client.export_idevid_public_key_as_pem(unique_name=unique_name))
    click.echo(f'Successfully exported IDevID {unique_name} public key {file_path}.')

@idevid_export.command(name='private-key')
@click.option('--unique-name', '-u', type=str, required=True)
@click.option('--password', '-p', type=str, required=False)
@click.argument('file-path', type=click.Path(exists=False))
@handle_exception
def idevid_export_private_key(unique_name: str, password: None | str, file_path: str) -> None:
    """Exports the private key of the selected IDevID."""
    trustpoint_client = TrustpointClient()

    file_path = Path(file_path)
    if file_path.exists():
        raise click.ClickException(f'{file_path} already exists.')

    file_path.write_text(trustpoint_client.export_idevid_private_key_as_pkcs8_pem(
        unique_name=unique_name, password=password
    ))
    click.echo(f'Successfully exported IDevID {unique_name} private key {file_path}.')

@idevid_export.command(name='credential')
@click.option('--unique-name', '-u', type=str, required=True)
@click.option('--password', '-p', type=str, required=False)
@handle_exception
def idevid_export_credential(unique_name: str, password: None | str, file_path: str) -> None:
    """Exports the selected IDevID credential."""
    trustpoint_client = TrustpointClient()

    file_path = Path(file_path)
    if file_path.exists():
        raise click.ClickException(f'{file_path} already exists.')

    file_path.write_bytes(trustpoint_client.export_idevid_credential_as_pkcs12(
        unique_name=unique_name, password=password
    ))
    click.echo(f'Successfully exported IDevID {unique_name} credential {file_path}.')


@idevid.command(name='delete')
@click.option('--unique-name', '-u', type=str, required=True)
@handle_exception
def idevid_delete(unique_name: str) -> None:
    """Deletes the selected IDevID."""
    trustpoint_client = TrustpointClient()
    trustpoint_client.delete_idevid(unique_name=unique_name)
    click.echo(f'Successfully deleted IDevID with unique name {unique_name}.')


@idevid.command(name='import')
@handle_exception
def idevid_import() -> None:
    """Import of an IDevID credential."""


# -------------------------------------------------- IDevID Hierarchy --------------------------------------------------

@idevid.group(name='hierarchy')
def idevid_hierarchy() -> None:
    """Commands concerning DevID Hierarchies."""


@idevid_hierarchy.command(name='generate')
@click.option('--unique-name', '-u', type=str, required=True)
@click.option(
    '--signature-suite', '-s',
    type=click.Choice(['RSA2048', 'RSA3072', 'RSA4096', 'SECP256R1', 'SECP384R1']),
    required=True)
@handle_exception
def idevid_hierarchy_generate(unique_name: str, signature_suite: str) -> None:
    """Generates a new DevID Hierarchy.

    Both a new Root CA and Issuing CA will be created.
    """
    trustpoint_client = TrustpointClient()
    signature_suite = SignatureSuite(SignatureSuite[signature_suite.upper()].value)
    trustpoint_client.generate_idevid_hierarchy(unique_name=unique_name, signature_suite=signature_suite)

    click.echo(f'DevID Hierarchy with unique name {unique_name} created.')


@idevid_hierarchy.command(name='list')
@handle_exception
def idevid_hierarchy_list() -> None:
    trustpoint_client = TrustpointClient()

    table = prettytable.PrettyTable(['#', 'Unique Name', 'Signature Suite'])
    idevid_hierarchies = trustpoint_client.idevid_hierarchy_inventory.idevid_hierarchies
    if not idevid_hierarchies:
        click.echo('No IDevID Hierarchies available. Nothing to list.')
        return
    for index, (key, value) in enumerate(idevid_hierarchies.items()):
        table.add_row([index, key, value.signature_suite.value])
    click.echo(table)


@idevid_hierarchy.group(name='export')
def idevid_hierarchy_export() -> None:
    """Commands concerning export of IDevID hierarchies."""


@idevid_hierarchy_export.command(name='root-ca')
@click.option('--unique-name', '-u', type=str, required=True)
@click.option('--password', '-p', type=str, default=None, required=False)
@click.argument('file-path', type=click.Path(exists=False))
@handle_exception
def idevid_hierarchy_export_root_ca(unique_name: str, password: None | str, file_path: str) -> None:
    trustpoint_client = TrustpointClient()
    if not file_path.endswith('.12'):
        file_path += '.p12'
    file_path = Path(file_path)
    if file_path.exists():
        raise click.ClickException(f'{file_path} already exists.')
    root_ca_pkcs12, password = trustpoint_client.export_idevid_hierarchy_root_ca_as_pkcs12(unique_name, password)
    file_path.write_bytes(root_ca_pkcs12)
    click.echo(f'Root CA of IDevID hierarchy {unique_name} stored at {file_path}')
    click.echo(f'Password: {password.decode()}.')


@idevid_hierarchy_export.command(name='issuing-ca')
@click.option('--unique-name', '-u', type=str, required=True)
@click.option('--password', '-p', type=str, default=None, required=False)
@click.argument('file-path', type=click.Path(exists=False))
@handle_exception
def idevid_hierarchy_export_issuing_ca(unique_name: str, password: None | str, file_path: str) -> None:
    trustpoint_client = TrustpointClient()
    if not file_path.endswith('.12'):
        file_path += '.p12'
    file_path = Path(file_path)
    if file_path.exists():
        raise click.ClickException(f'{file_path} already exists.')
    issuing_ca_pkcs12, password = trustpoint_client.export_idevid_hierarchy_issuing_ca_as_pkcs12(unique_name, password)
    file_path.write_bytes(issuing_ca_pkcs12)
    click.echo(f'Issuing CA of IDevID hierarchy {unique_name} stored at {file_path}')
    click.echo(f'Password: {password.decode()}.')


@idevid_hierarchy_export.command(name='trust-store')
@click.option('--unique-name', '-u', type=str, required=True)
@click.argument('file-path', type=click.Path(exists=False))
@handle_exception
def idevid_hierarchy_export_trust_store_as_pem(unique_name: str, file_path: str) -> None:
    trustpoint_client = TrustpointClient()
    if not file_path.endswith('.12'):
        file_path += '.p12'
    file_path = Path(file_path)
    if file_path.exists():
        raise click.ClickException(f'{file_path} already exists.')
    trust_store = trustpoint_client.export_idevid_hierarchy_trust_store_as_pem(unique_name)
    file_path.write_text(trust_store)
    click.echo(f'Trust-Store of IDevID hierarchy {unique_name} stored at {file_path}')


@idevid_hierarchy.command(name='delete')
@click.option('--unique-name', '-u', type=str, required=True)
@handle_exception
def idevid_hierarchy_delete(unique_name: str) -> None:
    trustpoint_client = TrustpointClient()
    if unique_name not in trustpoint_client.idevid_hierarchy_inventory.idevid_hierarchies:
        raise click.ClickException(f'{unique_name} does not exist.')
    trustpoint_client.delete_idevid_hierarchy(unique_name)
    click.echo(f'IDevID hierarchy {unique_name} deleted.')
