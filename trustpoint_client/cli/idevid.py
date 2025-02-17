"""Commands concerning IDevID management."""
from __future__ import annotations


import click
from pathlib import Path

from prettytable import PrettyTable

from trustpoint_client.api import TrustpointClientContext
from trustpoint_client.api.idevid import inject_idevid, delete_idevid


@click.group
def idevid() -> None:
    """Commands concerning IDevID management."""

@idevid.command(name='inject')
@click.option('--file-path', '-f', type=click.Path(exists=True), required=True, help='IDevID as PKCS#12 file.')
@click.option('--password', '-p', type=str, required=False, default=None, help='Password to encrypt the PKCS#12 file, if any.')
def idevid_inject(file_path: str, password: None | str) -> None:
    """Injects an IDevID credential into the client."""

    if isinstance(password, str):
        encoded_password = password.encode()
    else:
        encoded_password = None

    try:
        p12_bytes = Path(file_path).read_bytes()
        inject_idevid(p12_bytes, password=encoded_password)
        click.echo('Successfully injected IDevID credential into the Trustpoint-Client.')
    except Exception as exception:
        raise click.ClickException(str(exception)) from exception

@idevid.command(name='delete')
@click.option('--signature-suite', '-s', type=str, required=True, help='Signature suite identifier of the IDevID to delete.')
def idevid_delete(signature_suite: str) -> None:

    if click.confirm(
            f'Are you sure you want to delete the IDevID with signature suite {signature_suite} '
            f'from the Trustpoint-Client?'):

        try:
            delete_idevid(signature_suite)
            click.echo(
                f'Successfully deleted IDevID credential from the Trustpoint-Client for signature suite {signature_suite}.')
        except Exception as exception:
            raise click.ClickException(str(exception)) from exception

    else:
        click.echo('Aborted.')

@idevid.command(name='list')
def idevid_list() -> None:

    trustpoint_client_context = TrustpointClientContext()
    if not trustpoint_client_context.inventory_model.idevids:
        click.echo('No IDevIDs installed. Nothing to list.')

    table = PrettyTable(['IDevID Signature Suite', 'IDevID Subject'])
    for signature_suite, credential_model in trustpoint_client_context.inventory_model.idevids.items():
        table.add_row([signature_suite, credential_model.subject])
    click.echo(table)
