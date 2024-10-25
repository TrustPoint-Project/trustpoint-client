import click
from itertools import islice

from trustpoint_client.api import TrustpointClient

import prettytable


@click.group(name='domain')
def credential():
    """Commands concerning domains."""


@credential.command(name='list')
@click.option(
    '--domain', '-d',
    type=str,
    required=False,
    help='The desired domain. Defaults to the default domain.')
@click.option(
    '--domain-credential', '-c',
    is_flag=True,
    required=False,
    help='Lists the specific domain credential.')
@click.argument('unique-name', type=str, required=False)
def credential_list(domain: None | str, domain_credential: bool, unique_name: None | str) -> None:
    trustpoint_client = TrustpointClient()
    result = trustpoint_client.list_credential(domain, domain_credential, unique_name)

    if not result['credentials']:
        click.echo('\nNo credentials found to list.\n')
        return

    table = prettytable.PrettyTable(['Property', 'Value'])
    for key, value in result['header'].items():
        table.add_row([key, value])
    click.echo(table)
    click.echo('\n')

    for credential_entry, value in result['credentials'].items():
        click.echo(credential_entry)
        click.echo()
        for k, v in value.items():
            click.echo(k)
            click.echo(v)


@credential.command(name='delete')
@click.option(
    '--domain', '-d',
    type=str,
    required=False,
    help='The desired domain. Defaults to the default domain.')
@click.argument('unique-name', type=str, required=True)
def credential_delete(domain: None | str, unique_name: str) -> None:
    trustpoint_client = TrustpointClient()
    if not domain:
        domain = trustpoint_client.default_domain
    if not domain:
        click.echo()
        raise click.ClickException('No default domain configured. Nothing to delete.\n')
    if not trustpoint_client.credential_exists(domain, unique_name):
        click.echo()
        raise click.ClickException(f'No credential for the unique name {unique_name} and domain {domain} found.\n')

    if click.confirm(
            f'Are you sure you want to delete the credential with unique name {unique_name} and domain {domain}?'
            'This action is irreversible!'):
        if trustpoint_client.delete_credential(domain, unique_name):
            click.echo(f'\nCredential with unique name {unique_name} and domain {domain} successfully deleted.\n')
            return

        click.echo()
        raise click.ClickException(
            f'Failed to delete the credential with unique name {unique_name} and domain {domain}.\n')
    else:
        click.echo('\nAborted.\n')

