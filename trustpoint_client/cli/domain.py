import traceback
from inspect import trace
from multiprocessing.managers import Value

import click
from trustpoint_devid_module.serializer import CertificateCollectionSerializer

from trustpoint_client.cli import handle_cli_error
from trustpoint_client.api import TrustpointClient

import prettytable

@click.group(name='domain')
def domain_():
    """Commands concerning domains."""


def echo_single_domain_info_table(dict_: dict[str, str]) -> None:
    table = prettytable.PrettyTable(['Property', 'Value'])
    table.align = 'l'
    for key, value in dict_.items():
        table.add_row([key, value])
    click.echo(table)


@domain_.command(name='list')
@click.option('--default', '-d', is_flag=True, default=False, help='Lists the default domain.')
@click.argument('domain_name', required=False, type=str, default=None)
@handle_cli_error
def domain_list(default: bool, domain_name: None | str) -> None:
    """Lists information about the default or specified domain."""
    trustpoint_client = TrustpointClient()
    if default is True:
        domain_info = trustpoint_client.list_domain()
        echo_single_domain_info_table(domain_info)
        return

    if domain_name:
        domain_info = trustpoint_client.list_domain(domain_name)
        echo_single_domain_info_table(domain_info)
        return

    domain_info = trustpoint_client.list_all_domains()
    for _, value in domain_info.items():
        echo_single_domain_info_table(value)

@domain_.command(name='delete')
@click.argument('domain_name', required=True, type=str)
def domain_delete(domain_name: str) -> None:
    """Deletes the specific domain and all corresponding credentials.

    \b
    Remark:
    -------
    Certificates are currently not revoked, but just deleted.
    """
    trustpoint_client = TrustpointClient()
    if click.confirm(
            f'Are you sure you want to delete the domain {domain_name}? '
            f'This will delete all corresponding credentials and data.'):
        try:
            trustpoint_client.delete_domain(domain_name)
        except ValueError as exception:
            click.echo(f'\n{exception}\n')
            return
        click.echo(f'Successfully deleted domain {domain_name} and all corresponding credentials and data.')
        return
    click.echo('Aborted.')
