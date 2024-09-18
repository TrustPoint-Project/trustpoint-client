import click
from prettytable import PrettyTable

from trustpoint_client.cli import get_client_config
from trustpoint_client.api.schema import PkiProtocol



@click.group
def config():
    """Configuration options."""


@config.command(name='list')
def config_list():
    """Lists the current configurations."""
    client_config = get_client_config()
    table = PrettyTable()
    table.field_names = ['Setting', 'Value']
    for key, value in client_config.list_config().items():
        if value is None:
            value = ''
        if isinstance(value, PkiProtocol):
            value = value.value
        key = str(key)
        value = str(value)
        table.add_row([str(key), str(value)])
    click.echo(f'\n{table}\n')


@config.command(name='sync')
def config_sync():
    """Gets the current configurations from the Trustpoint."""


@config.command(name='get-default-domain')
def config_get_default_domain():
    """Gets the current default trustpoint domain."""
    client_config = get_client_config()
    if client_config.default_domain:
        click.echo(f'\n\tDefault domain: {client_config.default_domain}.\n')
    else:
        click.echo('\n\tNo default domain configured.\n')

@config.command(name='set-default-domain')
@click.argument('domain', type=str)
def config_set_default_domain(domain: str):
    """Sets / overwrites the default trustpoint domain."""
    client_config = get_client_config()
    client_config.default_domain = domain
    click.echo(f'\n\tDefault domain configured: {domain}.\n')


@config.command(name='get-pki-protocol')
def config_get_default_pki_protocol():
    """Gets the currently used pki-protocol."""
    client_config = get_client_config()
    if client_config.pki_protocol:
        click.echo(f'\n\tPki protocol: {client_config.pki_protocol.value}.\n')
    else:
        click.echo('\n\tNo PKI protocol configured.\n')


@config.command(name='set-pki-protocol')
@click.argument('pki-protocol', type=click.Choice([protocol.value for protocol in PkiProtocol]))
def config_set_default_pki_protocol(pki_protocol: str):
    """Sets the pki-protocol to use."""
    pki_protocol = PkiProtocol(pki_protocol)
    client_config = get_client_config()
    client_config.pki_protocol = pki_protocol
    click.echo(f'\n\tPKI protocol configured: {pki_protocol.value}.\n')
