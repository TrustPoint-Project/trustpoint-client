import click
from prettytable import PrettyTable
from enum import Enum

from trustpoint_client.api import TrustpointClient
from trustpoint_client.api.schema import PkiProtocol


@click.group
def config():
    """Configuration options."""

@config.command(name='list')
def config_list():
    """Lists the current configurations."""
    table = PrettyTable()
    table.field_names = ['Setting', 'Value']
    for key, value in TrustpointClient().get_config_as_dict().items():
        if value is None:
            value = ''
        if isinstance(value, Enum):
            value = value.value
        key = str(key)
        value = str(value)
        table.add_row([str(key), str(value)])
    click.echo(f'\n{table}\n')

@config.command(name='sync')
def config_sync():
    """Gets the current configurations from the Trustpoint."""

# --------------------------------------------------- Config Getter ----------------------------------------------------

@config.group(name='get')
def config_get():
    """Gets the specific configuration field"""

@config_get.command(name='default-domain')
def config_get_default_domain():
    """Gets the current default trustpoint domain."""
    default_domain = TrustpointClient().default_domain
    if default_domain:
        click.echo(f'\n\tDefault domain: {default_domain}.\n')
    else:
        click.echo('\n\tNo default domain configured.\n')

@config_get.command(name='default-pki-protocol')
def config_get_default_pki_protocol():
    """Gets the current default trustpoint domain."""
    default_pki_protocol = TrustpointClient().default_pki_protocol
    if default_pki_protocol:
        click.echo(f'\n\tDefault pki protocol: {default_pki_protocol}.\n')
    else:
        click.echo('\n\tNo default pki protocol configured.\n')

# --------------------------------------------------- Config Setter ----------------------------------------------------

@config.group(name='set')
def config_set():
    """Sets the specific configuration field."""

@config_set.command(name='default-domain')
@click.argument('domain', type=str)
def config_set_default_domain(domain: str):
    """Sets / overwrites the default trustpoint domain."""
    TrustpointClient().default_domain = domain
    click.echo(f'\n\tDefault domain configured: {domain}.\n')

@config_set.command(name='default-pki-protocol')
@click.argument('default-pki-protocol', type=str)
def config_set_default_pki_protocol(default_pki_protocol: str):
    """Sets / overwrites the default trustpoint domain."""
    TrustpointClient().default_pki_protocol = default_pki_protocol
    click.echo(f'\n\tDefault pki protocol configured: {default_pki_protocol}.\n')

# --------------------------------------------------- Config Clearer ---------------------------------------------------

@config.group(name='clear')
def config_clear():
    """Clears the specific configuration field."""

@config_clear.command(name='default-domain')
def config_clear_default_domain():
    """Clears the default trustpoint domain."""
    if TrustpointClient().default_domain is None:
        click.echo('\n\tNo default domain configured. Nothing to clear.\n')
        return

    if click.confirm(
            'Are you sure to clear the default trustpoint domain? '
            'You will have to explicitly state the domain with every command if no default domain is set.'):
        del TrustpointClient().default_domain
        click.echo(f'\n\tDefault domain cleared.\n')
        return

    click.echo(f'\n\tAborted.\n')

@config_clear.command(name='default-pki-protocol')
def config_clear_default_pki_protocol():
    """Clears the default trustpoint domain."""
    if TrustpointClient().default_pki_protocol is None:
        click.echo('\n\tNo default pki protocol configured. Nothing to clear.\n')
        return

    if click.confirm(
            'Are you sure to clear the default pki protocol? '
            'You will have to explicitly state the pki protocol to '
            'use with every command if no default pki protocol is set.'):
        del TrustpointClient().default_pki_protocol
        click.echo(f'\n\tDefault pki protocol cleared.\n')
        return

    click.echo(f'\n\tAborted.\n')