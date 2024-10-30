import click
from prettytable import PrettyTable
from enum import Enum

from trustpoint_client.cli import domain_option_required
from trustpoint_client.api import TrustpointClient
from trustpoint_client.api.exceptions import DomainDoesNotExist

@click.group
def config():
    """Configuration options."""

@config.command(name='list')
def config_list():
    """Lists the current configurations."""
    table = PrettyTable()
    table.field_names = ['Setting', 'Value']
    for key, value in TrustpointClient().config_as_dict.items():
        if value is None:
            value = ''
        if isinstance(value, Enum):
            value = value.value
        key = str(key)
        value = str(value)
        table.add_row([str(key), str(value)])
    click.echo(f'\n{table}\n')

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

# --------------------------------------------------- Config Setter ----------------------------------------------------

@config.group(name='set')
def config_set():
    """Sets the specific configuration field."""

@config_set.command(name='default-domain')
@domain_option_required
def config_set_default_domain(domain: str):
    """Sets / overwrites the default trustpoint domain."""
    try:
        TrustpointClient().default_domain = domain
        click.echo(f'\n\tDefault domain configured: {domain}.\n')
    except DomainDoesNotExist as exception:
        click.echo(f'\n{exception}\n')

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
