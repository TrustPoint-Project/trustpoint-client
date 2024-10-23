import click
from prettytable import PrettyTable
from enum import Enum
import ipaddress

from trustpoint_client.api import TrustpointClient


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

@config_get.command(name='ipv4')
def config_get_trustpoint_ipv4():
    """Gets the current Trustpoint IPv4 address."""
    trustpoint_ipv4 = TrustpointClient().trustpoint_ipv4
    if trustpoint_ipv4:
        click.echo(f'\n\tTrustpoint IPv4 address: {trustpoint_ipv4}\n')
    else:
        click.echo('\n\tNo Trustpoint IPv4 address configured.\n')

@config_get.command(name='port')
def config_get_trustpoint_port():
    """Gets the current Trustpoint port."""
    trustpoint_port = TrustpointClient().trustpoint_port
    if trustpoint_port:
        click.echo(f'\n\tTrustpoint port: {trustpoint_port}\n')
    else:
        click.echo('\n\tNo Trustpoint port configured.\n')

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

@config_set.command(name='ipv4')
@click.argument('trustpoint_ipv4', type=ipaddress.IPv4Address)
def config_set_trustpoint_ipv4(trustpoint_ipv4: ipaddress.IPv4Address):
    """Sets / overwrites the Trustpoint IPv4 address."""
    TrustpointClient().trustpoint_ipv4 = trustpoint_ipv4
    click.echo(f'\n\tTrustpoint IPv4 address configured: {trustpoint_ipv4}\n')

@config_set.command(name='port')
@click.argument('trustpoint_port', type=int)
def config_set_trustpoint_port(trustpoint_port: int):
    """Sets / overwrites the Trustpoint port."""
    TrustpointClient().trustpoint_port = trustpoint_port
    click.echo(f'\n\tTrustpoint port configured: {trustpoint_port}\n')

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

@config_clear.command(name='ipv4')
def config_clear_trustpoint_ipv4():
    """Clears the Trustpoint IPv4 address."""
    if TrustpointClient().trustpoint_ipv4 is None:
        click.echo('\n\tNo Trustpoint IPv4 address configured. Nothing to clear.\n')
        return

    if click.confirm(
            'Are you sure to clear the Trustpoint IPv4 Address?'):
        del TrustpointClient().trustpoint_ipv4
        click.echo(f'\n\tTrustpoint IPv4 address cleared.\n')
        return

    click.echo(f'\n\tAborted.\n')

@config_clear.command(name='port')
def config_clear_trustpoint_port():
    """Clears the Trustpoint port."""
    if TrustpointClient().trustpoint_port is None:
        click.echo('\n\tNo Trustpoint port configured. Nothing to clear.\n')
        return

    if click.confirm(
            'Are you sure to clear the Trustpoint port?'):
        del TrustpointClient().trustpoint_port
        click.echo(f'\n\tTrustpoint port cleared.\n')
        return

    click.echo(f'\n\tAborted.\n')
