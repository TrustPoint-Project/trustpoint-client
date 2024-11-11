"""Trustpoint-Client commands concerning global configurations."""

from __future__ import annotations

from enum import Enum

import click
from prettytable import PrettyTable

from trustpoint_client.api import TrustpointClient
from trustpoint_client.api.exceptions import DomainDoesNotExist
from trustpoint_client.cli import domain_option_required, handle_exception


@click.group
def config() -> None:
    """Configuration options."""


@config.command(name='list')
@handle_exception
def config_list() -> None:
    """Lists the current configurations."""
    table = PrettyTable()
    table.field_names = ['Setting', 'Value']
    for key, value in TrustpointClient().config_as_dict.items():
        local_value = '' if value is None else value
        if isinstance(local_value, Enum):
            local_value = value.value
        local_key = str(key)
        local_value = str(local_value)
        table.add_row([str(local_key), str(local_value)])
    click.echo(f'\n{table}\n')


# --------------------------------------------------- Config Getter ----------------------------------------------------


@config.group(name='get')
def config_get() -> None:
    """Gets the specific configuration field"""


@config_get.command(name='default-domain')
@handle_exception
def config_get_default_domain() -> None:
    """Gets the current default trustpoint domain."""
    default_domain = TrustpointClient().default_domain
    if default_domain:
        click.echo(f'\n\tDefault domain: {default_domain}.\n')
    else:
        click.echo('\n\tNo default domain configured.\n')


# --------------------------------------------------- Config Setter ----------------------------------------------------


@config.group(name='set')
def config_set() -> None:
    """Sets the specific configuration field."""


@config_set.command(name='default-domain')
@domain_option_required
@handle_exception
def config_set_default_domain(domain: str) -> None:
    """Sets / overwrites the default trustpoint domain."""
    try:
        TrustpointClient().default_domain = domain
        click.echo(f'\n\tDefault domain configured: {domain}.\n')
    except DomainDoesNotExist as exception:
        click.echo(f'\n{exception}\n')


# --------------------------------------------------- Config Clearer ---------------------------------------------------


@config.group(name='clear')
def config_clear() -> None:
    """Clears the specific configuration field."""


@config_clear.command(name='default-domain')
@handle_exception
def config_clear_default_domain() -> None:
    """Clears the default trustpoint domain."""
    if TrustpointClient().default_domain is None:
        click.echo('\n\tNo default domain configured. Nothing to clear.\n')
        return

    if click.confirm(
        'Are you sure to clear the default trustpoint domain? '
        'You will have to explicitly state the domain with every command if no default domain is set.'
    ):
        del TrustpointClient().default_domain
        click.echo('\n\tDefault domain cleared.\n')
        return

    click.echo('\n\tAborted.\n')
