"""Trustpoint-Client commands concerning global configurations."""

from __future__ import annotations

import click

from trustpoint_client.api import TrustpointClientError, get_table_from_dict
from trustpoint_client.api.config import (
    get_config,
    get_default_domain,
    get_device_serial_number,
    set_default_domain,
    set_device_serial_number,
)


@click.group
def config() -> None:
    """Configuration options."""


@config.command(name='list')
def config_list() -> None:
    """Lists the current configurations."""
    click.echo(get_table_from_dict(data=get_config(), key_header='Configuration'))


@config.group(name='get')
def config_get() -> None:
    """Commands for getting specific configurations manually."""


@config.group(name='set')
def config_set() -> None:
    """Commands for setting specific configurations manually."""


@config.group(name='clear')
def config_clear() -> None:
    """Commands for clearing configuration manually."""


@config_clear.command(name='all')
def config_clear_all() -> None:
    """Clears all global configurations."""
    try:
        set_default_domain(None)
        set_device_serial_number(None)
    except TrustpointClientError as exception:
        raise click.ClickException(str(exception)) from exception
    click.echo('All global configurations have been cleared.')


@config_get.command(name='default_domain')
def config_get_default_domain() -> None:
    """Gets the default domain."""
    click.echo(get_default_domain())


@config_set.command(name='default_domain')
@click.argument('default_domain', type=str)
def config_set_default_domain(default_domain: str) -> None:
    """Sets the default domain.

    Args:
        default_domain: The default domain to set.
    """
    try:
        set_default_domain(default_domain)
    except TrustpointClientError as exception:
        raise click.ClickException(str(exception)) from exception
    click.echo(f'Default domain set to {default_domain}.')


@config_clear.command(name='default_domain')
def config_clear_default_domain() -> None:
    """Clears the default domain."""
    try:
        set_default_domain(None)
    except TrustpointClientError as exception:
        raise click.ClickException(str(exception)) from exception
    click.echo('Default domain cleared.')


@config_get.command(name='device_serial_number')
def config_get_device_serial_number() -> None:
    """Gets the device serial number."""
    click.echo(get_device_serial_number())


@config_set.command(name='device_serial_number')
@click.argument('device_serial_number', type=str)
def config_set_device_serial_number(device_serial_number: str) -> None:
    """Sets the device serial number.

    Args:
        device_serial_number: The device serial number to set.
    """
    current_serial_number = get_device_serial_number()
    if current_serial_number is None or click.confirm(
        f'The current device serial number is {current_serial_number}. '
        f'The device serial number must match the serial number field in DevID certificate subjects.'
        f'Are you sure you want to overwrite it?'
    ):
        set_device_serial_number(device_serial_number)
        click.echo(f'Device serial number set to: {device_serial_number}.')
    else:
        click.echo('Aborted. Device serial number was not modified.')


@config_clear.command(name='device_serial_number')
def config_clear_device_serial_number() -> None:
    """Clears the device serial number."""
    try:
        set_device_serial_number(None)
    except TrustpointClientError as exception:
        raise click.ClickException(str(exception)) from exception
    click.echo('Device serial number cleared.')
