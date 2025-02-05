"""Trustpoint-Client commands concerning status dumps."""

from __future__ import annotations

import click
from prettytable import PrettyTable

from trustpoint_client.api import TrustpointClientContext


@click.command
def status() -> None:
    """Purges all data of the Trustpoint Client."""
    inventory_model = TrustpointClientContext().inventory_model
    table = PrettyTable(['Attribute', 'Value'])
    table.add_row(['Device Serial Number', inventory_model.device_serial_number])
    table.add_row(['IDevID Available', False])
    table.add_row(['Is Onboarded', bool(inventory_model.default_domain)])
    table.add_row(['Default Domain', inventory_model.default_domain])
    click.echo(table)