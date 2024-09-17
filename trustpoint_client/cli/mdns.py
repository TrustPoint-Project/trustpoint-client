from __future__ import annotations

import click
from trustpoint_client.cli import handle_cli_error
from trustpoint_client.api.mdns import find_services

@click.group
def mdns():
    """mDNS commands"""


@mdns.command(name='find') #@handle_cli_error
def mdns_find():
    """Finds potential Trustpoint servers on the network using mDNS."""
    find_services(zero_touch=False)