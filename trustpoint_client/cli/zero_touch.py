from __future__ import annotations

import click
from trustpoint_client.cli import get_trustpoint_client, handle_cli_error
from trustpoint_client.api.mdns import find_services
from trustpoint_client.api.zero_touch_aoki import aoki_onboarding


@click.group()
def zero_touch():
    """Zero-touch onboarding commands"""
    pass

@zero_touch.command(name='start')
#@handle_cli_error
@click.option('--host', '-h', required=False, type=str, help='The domain or IP address of the Trustpoint. For testing without discovery.')
@click.option('--port', '-p', required=False, type=int, default=443, help='The port of the Trustpoint if not 443. For testing without discovery.')
def zero_touch_start(host: str, port: int):
    """Starts the AOKI demo zero-touch onboarding process."""

    trustpoint_client = get_trustpoint_client()

    if host is None: # regular zero-touch onboarding with mDNS discovery
        find_services(zero_touch=True)
        return
    
    # check if host contains a port
    if ':' in host:
        host, port = host.split(':')
        port = int(port)

    aoki_onboarding(host, port)
