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
def zero_touch_start():
    """Starts the AOKI demo zero-touch onboarding process."""

    trustpoint_client = get_trustpoint_client()
    find_services(zero_touch=True)
