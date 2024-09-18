from __future__ import annotations

import click
from trustpoint_client.api.provision import ProvisioningState
from trustpoint_client.cli import get_trustpoint_client
from trustpoint_client.demo.callback_demo_leds import callback_demo

@click.group()
def demo():
    """Demo-specific commands"""
    pass

@demo.command(name='reset')
def demo_reset():
    """Resets demo
    
    This sets LED back to red"""

    # TODO: Also delete LDevID

    callback_demo(ProvisioningState.NO_TRUST)
