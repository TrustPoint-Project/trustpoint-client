"""Command-line interface for the Trustpoint-Client."""
from __future__ import annotations


import click


@click.group
def provision():
    """Provisions this device."""