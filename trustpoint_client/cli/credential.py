"""Contains all commands concerned with credential management."""
from __future__ import annotations

import click

@click.group
def credential() -> None:
    """Credential options."""
