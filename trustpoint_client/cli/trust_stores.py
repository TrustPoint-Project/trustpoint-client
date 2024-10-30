from __future__ import annotations
import click


@click.group
def trust_stores() -> None:
    """Commands concerning trust-stores."""