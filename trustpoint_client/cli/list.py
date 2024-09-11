import click


# noinspection PyShadowingBuiltins
@click.group()
def list_():
    """Lists keys, certificates and/or trust-stores."""


@list_.command(name='credential')
def list_credentials():
    """Lists all available keys."""


@list_.command(name='trust-stores')
def list_trust_stores():
    """Lists all available trust-stores."""