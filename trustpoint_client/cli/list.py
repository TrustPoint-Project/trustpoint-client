import click


# noinspection PyShadowingBuiltins
@click.group()
def list_():
    """Lists keys, certificates and/or trust-stores."""


@list_.command(name='keys')
def list_keys():
    """Lists all available keys."""


@list_.command(name='certs')
def list_certificates():
    """Lists all available certificates."""


@list_.command(name='trust-stores')
def list_trust_stores():
    """Lists all available trust-stores."""