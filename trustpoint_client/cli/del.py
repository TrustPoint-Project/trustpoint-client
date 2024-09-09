import click


@click.group
def del_():
    """Deletes credentials or trust-stores."""


@del_.command(name='credential')
def del_credential():
    """Deletes a credential."""


@del_.command(name='trust-store')
def del_truststore():
    """Deletes a trust-store."""
