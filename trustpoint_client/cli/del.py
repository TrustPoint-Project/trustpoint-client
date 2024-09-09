import click


@click.group
def del_():
    """Deletes keys, certificates, ca-certs and/or trust-stores."""
