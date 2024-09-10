import click


@click.group
def config():
    """Configuration options."""


@config.command(name='list')
def config_list():
    """Lists the current configurations."""


@config.command(name='sync')
def config_sync():
    """Gets the current configurations from the Trustpoint."""


@config.command(name='get-default-domain')
def config_get_default_domain():
    """Gets the current default trustpoint domain."""


@config.command(name='set-default-domain')
def config_set_default_domain():
    """Sets / overwrites the default trustpoint domain."""


@config.command(name='set-pki-protocol')
def config_get_default_pki_protocol():
    """Gets the currently used pki-protocol."""


@config.command(name='set-pki-protocol')
def config_set_default_pki_protocol():
    """Sets the pki-protocol to use."""
