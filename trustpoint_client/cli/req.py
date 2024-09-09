import click

@click.group
def req():
    """Request a new certificate or trust-store."""


@req.command(name='cert')
def req_certificate():
    """Request a new certificate."""


@req.command(name='ca-certs')
def req_ca_certs():
    """Requests the certificate chain for the issuing ca in use."""


@req.command(name='trust-store')
def req_trust_store():
    """Request a trust-store."""