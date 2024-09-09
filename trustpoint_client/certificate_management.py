import click

from trustpoint_client.cli import cli


# ----------------------------------------------- trustpoint-client list -----------------------------------------------

def domain_option(function):
    print(type(function))
    function = click.option(
        '--domain', '-d', type=str,
        required=False, default='default',
        help='Selects the desired domain.')(function)
    print(type(function))
    return function

# ----------------------------------------------- trustpoint-client list -----------------------------------------------


@click.group()
def cli():
    """Lists keys, certificates and/or trust-stores."""


# @list_.command(name='keys')
# def list_keys():
#     """Lists all available keys."""
#
#
# @list_.command(name='certs')
# def list_certificates():
#     """Lists all available certificates."""
#
#
# @list_.command(name='trust-stores')
# def list_trust_stores():
#     """Lists all available trust-stores."""


# --------------------------------------------- trustpoint-client request ----------------------------------------------


@cli.group(name='req')
def request():
    """Request a new certificate or trust-store."""


@request.command(name='cert')
def request_certificate():
    """Request a new certificate."""


@click.command(name='ca-certs')
def request_ca_certs():
    """Requests the certificate chain for the issuing ca in use."""


@request.command(name='trust-store')
def request_trust_store():
    """Request a trust-store."""


# ---------------------------------------------- trustpoint-client renew -----------------------------------------------


@click.command(name='renew')
def renew():
    """Renews an existing certificate"""


# ---------------------------------------------- trustpoint-client revoke ----------------------------------------------


@click.command(name='revoke')
def revoke():
    """Revokes an existing certificate."""


# ----------------------------------------- trustpoint-client revoke & delete ------------------------------------------


@cli.group(name='del')
def delete():
    """Deletes keys, certificates, ca-certs and/or trust-stores."""


@click.command(name='credential')
def delete_credential():
    """Deletes the key, certificate and ca-certs corresponding to the given name."""


@click.command(name='trust-store')
def delete_certificate():
    """Deletes the certificate and """