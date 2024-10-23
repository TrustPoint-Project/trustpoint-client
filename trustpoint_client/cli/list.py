import click
from trustpoint_devid_module.serializer import CertificateCollectionSerializer

from trustpoint_client.cli import handle_cli_error
from trustpoint_client.api import TrustpointClient


@click.group()
def list_():
    """Lists keys, certificates and/or trust-stores."""

@list_.command(name='domain-credential')
# @handle_cli_error
def list_domain_credential():
    """Lists the domain credential."""
    trustpoint_client = TrustpointClient()
    config = trustpoint_client.config
    inventory = trustpoint_client.inventory
    devid_module = trustpoint_client.devid_module

    public_key = devid_module.inventory.devid_keys[
        inventory.domains[config.default_domain].ldevid_credential.key_index
    ].public_key.decode().replace('\n', '\n')

    certificate = devid_module.inventory.devid_certificates[
        inventory.domains[config.default_domain].ldevid_credential.active_certificate_index
    ].certificate.decode().replace('\n', '\n')

    certificate_chain = CertificateCollectionSerializer(devid_module.inventory.devid_certificates[
        inventory.domains[config.default_domain].ldevid_credential.active_certificate_index
    ].certificate_chain).as_pem().decode().replace('\n', '\n')

    click.echo(f'\nDomain-Credential for Domain: {config.default_domain}:\n')

    click.echo(f'Domain: {config.default_domain}.')
    domain_inventory = inventory.domains[config.default_domain]
    click.echo(f'Signature-Suite: {domain_inventory.signature_suite}')
    click.echo(f'Default-PKI-Protocol: {domain_inventory.pki_protocol.value}.')
    click.echo(f'\n\nPublic Key:\n\n{public_key}\n')
    click.echo(f'Certificate:\n\n{certificate}\n')
    click.echo(f'Certificate Chain:\n\n{certificate_chain}\n')
    click.echo(
        f'Trust-Store for verifying the Trustpoint TLS-Server Certificate:\n\n{domain_inventory.ldevid_trust_store}\n')

@list_.command(name='credential')
@click.argument('unique-name', type=str)
def list_credential(unique_name: str):
    """List the credential with the given unique name."""

@list_.command(name='credentials')
def list_credentials():
    """Lists all available keys."""

@list_.command(name='trust-store')
@click.argument('unique-name', type=str)
def list_truststore(unique_name: str):
    """List the trust-store with the given unique name."""

@list_.command(name='trust-stores')
def list_trust_stores():
    """Lists all available trust-stores."""
