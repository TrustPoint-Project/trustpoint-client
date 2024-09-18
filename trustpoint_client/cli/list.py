import click
from trustpoint_devid_module.serializer import CertificateCollectionSerializer

from trustpoint_client.cli import get_trustpoint_client, handle_cli_error


@click.group()
def list_():
    """Lists keys, certificates and/or trust-stores."""


@list_.command(name='domain-credential')
@handle_cli_error
def list_domain_credential():
    """Lists the domain credential."""
    trustpoint_client = get_trustpoint_client()
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
    click.echo('Signature-Suite: RSA2096-SHA256.')
    click.echo(f'Default-PKI-Protocol: {config.pki_protocol.value}.')
    click.echo(f'\n\nPublic Key:\n\n{public_key}\n')
    click.echo(f'Certificate:\n\n{certificate}\n')
    click.echo(f'Certificate Chain:\n\n{certificate_chain}\n')
    click.echo(f'Trust-Store for verifying the Trustpoint TLS-Server Certificate:\n\n{inventory.domains[config.default_domain].ldevid_trust_store}\n')



@list_.command(name='credential')
def list_credentials():
    """Lists all available keys."""


@list_.command(name='trust-stores')
def list_trust_stores():
    """Lists all available trust-stores."""