"""Contains all commands concerned with onboarding the device into a domain."""
from __future__ import annotations

import click
from prettytable import PrettyTable

from trustpoint_client.api import TrustpointClientContext
from trustpoint_devid_module.service_interface import DevIdModule


@click.group()
def domain() -> None:
    """Commands concerning domains."""


@domain.command(name='list')
@click.option('--verbose', '-v', is_flag=True, default=False, help='Will also list associated certificates')
def domain_list(verbose: bool = False) -> None:
    """Lists all onboarded domains.

    At this time, only a single domain is supported.
    """
    inventory_model = TrustpointClientContext().inventory_model

    if not inventory_model.default_domain:
        click.echo('No default domain configured. Nothing to list.')
        return

    domain_model = inventory_model.domains[inventory_model.default_domain]

    table = PrettyTable(['Attribute', 'Value'])
    table.add_row(['Domain Name', inventory_model.default_domain])
    table.add_row(['Is Default Domain', True])
    table.add_row(['Device Serial-Number', inventory_model.device_serial_number])
    table.add_row(['Subject', domain_model.domain_credential.subject])
    table.add_row(['Credential Type', domain_model.domain_credential.certificate_type])
    table.add_row(['Not Valid Before', domain_model.domain_credential.not_valid_before])
    table.add_row(['Not Valid After', domain_model.domain_credential.not_valid_after])
    for address in domain_model.domain_config.trustpoint_addresses:
        table.add_row(['Trustpoint Address', address])
    table.add_row(['Issued Application Certificates', len(domain_model.credentials)])

    click.echo(table)

    if verbose:
        devid_module = DevIdModule()

        domain_credential_certificate = devid_module.inventory.devid_certificates[
            domain_model.domain_credential.certificate_index
        ].certificate.decode().strip()

        domain_credential_certificate_chain = [
            certificate.decode().strip() for certificate in
            devid_module.inventory.devid_certificates[
                domain_model.domain_credential.certificate_index
            ].certificate_chain
        ]

        click.echo('\nDomain Credential Certificate:')
        click.echo(domain_credential_certificate)

        click.echo('\nDomain Credential Certificate Chain:')
        for certificate in domain_credential_certificate_chain:
            click.echo(certificate)




@domain.command(name='delete')
def domain_delete() -> None:
    """Deletes the desired domain.

    At this time, this will delete the default domain.
    """
    trustpoint_client_context = TrustpointClientContext()
    inventory_model = trustpoint_client_context.inventory_model

    if not inventory_model.default_domain:
        click.echo('No default domain configured. Nothing to delete.')
        return

    if click.confirm(f'Are you sure you want to delete the default domain {inventory_model.default_domain}?'):
        # TODO(AlexHx8472): Delete all application credentials first.
        devid_module = DevIdModule()

        domain_credential_key_index = inventory_model.domains[
            inventory_model.default_domain
        ].domain_credential.key_index

        domain_credential_certificate_index = inventory_model.domains[
            inventory_model.default_domain
        ].domain_credential.certificate_index

        devid_module.delete_ldevid_certificate_chain(certificate_index=domain_credential_certificate_index)
        devid_module.delete_ldevid_certificate(certificate_index=domain_credential_certificate_index)
        devid_module.delete_ldevid_key(key_index=domain_credential_key_index)

        inventory_model.default_domain = None
        inventory_model.domains = {}

        trustpoint_client_context.store_inventory()

    else:
        click.echo('Aborted.')