from __future__ import annotations
import click

from trustpoint_client.enums import (
    CertificateFormat,
    CertificateCollectionFormat,
    PublicKeyFormat,
    PrivateKeyFormat
)
from trustpoint_client.cli import domain_option_optional, verbose_option
from trustpoint_client.api import TrustpointClient
from trustpoint_client.api.credentials import BasicConstraintsExtension, KeyUsageExtension, ExtendedKeyUsageExtension
import prettytable
from pathlib import Path
import uuid

BASE_PATH = Path('__file__').resolve().parent / 'trustpoint_client/demo_data'


@click.group(name='credential')
def credentials():
    """Commands concerning domains."""


def _credential_list(domain: None | str, verbose: bool, unique_name: None | str) -> None:
    trustpoint_client = TrustpointClient()
    if domain is None:
        domain = trustpoint_client.default_domain

    result = trustpoint_client.list_credential(domain, unique_name, verbose)

    if not result['credentials']:
        click.echo('\nNo credentials found to list.\n')
        return

    click.echo(f'\nDomain: {domain}')
    table = prettytable.PrettyTable(['Property', 'Value'])
    for key, value in result['header'].items():
        table.add_row([key, value])
    click.echo(table)
    click.echo('\n')

    for i, (unique_name, value) in enumerate(result['credentials'].items()):
        click.echo(f'\n\nCredential #{i}: {unique_name}')
        cred_table = prettytable.PrettyTable(['Property', 'Value'])
        cert = value.pop('Credential Certificate', None)
        pub_key = value.pop('Credential Public-Key', None)
        cert_chain = value.pop('Credential Certificate Chain', None)
        for k, v in value.items():
            cred_table.add_row([k, v])
        click.echo(cred_table)
        click.echo()

        if cert:
            click.echo(f'\nCredential Certificate: {unique_name}')
            click.echo(64 * '-' + '\n')
            click.echo(cert)

        if pub_key:
            click.echo(f'\nCredential Public-Key: {unique_name}')
            click.echo(64 * '-' + '\n')
            click.echo(cert)

        if cert_chain:
            click.echo(f'\nCredential Certificate-Chain: {unique_name}')
            click.echo(64 * '-' + '\n')
            click.echo(cert)


@credentials.command(name='list')
@domain_option_optional
@verbose_option
@click.argument('unique-name', type=str, required=False)
def credential_list(domain: None | str, verbose: bool, unique_name: None | str) -> None:
    _credential_list(domain, verbose, unique_name)


@credentials.command(name='delete')
@click.option(
    '--domain', '-d',
    type=str,
    required=False,
    help='The desired domain. Defaults to the default domain.')
@click.argument('unique-name', type=str, required=True)
def credential_delete(domain: None | str, unique_name: str) -> None:
    trustpoint_client = TrustpointClient()
    if not domain:
        domain = trustpoint_client.default_domain
    if not domain:
        click.echo()
        raise click.ClickException('No default domain configured. Nothing to delete.\n')
    if not trustpoint_client.credential_exists(domain, unique_name):
        click.echo()
        raise click.ClickException(f'No credential for the unique name {unique_name} and domain {domain} found.\n')

    if click.confirm(
            f'Are you sure you want to delete the credential with unique name {unique_name} and domain {domain}?'
            'This action is irreversible!'):
        if trustpoint_client.delete_credential(domain, unique_name):
            click.echo(f'\nCredential with unique name {unique_name} and domain {domain} successfully deleted.\n')
            return

        click.echo()
        raise click.ClickException(
            f'Failed to delete the credential with unique name {unique_name} and domain {domain}.\n')
    else:
        click.echo('\nAborted.\n')

@credentials.group
def export():
    """Export credentials in different formats."""

@export.command(name='credential')
@domain_option_optional
@click.option(
    '--password', '-pw',
    type=str,
    required=False,
    default=None,
    help='The password used to encrypt the file.')
@click.option('--unique-name', '-u', type=str, required=True)
@click.option('--pkcs12-out', '-o', type=click.Path(), required=True)
def export_credential(domain: None | str, password: None | str, unique_name: str, pkcs12_out: str) -> None:
    """Exports the whole credential as PKCS#12 file.

    If no password is provided, a new password with 12 characters will be generated and be echoed to the terminal.
    """
    trustpoint_client = TrustpointClient()
    if isinstance(password, str):
        password = password.encode()
    pkcs12_bytes, pkcs12_password = trustpoint_client.export_credential_as_pkcs12(domain, unique_name, password)

    if not pkcs12_out.endswith('.p12'):
        pkcs12_out += '.p12'
    pkcs12_path = Path(pkcs12_out)
    pkcs12_path.write_bytes(pkcs12_bytes)

    click.echo(f'\nPKCS#12 file saved: {pkcs12_path.resolve()}\n')

    if password != pkcs12_password:
        click.echo(f'PKCS#12 File encrypted with password {pkcs12_password.decode()}.\n')


@export.command(name='certificate')
@domain_option_optional
@click.option('--unique-name', '-u', type=str, required=True)
@click.option(
    '--format-out', '-f',
    type=click.Choice([format_.value for format_ in CertificateFormat]),
    required=False,
    default=CertificateFormat.PEM.value)
@click.option('--certificate-out', '-o', type=click.Path(), required=True)
def export_certificate(domain: None | str, unique_name: str, format_out: str, certificate_out: str) -> None:
    """Exports the credential certificate."""
    trustpoint_client = TrustpointClient()
    cert_format = CertificateFormat(format_out)
    cert_bytes = trustpoint_client.export_certificate(domain, unique_name, cert_format)

    if not certificate_out.endswith(cert_format.file_extension):
        certificate_out += cert_format.file_extension
    cert_path = Path(certificate_out)
    cert_path.write_bytes(cert_bytes)

    click.echo(f'\nCertificate file saved (Format: {format_out}): {cert_path.resolve()}\n')


@export.command(name='certificate-chain')
@domain_option_optional
@click.option('--unique-name', '-u', type=str, required=True)
@click.option(
    '--format-out', '-f',
    type=click.Choice([format_.value for format_ in CertificateCollectionFormat]),
    required=False,
    default=CertificateCollectionFormat.PEM.value)
@click.option('--certificate-chain-out', '-o', type=click.Path(), required=True)
def export_certificate_chain(domain: None | str, unique_name: str, format_out: str, certificate_chain_out: str):
    """Exports the credential certificate-chain."""
    trustpoint_client = TrustpointClient()
    cert_chain_format = CertificateCollectionFormat(format_out)
    cert_chain_bytes = trustpoint_client.export_certificate_chain(
        domain, unique_name, cert_chain_format)

    if not certificate_chain_out.endswith(cert_chain_format.file_extension):
        certificate_chain_out += cert_chain_format.file_extension
    cert_chain_path = Path(certificate_chain_out)
    cert_chain_path.write_bytes(cert_chain_bytes)

    click.echo(f'\nCertificate chain file saved (Format: {format_out}): {cert_chain_path.resolve()}\n')


@export.command(name='public-key')
@domain_option_optional
@click.option('--unique-name', '-u', type=str, required=True)
@click.option(
    '--format-out', '-f',
    type=click.Choice([format_.value for format_ in PublicKeyFormat]),
    required=False,
    default=PublicKeyFormat.PEM.value)
@click.option('--public-key-out', '-o', type=click.Path(), required=True)
def export_public_key(domain: None | str, unique_name: str, format_out: str, public_key_out: str):
    """Exports the credential public-key."""
    trustpoint_client = TrustpointClient()
    public_key_format = PublicKeyFormat(format_out)
    public_key_bytes = trustpoint_client.export_public_key(domain, unique_name, public_key_format)

    if not public_key_out.endswith(public_key_format.file_extension):
        public_key_out += public_key_format.file_extension
    pub_key_path = Path(public_key_out)
    pub_key_path.write_bytes(public_key_bytes)

    click.echo(f'\nPublic key file saved (Format: {format_out}): {pub_key_path.resolve()}\n')


@export.command(name='private-key')
@domain_option_optional
@click.option(
    '--password', '-pw',
    type=str,
    required=False,
    default=None,
    help='The password used to encrypt the file.')
@click.option('--unique-name', '-u', type=str, required=True)
@click.option(
    '--format-out', '-f',
    type=click.Choice([format_.value for format_ in PrivateKeyFormat]),
    required=False,
    default=PrivateKeyFormat.PKCS8_PEM.value)
@click.option('--private-key-out', '-o', type=click.Path(), required=True)
def export_private_key(
        domain: None | str, password: None | str, unique_name: str, format_out: str, private_key_out: str):
    """Exports the credential private-key."""
    trustpoint_client = TrustpointClient()
    if isinstance(password, str):
        password = password.encode()
    private_key_format = PrivateKeyFormat(format_out)
    private_key_bytes, private_key_password = trustpoint_client.export_private_key(
        domain, unique_name, password, private_key_format
    )

    if not private_key_out.endswith(private_key_format.file_extension):
        private_key_out += private_key_format.file_extension
    private_key_path = Path(private_key_out)
    private_key_path.write_bytes(private_key_bytes)

    click.echo(f'\nPrivate key file saved (Format: {format_out}): {private_key_path.resolve()}\n')

    if password != private_key_password:
        click.echo(f'Private key file encrypted with password {private_key_password.decode()}.\n')


@credentials.command
def renew():
    """Renews a certificate."""

@credentials.group
def revoke():
    """Revokes a certificate."""


# TODO(AlexHx8472): This information should be part of MAN pages, not of the help directly.
@credentials.group
def request() -> None:
    """Request a new certificate or trust-store."""

@request.command(name='generic')
@click.option(
    '--subject', '-s',
    type=str,
    help='Subject Entry in the form <Abbreviation, name or OID>:<value>',
    multiple=True,
    default=[f'CN:Trustpoint Generic Certificate', f'serialNumber:{uuid.uuid4()}'])
@click.option(
    '--validity-years', '-vy',
    type=int,
    required=False,
    default=0,
    help='Desired validity in years. Days will be added.')
@click.option(
    '--validity-days', '-vd',
    type=int,
    required=False,
    default=365,
    help='Desired validity in days. Will be added to years, if provided.')
@click.option('--basic-constraints', '-bc', type=str, required=False)
@click.option('--key-usage', '-ku', type=str, required=False)
@click.option('--extended-key-usage', '-eku', type=str, required=False)
@click.argument('unique_name', type=str, required=True)
def request_generic(
        subject: list[str],
        validity_years: int,
        validity_days: int,
        basic_constraints: None | str,
        key_usage: None | str,
        extended_key_usage: None | str,
        unique_name: str) -> None:
    """Request Generic Certificate

\b
Subject Options:
----------------

\b
Supported abbreviations, names and OIDs for the desired subject:
    - CN : commonName : 2.5.4.3
    - L : localityName : 2.5.4.6
    - S : ST : stateOrProvinceName : 2.5.4.8
    - streetAddress : 2.5.4.9
    - O : organizationName : 2.5.4.10
    - OU : organizationalUnitName : 2.5.4.11
    - serialNumber : 2.5.4.5
    - SN : surName : 2.5.4.4
    - GN : givenName : 2.5.4.42
    - title : 2.5.4.12
    - initials : 2.5.4.43
    - generationQualifier : 2.5.4.44
    - x500UniqueIdentifier : 2.5.4.45
    - dnQualifier : distinguishedNameQualifier : 2.5.4.46
    - pseudonym : 2.5.4.65
    - userId : 0.9.2342.19200300.100.1.1
    - domainComponent : 0.9.2342.19200300.100.1.25
    - emailAddress : 1.2.840.113549.1.9.1
    - jurisdictionCountryName : 1.3.6.1.4.1.311.60.2.1.3
    - jurisdictionLocalityName : 1.3.6.1.4.1.311.60.2.1.1
    - jurisdictionStateOrProvinceName : 1.3.6.1.4.1.311.60.2.1.2
    - businessCategory : 2.5.4.16
    - postalCode : 2.5.4.17
    - unstructuredName : 1.2.840.113549.1.9.2
    - unstructuredAddress : 1.2.840.113549.1.9.8

\b
All other attributes can be used by providing the OID directly.

\b
Examples:

\b
    --subject commonName:MyApplicationTlsClientCertificate
    --subject 2.5.4.3:MyApplicationTlsClientCertificate

\b
Validity Options:
-----------------

\b
Examples:

\b
    2 years
    --validity-years 2
    -vy 2

\b
    1 years and 35 days (400 days)
    --validity-years 2 --validity-days 35
    -vy 1 -vd 35
    --validity-days 400

\b
X.509 Extension Options:
------------------------

\b
    Defaults to not including any extension that is not explicitly given.

\b
    Basic Constraints
    -----------------
    --basic-constraints, -bc

\b
        The cA flag will always be false and the path length constraint will not be set, since we do not allow
        the issuance of CA certificates. Basic constraints can be set to either critical or non-critical.

\b
        critical:
        --basic-constraints critical
        --basic-constraints c
        -bc critical
        -bc c
\b
        non-critical:
        --basic-constraints non-critical
        --basic-constraints n
        -bc non-critical
        -bc n

\b
    Key Usage
    ---------
    --key-usage, -ku

\b
    The following options can be set, while every options defaults to false.
    At least one flag must be set to true (or 1).
    If encipherOnly or decipherOnly is set, keyAgreement must also be set.
\b
    digitalSignature
    contentCommitment
    keyEncipherment
    dataEncipherment
    keyAgreement
    keyCertSign
    cRLSign
    encipherOnly
    decipherOnly
\b
    Criticality can be set using 'critical' ('c'), or 'non-critical' ('n'). Compare the examples section.

\b
        Examples:
        ---------
\b
            Setting the Key Usage extension to critical and digitalSignature and keyEncipherment to true,
            everything else shall be false. The following options are equivalent.
            --key-usage critical:digitalSignature=true:keyEncipherment=true:cRLSign=false:encipherOnly=false
            --key-usage critical:digitalSignature=true:keyEncipherment=true
            -ku c:digitalSignature=true:keyEncipherment=true
            -ku c:101000000
\b
            The last example shows the shorthand using 9 bits. 0 and 1 correspond to false and true, respectively.
            The order corresponds to the list of options above. The first bit corresponds to digitalSignature and
            the last bit corresponds to decipherOnly.
\b
            To set the same extension, but as non-critical we can use:
            -ku non-critical:101000000
            -ku n:101000000

    """
    try:
        trustpoint_client = TrustpointClient()

        # no more default pki protocol
        if trustpoint_client.default_domain is None:
            click.ClickException('No default domain is configured.')

        validity_days = validity_years * 365 + validity_days

        extensions = []
        if basic_constraints:
            extensions.append(BasicConstraintsExtension(basic_constraints))
        if key_usage:
            extensions.append(KeyUsageExtension(key_usage))
        if extended_key_usage:
            extensions.append(ExtendedKeyUsageExtension(extended_key_usage))

        trustpoint_client.request_generic(
            domain=None,
            unique_name=unique_name,
            subject=subject,
            extensions=extensions,
            validity_days=validity_days
        )

    except ValueError as exception:
        raise click.ClickException(f'\n{exception}\n')

    _credential_list(domain=None, verbose=False, unique_name=unique_name)

# @req.command(name='tls-client-cert')
# @click.option('--name', '-n', type=str, required=True, help='The name (handle) to identify the new certificate.')
# @click.option('--common-name', '-c', type=str, required=False, help='The common name to use.')
# @click.option('--subject', '-s', type=str, required=False, help='The subject to use.')
# def req_tls_client_cert(name:str, common_name: str, subject: str):
#     """Request a new tls client certificate."""
#     if not name.isidentifier():
#         raise click.BadParameter('Name must be a valid identifier.')
#
#     click.echo('\n\tTLS Client Certificate Issued.\n')
#     click.echo('\tCertificate Type: TLS Client Certificate.')
#     click.echo(f'\tName (handle): {name}.')
#     click.echo(f'\tSignature-Suite: RSA2048-SHA256')
#     if common_name:
#         click.echo(f'\tCommon Name: {common_name}.')
#     else:
#         click.echo(f'\tCommon Name: {name}.')
#     if subject:
#         click.echo(f'\tSubject: {subject}.')
#
#     click.echo()
#
#     click.echo('\tTLS Client Certificate:\n')
#     with (BASE_PATH / 'rsa2048-ee-cert.pem').open('r') as f:
#         click.echo(f.read())
#         click.echo('\n')
#
#     click.echo('\tTLS Client Certificate Chain:\n')
#     with (BASE_PATH / 'rsa2048-chain.pem').open('r') as f:
#         click.echo(f.read())
#
#     # TODO: Show certs
#
#
# @req.command(name='tls-server-cert')
# @click.option('--name', '-n', type=str, required=True, help='The name (handle) to identify the new certificate.')
# @click.option('--common-name', '-c', type=str, required=False, help='The common name to use.')
# @click.option('--subject', '-s', type=str, required=False, help='The subject to use.')
# @click.option('--domains', '-d', type=str, required=False, help='The domains for the TLS Server Certificate.')
# @click.option('--host-addresses', '-i', type=str, required=False, help='The host addresses for the TLS Server Certificate.')
# @click.option('--ipv6-addresses', '-j', type=str, required=False, help='The IPv6 addresses for the TLS Server Certificate.')
# def req_tls_server_cert(name: str, common_name: str, subject: str, domains: str, host_addresses: str, ipv6_addresses: str):
#     """Request a new tls server certificate."""
#
#     click.echo('\n\tTLS Server Certificate Issued.\n')
#     click.echo('\tCertificate Type: TLS Server Certificate.')
#     click.echo(f'\tName (handle): {name}.')
#     click.echo(f'\tSignature-Suite: RSA2048-SHA256')
#     if common_name:
#         click.echo(f'\tCommon Name: {common_name}.')
#     else:
#         click.echo(f'\tCommon Name: {name}.')
#     if subject:
#         click.echo(f'\tSubject: {subject}.')
#     if domains:
#         click.echo(f'\tDomains: {domains}.')
#     if host_addresses:
#         click.echo(f'\thost Addresses: {host_addresses}.')
#     if ipv6_addresses:
#         click.echo(f'\tIPv6 Addresses: {ipv6_addresses}.')
#
#     click.echo()
#
#     click.echo('\tTLS Server Certificate:\n')
#     with (BASE_PATH / 'rsa2048-ee-cert.pem').open('r') as f:
#         click.echo(f.read())
#         click.echo('\n')
#
#     click.echo('\tTLS Server Certificate Chain:\n')
#     with (BASE_PATH / 'rsa2048-chain.pem').open('r') as f:
#         click.echo(f.read())
#
#
#
# @req.command(name='mqtt-client-cert')
# def req_mqtt_client_cert():
#     """Request a new mqtt client certificate."""
#
#
# @req.command(name='mqtt-server-cert')
# def req_mqtt_server_cert():
#     """Request a new mqtt server certificate."""
#
#
# @req.command(name='opc-ua-client-cert')
# def req_opc_ua_client_cert():
#     """Request a new opc ua client certificate."""
#
#
# @req.command(name='opc-ua-server-cert')
# def req_opc_ua_server_cert():
#     """Request a new opc ua server certificate."""
#
#
# @req.command(name='ca-certs')
# def req_ca_certs():
#     """Requests the certificate chain for the issuing ca in use."""
#
#
# @req.command(name='trust-store')
# def req_trust_store():
#     """Request a trust-store."""

# @credential.group(name='list')
# def credential_list():
#     """Lists credentials."""

# @list_.command(name='domain-credential')
# def list_domain_credential():
#     """Lists the domain credential."""
#     trustpoint_client = TrustpointClient()
#     config = trustpoint_client.config
#     inventory = trustpoint_client.inventory
#     devid_module = trustpoint_client.devid_module
#
#     public_key = devid_module.inventory.devid_keys[
#         inventory.domains[config.default_domain].ldevid_credential.key_index
#     ].public_key.decode().replace('\n', '\n')
#
#     certificate = devid_module.inventory.devid_certificates[
#         inventory.domains[config.default_domain].ldevid_credential.active_certificate_index
#     ].certificate.decode().replace('\n', '\n')
#
#     certificate_chain = CertificateCollectionSerializer(devid_module.inventory.devid_certificates[
#         inventory.domains[config.default_domain].ldevid_credential.active_certificate_index
#     ].certificate_chain).as_pem().decode().replace('\n', '\n')
#
#     click.echo(f'\nDomain-Credential for Domain: {config.default_domain}:\n')
#
#     click.echo(f'Domain: {config.default_domain}.')
#     domain_inventory = inventory.domains[config.default_domain]
#     click.echo(f'Signature-Suite: {domain_inventory.signature_suite}')
#     click.echo(f'Default-PKI-Protocol: {domain_inventory.pki_protocol.value}.')
#     click.echo(f'\n\nPublic Key:\n\n{public_key}\n')
#     click.echo(f'Certificate:\n\n{certificate}\n')
#     click.echo(f'Certificate Chain:\n\n{certificate_chain}\n')
#     click.echo(
#         f'Trust-Store for verifying the Trustpoint TLS-Server Certificate:\n\n{domain_inventory.ldevid_trust_store}\n')
#
# @list_.command(name='credential')
# @click.argument('unique-name', type=str)
# def list_credential(unique_name: str):
#     """List the credential with the given unique name."""
#
# @list_.command(name='credentials')
# def list_credentials():
#     """Lists all available keys."""
#
# @list_.command(name='trust-store')
# @click.argument('unique-name', type=str)
# def list_truststore(unique_name: str):
#     """List the trust-store with the given unique name."""
#
# @list_.command(name='trust-stores')
# def list_trust_stores():
#     """Lists all available trust-stores."""