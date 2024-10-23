from __future__ import annotations

import uuid
import subprocess
import click
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from trustpoint_client.api import TrustpointClient
from trustpoint_client.api.schema import PkiProtocol

BASE_PATH = Path('__file__').resolve().parent / 'trustpoint_client/demo_data'


# TODO(AlexHx8472): This information should be part of MAN pages, not of the help directly.
@click.group
def req() -> None:
    """Request a new certificate or trust-store."""

@req.command(name='generic-cert', help="""\b
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
\b
All other attributes can be used by providing the OID directly.

\b
Examples:

\b
    --subject-entry commonName:MyApplicationTlsClientCertificate
    --subject-entry 2.5.4.3:MyApplicationTlsClientCertificate

\b    
Validity Options:
-----------------

\b
The validity must be provided as an ISO 8601 datetime string:
%Y-%m-%d","%Y-%m-%dT%H:%M:%S" or "%Y-%m-%d %H:%M:%S"

\b
Examples:

\b
    2 years, 2 months, 5 days
    --validity 2Y-2m-5d

\b
    2 years, 2 months, 5 days, 4 hours, 3 minutes, 25 seconds
    --validity 2Y-2m-5dT4H:3M:25S
    --validity 2Y-2m-5d 4H:3M:25S
    
\b
    30 minutes
    0Y-0m-0dT

\b
Extension Options:
------------------

""")
@click.option(
    '--subject', '-s',
    type=str,
    help='Subject Entry in the form <Abbreviation, name or OID>:<value>',
    multiple=True,
    default=[f'CN:Trustpoint Generic Certificate', f'serialNumber:{uuid.uuid4()}'])
# @click.option(
#     '--validity', '-v',
#     type=str,
#     required=True,
#     help='Expects an ISO 8601 datetime string:"%Y-%m-%d".')
@click.option('--extension', '-e', type=str, required=False)
def req_generic_cert(subject: list[str], extension: list[str]) -> None:
    """Request a new generic certificate."""
    trustpoint_client = TrustpointClient()
    if trustpoint_client.config.default_pki_protocol == PkiProtocol.CMP:
        _reg_cmp_cert(trustpoint_client=trustpoint_client, subject=subject, extension=extension)

def _reg_cmp_cert(trustpoint_client: TrustpointClient, subject: list[str], extension: list[str]) -> None:

    inventory_domain = trustpoint_client.inventory.domains[trustpoint_client.default_domain]
    key_index = inventory_domain.ldevid_credential.key_index
    cert_index = inventory_domain.ldevid_credential.active_certificate_index

    key = trustpoint_client.devid_module.inventory.devid_keys[key_index].private_key
    cert = trustpoint_client.devid_module.inventory.devid_certificates[cert_index].certificate

    key_path = trustpoint_client.inventory_file_path.parent / 'key.pem'
    cert_path = trustpoint_client.inventory_file_path.parent / 'cert.pem'

    key_path.write_bytes(key)
    cert_path.write_bytes(cert)

    new_key_path = trustpoint_client.inventory_file_path.parent / 'new_key_path.pem'
    new_cert_path = trustpoint_client.inventory_file_path.parent / 'new_cert_path.pem'

    new_private_key = trustpoint_client.generate_new_key(inventory_domain.signature_suite)
    new_key_path.write_bytes(
        new_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
    ))

    cmd = (
        f'openssl cmp '
        f'-cmd ir '
        f'-server {trustpoint_client.trustpoint_ipv4}:{trustpoint_client.trustpoint_port} '
        f'-path /.well-known/cmp/p/{trustpoint_client.default_domain}/initialization/ '
        f'-newkey {new_key_path} '
        f'-key {key_path} '
        f'-cert {cert_path} '
        f'-certout {new_cert_path} '
        f'-implicit_confirm -disable_confirm '
        f'-unprotected_errors'
    )

    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    print(result)

#
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
# @click.option('--ipv4-addresses', '-i', type=str, required=False, help='The IPv4 addresses for the TLS Server Certificate.')
# @click.option('--ipv6-addresses', '-j', type=str, required=False, help='The IPv6 addresses for the TLS Server Certificate.')
# def req_tls_server_cert(name: str, common_name: str, subject: str, domains: str, ipv4_addresses: str, ipv6_addresses: str):
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
#     if ipv4_addresses:
#         click.echo(f'\tIPv4 Addresses: {ipv4_addresses}.')
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
