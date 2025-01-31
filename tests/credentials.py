"""Trustpoint-Client commands concerning credentials."""

from __future__ import annotations

import uuid
from pathlib import Path

import click
import prettytable

from trustpoint_client.api import TrustpointClient
from trustpoint_client.api.credentials import (
    AuthorityKeyIdentifier,
    BasicConstraintsExtension,
    ExtendedKeyUsageExtension,
    KeyUsageExtension,
    SubjectAlternativeNameExtension,
    SubjectKeyIdentifier,
)
from trustpoint_client.cli import domain_option_optional, handle_exception, verbose_option
from trustpoint_client.enums import CertificateCollectionFormat, CertificateFormat, PrivateKeyFormat, PublicKeyFormat

BASE_PATH = Path('__file__').resolve().parent / 'trustpoint_client/demo_data'


@click.group(name='credential')
def credentials() -> None:
    """Commands concerning domains."""


def _credential_list(domain: None | str, verbose: bool, unique_name: None | str) -> None:  # noqa: FBT001
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

    for i, (local_unique_name, value) in enumerate(result['credentials'].items()):
        click.echo(f'\n\nCredential #{i}: {local_unique_name}')
        cred_table = prettytable.PrettyTable(['Property', 'Value'])
        cert = value.pop('Credential Certificate', None)
        pub_key = value.pop('Credential Public-Key', None)
        cert_chain = value.pop('Credential Certificate Chain', None)
        for k, v in value.items():
            cred_table.add_row([k, v])
        click.echo(cred_table)
        click.echo()

        if cert:
            click.echo(f'\nCredential Certificate: {local_unique_name}')
            click.echo(64 * '-' + '\n')
            click.echo(cert)

        if pub_key:
            click.echo(f'\nCredential Public-Key: {local_unique_name}')
            click.echo(64 * '-' + '\n')
            click.echo(cert)

        if cert_chain:
            click.echo(f'\nCredential Certificate-Chain: {local_unique_name}')
            click.echo(64 * '-' + '\n')
            click.echo(cert)


@credentials.command(name='list')
@domain_option_optional
@verbose_option
@click.argument('unique-name', type=str, required=False)
@handle_exception
def credential_list(domain: None | str, verbose: bool, unique_name: None | str) -> None:  # noqa: FBT001
    """Lists all or specific credentials.

    \b
    Args:
        domain: The domain in which the credential resides in.
        unique_name: The unique name of the credential to list.
        verbose: If True, the credential in PEM format is also echoed to the CLI (stdout).

    """     # noqa: D301
    _credential_list(domain, verbose, unique_name)


@credentials.command(name='delete')
@click.option('--domain', '-d', type=str, required=False, help='The desired domain. Defaults to the default domain.')
@click.argument('unique-name', type=str, required=True)
@handle_exception
def credential_delete(domain: None | str, unique_name: str) -> None:
    """Deletes the corresponding credential.

    \b
    Note:
        Does not yet try to revoke these certificates. (Planned feature)

    \b
    Args:
        domain: The domain in which the credential resides in.
        unique_name: The unique name of the credential to delete.

    """     # noqa: D301
    trustpoint_client = TrustpointClient()
    if not domain:
        domain = trustpoint_client.default_domain
    if not domain:
        click.echo()
        err_msg = 'No default domain configured. Nothing to delete.\n'
        raise click.ClickException(err_msg)
    if not trustpoint_client.credential_exists(domain, unique_name):
        click.echo()
        err_msg = f'No credential for the unique name {unique_name} and domain {domain} found.\n'
        raise click.ClickException(err_msg)

    if click.confirm(
        f'Are you sure you want to delete the credential with unique name {unique_name} and domain {domain}?'
        'This action is irreversible!'
    ):
        if trustpoint_client.delete_credential(domain, unique_name):
            click.echo(f'\nCredential with unique name {unique_name} and domain {domain} successfully deleted.\n')
            return

        click.echo()
        err_msg = f'Failed to delete the credential with unique name {unique_name} and domain {domain}.\n'
        raise click.ClickException(err_msg)
    click.echo('\nAborted.\n')


@credentials.group
def export() -> None:
    """Export credentials in different formats."""


@export.command(name='credential')
@domain_option_optional
@click.option(
    '--password', '-pw', type=str, required=False, default=None, help='The password used to encrypt the file.'
)
@click.option('--unique-name', '-u', type=str, required=True)
@click.option('--pkcs12-out', '-o', type=click.Path(), required=True)
@handle_exception
def export_credential(domain: None | str, password: None | str, unique_name: str, pkcs12_out: str) -> None:
    """Exports the whole credential as PKCS#12 file.

    \b
    If no password is provided, a new password with 12 characters will be generated and be echoed to the terminal.
    """     # noqa: D301
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
    '--format-out',
    '-f',
    type=click.Choice([format_.value for format_ in CertificateFormat]),
    required=False,
    default=CertificateFormat.PEM.value,
)
@click.option('--certificate-out', '-o', type=click.Path(), required=True)
@handle_exception
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
    '--format-out',
    '-f',
    type=click.Choice([format_.value for format_ in CertificateCollectionFormat]),
    required=False,
    default=CertificateCollectionFormat.PEM.value,
)
@click.option('--certificate-chain-out', '-o', type=click.Path(), required=True)
@handle_exception
def export_certificate_chain(domain: None | str, unique_name: str, format_out: str, certificate_chain_out: str) -> None:
    """Exports the credential certificate-chain."""
    trustpoint_client = TrustpointClient()
    cert_chain_format = CertificateCollectionFormat(format_out)
    cert_chain_bytes = trustpoint_client.export_certificate_chain(domain, unique_name, cert_chain_format)

    if not certificate_chain_out.endswith(cert_chain_format.file_extension):
        certificate_chain_out += cert_chain_format.file_extension
    cert_chain_path = Path(certificate_chain_out)
    cert_chain_path.write_bytes(cert_chain_bytes)

    click.echo(f'\nCertificate chain file saved (Format: {format_out}): {cert_chain_path.resolve()}\n')


@export.command(name='public-key')
@domain_option_optional
@click.option('--unique-name', '-u', type=str, required=True)
@click.option(
    '--format-out',
    '-f',
    type=click.Choice([format_.value for format_ in PublicKeyFormat]),
    required=False,
    default=PublicKeyFormat.PEM.value,
)
@click.option('--public-key-out', '-o', type=click.Path(), required=True)
@handle_exception
def export_public_key(domain: None | str, unique_name: str, format_out: str, public_key_out: str) -> None:
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
    '--password', '-pw', type=str, required=False, default=None, help='The password used to encrypt the file.'
)
@click.option('--unique-name', '-u', type=str, required=True)
@click.option(
    '--format-out',
    '-f',
    type=click.Choice([format_.value for format_ in PrivateKeyFormat]),
    required=False,
    default=PrivateKeyFormat.PKCS8_PEM.value,
)
@click.option('--private-key-out', '-o', type=click.Path(), required=True)
@handle_exception
def export_private_key(
    domain: None | str, password: None | str, unique_name: str, format_out: str, private_key_out: str
) -> None:
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
@handle_exception
def renew() -> None:
    """Renews a certificate."""


@credentials.group
def revoke() -> None:
    """Revokes a certificate."""


# TODO(AlexHx8472): This information should be part of MAN pages, not of the help directly.
@credentials.group
def request() -> None:
    """Request a new certificate or trust-store."""


@request.command(name='generic')
@click.option(
    '--subject',
    '-s',
    type=str,
    help='Subject Entry in the form <Abbreviation, name or OID>:<value>',
    multiple=True,
    default=['CN:Trustpoint Generic Certificate', f'serialNumber:{uuid.uuid4()}'],
)
@click.option(
    '--validity-years',
    '-vy',
    type=int,
    required=False,
    default=0,
    help='Desired validity in years. Days will be added.',
)
@click.option(
    '--validity-days',
    '-vd',
    type=int,
    required=False,
    default=365,
    help='Desired validity in days. Will be added to years, if provided.',
)
@click.option('--basic-constraints', '-bc', type=str, required=False)
@click.option('--key-usage', '-ku', type=str, required=False)
@click.option('--extended-key-usage', '-eku', type=str, required=False)
@click.option('--no-authority-key-identifier', '-no-aki', is_flag=True, required=False)
@click.option('--no-subject-key-identifier', '-no-ski', is_flag=True, required=False)
@click.option('--subject-alt-name-email', '-san-email', type=str, required=False, multiple=True)
@click.option('--subject-alt-name-uri', '-san-uri', type=str, required=False, multiple=True)
@click.option('--subject-alt-name-dns', '-san-dns', type=str, required=False, multiple=True)
@click.option('--subject-alt-name-rid', '-san-rid', type=str, required=False, multiple=True)
@click.option('--subject-alt-name-ip', '-san-ip', type=str, required=False, multiple=True)
@click.option('--subject-alt-name-dir-name', '-san-dn', type=str, required=False, multiple=True)
@click.option('--subject-alt-name-other-name', '-san-on', type=str, required=False, multiple=True)
@click.argument('unique_name', type=str, required=True)
@handle_exception
def request_generic(  # noqa: PLR0913
    subject: list[str],
    validity_years: int,
    validity_days: int,
    basic_constraints: None | str,
    key_usage: None | str,
    extended_key_usage: None | str,
    subject_alt_name_email: str,
    subject_alt_name_uri: str,
    subject_alt_name_dns: str,
    subject_alt_name_rid: str,
    subject_alt_name_ip: str,
    subject_alt_name_dir_name: str,
    subject_alt_name_other_name: str,
    no_authority_key_identifier: bool,  # noqa: FBT001
    no_subject_key_identifier: bool,  # noqa: FBT001
    unique_name: str,
) -> None:
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

    \b
        Extended Key Usage
        ------------------
            --extended-key-usage, -eku

    \b
            The option expects critical / non-critical followed by a : separated list of extended key usages.
            These can be one of the following list or any arbitrary OID.
    \b
            serverAuth
            clientAuth
            codeSigning
            emailProtection
            timeStamping
            ocspSigning
            anyExtendedKeyUsage
            smartcardLogon
            kerberosPkinitKdc
            ipsecIke
            certificateTransparency
    \b
            Criticality can be set using 'critical' ('c'), or 'non-critical' ('n'). Compare the examples section.

    \b

    Examples:
            ---------
    \b
                --extended-key-usage critical:serverAuth
                -eku n:clientAuth:codeSigning:emailProtection:1.2.3.4.5


    """  # noqa: D301
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
        if no_authority_key_identifier:
            extensions.append(AuthorityKeyIdentifier(include_aki=False))
        else:
            extensions.append(AuthorityKeyIdentifier(include_aki=True))
        if no_subject_key_identifier:
            extensions.append(SubjectKeyIdentifier(include_ski=False))
        else:
            extensions.append(SubjectKeyIdentifier(include_ski=True))

        san_entries = {
            'emails': list(subject_alt_name_email),
            'uris': list(subject_alt_name_uri),
            'dnss': list(subject_alt_name_dns),
            'rids': list(subject_alt_name_rid),
            'ips': list(subject_alt_name_ip),
            'dir_names': list(subject_alt_name_dir_name),
            'other_names': list(subject_alt_name_other_name),
        }

        extensions.append(SubjectAlternativeNameExtension(**san_entries))

        trustpoint_client.request_generic(
            domain=None, unique_name=unique_name, subject=subject, extensions=extensions, validity_days=validity_days
        )

    except ValueError as exception:
        err_msg = f'\n{exception}\n'
        raise click.ClickException(err_msg) from exception

    _credential_list(domain=None, verbose=False, unique_name=unique_name)


@request.command(name='tls-client')
@click.argument('unique_name', type=str, required=True)
@handle_exception
def request_tls_client(unique_name: str) -> None:
    """Requests a new TLS-Client credential.

    \b
    Args:
        unique_name: Unique name (handle) to use for the new credential.
    """ # noqa: D301
    try:
        trustpoint_client = TrustpointClient()

        # no more default pki protocol
        if trustpoint_client.default_domain is None:
            click.ClickException('No default domain is configured.')

        validity_days = 365

        extensions = [
            BasicConstraintsExtension('non-critical'),
            KeyUsageExtension('critical:100010000'),
            ExtendedKeyUsageExtension('non-critical:clientauth'),
        ]

        trustpoint_client.request_generic(
            domain=None,
            unique_name=unique_name,
            subject=['trustpoint-tls-client'],
            extensions=extensions,
            validity_days=validity_days,
        )

    except ValueError as exception:
        err_msg = f'\n{exception}\n'
        raise click.ClickException(err_msg) from exception

    _credential_list(domain=None, verbose=False, unique_name=unique_name)


@request.command(name='tls-server')
@click.option('--san-ip', '-i', type=str, required=False, multiple=True)
@click.option('--san-domain', '-d', type=str, required=False, multiple=True)
@click.argument('unique_name', type=str, required=True)
@handle_exception
def request_tls_server(unique_name: str, san_ip: tuple[str], san_domain: tuple[str]) -> None:
    """Requests a new TLS-Server credential.

    \b
    Args:
        unique_name: Unique name (handle) to use for the new credential.
        san_ip: IPv4 / IPv6 addresses to use in the subject alternative name of the new TLS-Server certificate.
        san_domain: Domain names to use in the subject alternative name of the new TLS-Server certificate.
    """     # noqa: D301
    if not san_ip and not san_domain:
        err_msg = 'At least one SAN IP or SAN DNS-Domain must be specified.'
        raise click.ClickException(err_msg)

    try:
        trustpoint_client = TrustpointClient()

        # no more default pki protocol
        if trustpoint_client.default_domain is None:
            click.ClickException('No default domain is configured.')

        validity_days = 365

        extensions = [
            BasicConstraintsExtension('non-critical'),
            KeyUsageExtension('critical:101010000'),
            ExtendedKeyUsageExtension('non-critical:serverauth'),
        ]

        trustpoint_client.request_generic(
            domain=None,
            unique_name=unique_name,
            subject=['trustpoint-tls-server'],
            extensions=extensions,
            validity_days=validity_days,
        )

        san_entries = {
            'emails': [],
            'uris': [],
            'dnss': list(san_domain),
            'rids': [],
            'ips': list(san_ip),
            'dir_names': [],
            'other_names': [],
        }

        extensions.append(SubjectAlternativeNameExtension(**san_entries))

    except ValueError as exception:
        err_msg = f'\n{exception}\n'
        raise click.ClickException(err_msg) from exception

    _credential_list(domain=None, verbose=False, unique_name=unique_name)
