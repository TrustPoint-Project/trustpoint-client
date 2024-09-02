"""This module contains cryptographic operations for the Trustpoint-Client."""

import datetime
import secrets
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


# TODO(Air): Security risk! Generate and store key in HSM instead if available
# TODO(Air): Allow configuration of key type and size
def generate_new_key_and_csr(serial: str = '') -> bytes:
    """Generates a new private key and a corresponding CSR for the LDevID.

    ECC private key is written to disk as ldevid-private-key.pem

    Args:
        serial: The device serial number to use in the CSR. If not provided, a random one is generated.

    Returns:
        Certificate signing request as PEM-encoded bytes.
    """
    key = ec.generate_private_key(ec.SECP256R1())

    with Path('ldevid-private-key.pem').open('wb') as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                # TODO(Air): python requests does not support encrypted private keys
                encryption_algorithm=serialization.NoEncryption(),
                # TODO(Air): derive private key encryption pwd from something?
                # encryption_algorithm=serialization.BestAvailableEncryption(b"bad1deaThisSe3msLike") noqa: ERA001
            )
        )

    if not serial:
        try:
            with Path('tpclient-serial-no.txt').open('r') as f:
                serial = f.read()
        except FileNotFoundError:
            pass

        if not serial:
            serial = 'tpclient_' + secrets.token_urlsafe(12)

    with Path('tpclient-serial-no.txt').open('w') as f:
        f.write(serial)

    click.echo('Device Serial number: ' + serial)

    # Generate a CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.SERIAL_NUMBER, serial),
                    x509.NameAttribute(NameOID.COMMON_NAME, 'client.trustpoint.ldevid.local'),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )

    # Optionally write CSR to disk.
    # with open("ldevid-csr.pem", "wb") as f:
    #    f.write(csr.public_bytes(serialization.Encoding.PEM))      # noqa: ERA001
    return csr.public_bytes(serialization.Encoding.PEM)


MINIMUM_YEAR = 2024


def check_certificate_unexpired(certbytes: bytes) -> bool:
    """Checks if the certificate is currently in its validity period.

    Checks valididity time against system time only. Does NOT verify chain of trust.
    """
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    # extremely naive check, it does not cover (even significant) clock drift
    # but at least should catch uninitialized time (Jan 1 1970)
    # TODO(Air): perhaps use NTP to get time, however this would require an Internet connection
    if now.year < MINIMUM_YEAR:
        click.echo('Cannot validate the certificate as system time is not set correctly.')
        click.echo('Current system time year is ' + now.year)
        return False
    certificate = x509.load_pem_x509_certificate(certbytes)

    if certificate.not_valid_after_utc < now:
        click.echo('Certificate is expired since' + certificate.not_valid_after_utc.strftime('%Y-%m-%dT%H:%M:%SZ'))
        return False
    if now < certificate.not_valid_before_utc:
        # Are there certificates with a notBefore significantly after creation in practice?
        # This is disallowed in the Web PKI, but could be used in a private PKI
        click.echo(
            'Certificate not yet valid, starts' + certificate.not_valid_before_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        )
        return False

    days_to_expiration = certificate.not_valid_after_utc - now
    click.echo(
        'Cert expires '
        + str(certificate.not_valid_after_utc)
        + ', '
        + str(days_to_expiration).split('.')[0]
        + ' h from now.'
    )
    return True
