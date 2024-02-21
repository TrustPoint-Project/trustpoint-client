from cryptography.hazmat.primitives import serialization
#from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import click
import datetime

# Create RSA key-pair and corresponding CSR, write to disk as ldevid-private-key.pem and ldevid-csr.pem
# Returns the CSR to reduce file operations
# TODO Security risk! Generate key in HSM instead if available
def generateNewKeyAndCSR() -> bytes:
    key = ec.generate_private_key(
        ec.SECP256R1()
    )

    with open("ldevid-private-key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            # TODO python requests does not support encrypted private keys 
            encryption_algorithm=serialization.NoEncryption(),
            #encryption_algorithm=serialization.BestAvailableEncryption(b"bad1deaThisSe3msLike"), # TODO derive private key encryption pwd from something
        ))

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "0"),
        x509.NameAttribute(NameOID.COMMON_NAME, "client.trustpoint.ldevid.local"),
    ])).sign(key, hashes.SHA256())

    # Optionally write CSR to disk.
    #with open("ldevid-csr.pem", "wb") as f:
    #    f.write(csr.public_bytes(serialization.Encoding.PEM))
    return csr.public_bytes(serialization.Encoding.PEM)

# Checks valididity time against system time only. Does NOT verify chain of trust.
def checkCertificateUnexpired(certbytes : bytes) -> bool:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    #now = now.replace(tzinfo=None)
    if now.year < 2024: # extremely naive check, it does not cover (even significant) clock drift, but at least should catch uninitialized time
        click.echo("Cannot validate the certificate as system time is not set correctly.")
        click.echo('Current system time year is ' + now.year)
        return False
    certificate = x509.load_pem_x509_certificate(certbytes)

    if certificate.not_valid_after_utc < now:
        click.echo("Certificate is expired since" + certificate.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"))
        return False
    elif now < certificate.not_valid_before_utc:
        # Are there certificates with a notBefore significantly after creation in practice? This is disallowed in the Web PKI, but could be used in a private PKI
        click.echo("Certificate not yet valid, starting" + certificate.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"))
        return False
    else:
        daysToExpiration = (certificate.not_valid_after_utc - now)
        click.echo("Cert expires " + str(certificate.not_valid_after_utc) + ", " + str(daysToExpiration) + " days from now.")
    return True