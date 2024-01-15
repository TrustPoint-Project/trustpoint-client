from cryptography.hazmat.primitives import serialization
#from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

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