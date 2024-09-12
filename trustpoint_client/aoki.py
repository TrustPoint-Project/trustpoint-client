"""Implementation of the Automatic Onboarding Key Infrastructure (AOKI) v0.1 zero-touch onboarding demo client."""

# Prerequisites:
# Client device must have an IDevID and corresponding private key
# Client device must have the certificate that signed the Ownership Certificate in its truststore (this CA should be unique per device)
# Server must have the Ownership Certificate and associated IDevID public key in DB
# Server must have the cert chain of the CA that signed the client's IDevID in its truststore

# Step 1: Discover the Trustpoint/AOKI Server service (mDNS)

# Step 2: Establish provisionally trusted TLS connection
# It is assumed that TLS client authentication is unavailable (IDevID not directly usable as client cert)

# Send onboarding request, including IDevID cert and a nonce for the server to sign to prove possession of the ownership key

# Step 3: Receive and verify the server's ownership certificate
# Note: For flexibility, the ownership certificate is independent of the server's TLS certificate
# However, client must ensure the server is in possession of the ownership key to prevent MitM attacks
# Therefore, the ownership key is used to sign the message (ownership_cert | nonce | server_tls_cert | {server_nonce})
# Server nonce is only required if TLS client authentication is unavailable

# Step 4: If client-side verification is successful, sign server_nonce with IDevID private key and send back to server
# # At this point, the client trusts the server and may e.g. accept the server's TLS certificate and EST truststore

# Step 5: Server verifies signed nonce and responds with an OTP to use as HTTP basicAuth credentials for EST simpleenroll

# Step 6: Client obtains the server's truststore (EST getcacerts)

# Step 7: Client sends a CSR to the server (EST simpleenroll with OTP obtained above)
# Step 8: Receive LDevID certificate

# ====================================================================
# Alternative, simpler protocol (TLS client authentication available):

# Step 1: Discover the Trustpoint/AOKI Server service (mDNS)

# Step 2: Establish provisionally trusted TLS connection, use IDevID as client cert

# Send onboarding request, including a nonce for the server to sign to prove possession of the ownership key

# Step 3: Receive and verify the server's ownership certificate
# Note: For flexibility, the ownership certificate is independent of the server's TLS certificate
# However, client must ensure the server is in possession of the ownership key to prevent MitM attacks
# Therefore, the ownership key is used to sign the message (ownership_cert | nonce | server_tls_cert)

# Step 4: If client-side verification is successful, client obtains the server's truststore (EST getcacerts)
# # At this point, the client trusts the server and may e.g. accept the server's TLS certificate and EST truststore

# Step 5: Client sends a CSR to the server (EST simpleenroll with IDevID as client cert)
# Step 6: Receive LDevID certificate

# ====================================================================

import base64
import click
import json
import logging
import requests
import secrets
import threading
import urllib3

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from trustpoint_client.api import ProvisioningError, request_ldevid

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('tpclient.aoki')

onboarding_lock = threading.Lock()

HTTP_STATUS_OK = 200

def verify_ownership_cert(ownership_cert: bytes) -> bool:
    """Verifies the ownership certificate of the Trustpoint server is part of a PKI in the client trust store."""
    # TODO (Air): Implement proper PKI verification
    # For now, just do a file-level check against 'trust_store.pem'
    with open('owner_cert_chain.pem', 'rb') as truststore:
        truststore_data = truststore.read()
        if ownership_cert not in truststore_data:
            exc_msg = 'Server ownership certificate is not part of the client trust store.'
            raise ProvisioningError(exc_msg)
    return True

def verify_server_signature(message: bytes, ownership_cert: bytes, server_signature: bytes) -> bool:
    """Verifies the message received was signed by the ownership key."""

    log.debug('Verifying server signature...')
    hash = hashes.Hash(hashes.SHA256())
    hash.update(message)
    log.debug(f'SHA-256 hash of message: {hash.finalize().hex()}')

    try:
        cert = x509.load_pem_x509_certificate(ownership_cert)
        signer_public_key = cert.public_key()
        print(f'Signer public key: {signer_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}')
    except Exception as e:
        exc_msg = 'Failed to load public key from ownership certificate.'
        raise ProvisioningError(exc_msg) from e
    try:
        print(f'Server signature: {server_signature}')
        signer_public_key.verify(signature=server_signature, data=message, signature_algorithm=ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        exc_msg = 'Server signature verification failed.'
        raise ProvisioningError(exc_msg) from e


def aoki_onboarding(host: str):
    """Called for each discovered Trustpoint server to attempt onboarding."""
    # Use threading to handle multiple servers (but only run one onboarding process at a time)
    log.info(f'Pending zero-touch onboarding attempt with Trustpoint server at {host}')
    onboarding_lock.acquire()
    log.info(f'AOKI onboarding with Trustpoint server at {host} started')

    # Step 2: Establish provisionally trusted TLS connection
    # Send onboarding request, including IDevID cert and a nonce for the server to sign to prove possession of the ownership key

    click.echo('Sending onboarding request to server...')
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    idevid = open('idevid_cert.pem', 'rb')
    client_nonce = secrets.token_hex(16)
    init_data = {'idevid': idevid.read().decode('utf-8'),
                 'client_nonce': client_nonce}
    response = requests.post('https://' + host + '/api/onboarding/aoki/init',
                             json=init_data, verify=False, timeout=6)  # noqa: S501
    log.debug(response.text) 
    log.debug(response.headers)
    if response.status_code != HTTP_STATUS_OK:
        exc_msg = 'Server returned HTTP code ' + str(response.status_code)
        raise ProvisioningError(exc_msg)

    # Step 3: Receive and verify the server's ownership certificate
    # Response is the servers ownership certificate and a nonce to sign
    try:
        response_json = response.json()
    except Exception as e:
        exc_msg = 'Server response is not a valid JSON object.'
        raise ProvisioningError(exc_msg)

    if 'aoki-server-signature' not in response.headers:
        exc_msg = 'AOKI Signature header is required but missing in Trustpoint response headers.'
        raise ProvisioningError(exc_msg)
    
    try:
        ownership_cert = response_json['ownership_cert'].encode('utf-8')
        server_nonce = response_json['server_nonce'].encode('utf-8')
        client_nonce_response = response_json['client_nonce']
        server_tls_cert = response_json['server_tls_cert']
        server_signature = base64.b64decode(response.headers['aoki-server-signature'].encode('utf-8'))
    except KeyError as e:
        exc_msg = 'Server init response JSON is missing required fields.'
        raise ProvisioningError(exc_msg) from e
    
    if client_nonce_response != client_nonce:
        exc_msg = 'Client nonce mismatch in server response.'
        raise ProvisioningError(exc_msg)
    
    click.echo('Received ownership certificate from server, verifying...')
    
    verify_ownership_cert(ownership_cert)
    
    response_bytes = str(response_json).encode()
    verify_server_signature(response_bytes, ownership_cert=ownership_cert, server_signature=server_signature)

    click.echo('Ownership certificate verified!')
    
    # Step 4: If client-side verification is successful, sign server_nonce with IDevID private key and send back to server
    # TODO: Support all DevID conformant signature suites (RSA-2048/SHA-256, ECDSA P-256/SHA-256, ECDSA P-384/SHA-38)
    # TODO: Integrate with DevID module
    with open('tls_trust_store.pem', 'w') as tls_truststore:
        tls_truststore.write(server_tls_cert)

    click.echo('Sending finalization request...')
    print('Nonce to sign:', server_nonce)
    fin_data = {'server_nonce': server_nonce.decode('utf-8')}
    fin_str = json.dumps(fin_data,separators=(',', ':'))
    print(fin_str)
    fin_bytes = fin_str.encode()

    hash = hashes.Hash(hashes.SHA256())
    hash.update(fin_bytes)
    log.debug(f'SHA-256 hash of message: {hash.finalize().hex()}')

    with open('idevid_private.key', 'rb') as keyfile:
        idevid_private_key = serialization.load_pem_private_key(keyfile.read(), password=None)
        signature = idevid_private_key.sign(fin_bytes, ec.ECDSA(hashes.SHA256()))
        headers = {'aoki-client-signature': base64.b64encode(signature)}
        
    print('Client Signature:', signature)
    response = requests.post('https://' + host + '/api/onboarding/aoki/finalize',
                             json=fin_data, verify='tls_trust_store.pem', timeout=6, headers=headers)  # noqa: S501
    if response.status_code != HTTP_STATUS_OK:
        exc_msg = 'Server returned HTTP code ' + str(response.status_code)
        raise ProvisioningError(exc_msg)

    try:
        response_json = response.json()
    except Exception as e:
        exc_msg = 'Server response is not a valid JSON object.'
        raise ProvisioningError(exc_msg)
    
    try:
        otp = response_json['otp']
        salt = response_json['salt']
        url_ext = response_json['url_ext']  # Temporary URL extension for LDevID enrollment, use a single endpoint long-term
    except KeyError as e:
        exc_msg = 'Server finalize response JSON is missing required fields.'
        raise ProvisioningError(exc_msg) from e
    
    click.echo('Received OTP from server, proceeding to LDevID enrollment...')
    
    with open('idevid_cert.pem', 'rb') as idevid:
        idevid_cert = x509.load_pem_x509_certificate(idevid.read())
        try:
            serial_number = idevid_cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
        except (x509.ExtensionNotFound, IndexError):
            serial_number = 'tpcl_' + secrets.token_urlsafe(12)
    
    request_ldevid(host, url_ext, otp, salt, serial_number)