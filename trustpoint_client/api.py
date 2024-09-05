"""Main provisioning logic module for Trustpoint-Client."""

from __future__ import annotations

import datetime
import hashlib
import hmac
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING

import click
import requests
import urllib3

from trustpoint_client import key

if TYPE_CHECKING:
    from typing import Callable

HTTP_STATUS_OK = 200


class ProvisioningError(Exception):
    """Exception raised for errors in the onboarding / client provisioning process."""

    def __init__(self, message: str = 'An error occurred during provisioning.') -> None:
        """Initializes a new ProvisioningError with a given message."""
        self.message = message
        super().__init__(self.message)


class ProvisioningState(IntEnum):
    """Enum for the state of the provisioning process."""

    NOT_PROVISIONED = 0
    HAS_TRUSTSTORE = 1
    HAS_LDEVID = 2
    HAS_CERT_CHAIN = 3
    ERROR = -1


def _verify_hash(content: bytes) -> None:
    """Verifies the hash of the trust store."""
    click.echo('Using simple hash verification')
    s = hashlib.sha3_256()
    s.update(content)
    r_hash = s.hexdigest()
    # how many bytes of the hash the admin has to explicitely enter for checking
    # TODO(Air): this should be determined by trustpoint
    explicit_verification_bytes = 3
    if explicit_verification_bytes > 0:
        value = click.prompt(
            'Please enter the first '
            + str(explicit_verification_bytes * 2)
            + ' characters of the trust store hash displayed by Trustpoint'
        )
        if value != r_hash[: explicit_verification_bytes * 2]:
            exc_msg = 'Downloaded and entered hash portion do not match.'
            raise ProvisioningError(exc_msg)
    click.echo('\nPLEASE VERIFY BELOW HASH AGAINST THAT DISPLAYED BY TRUSTPOINT\n')
    click.echo(r_hash)
    feedback = click.prompt('\nDo the hashes match EXACTLY? (y/n)')
    # TODO(Air): maybe consider adding https://github.com/ansemjo/randomart (not as lib, but as src)
    if feedback not in ('Y', 'y'):
        exc_msg = 'Hash does not match the one displayed by Trustpoint, aborting.'
        raise ProvisioningError(exc_msg)


def get_trust_store(host: str = '127.0.0.1:5000', uriext: str = '', hexpass: str = '', hexsalt: str = '') -> None:
    """Retrieves the TLS trust store from the Trustpoint."""
    click.echo('Retrieving Trustpoint Trust Store')

    if Path('trust-store.pem').exists():
        # TODO(Air): it might be a security risk to have this (write) accessible on the filesystem
        click.echo('trust-store.pem file present locally')
        with Path('trust-store.pem').open('rb') as certfile:
            cert_unexpired = key.check_certificate_unexpired(certfile.read())
            if cert_unexpired:
                return

    # Truststore file not present, obtain it (this request is intentionally not verified)
    click.echo('trust-store.pem missing, downloading from Trustpoint...')
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get('https://' + host + '/api/onboarding/trust-store/' + uriext, verify=False, timeout=6)  # noqa: S501
    if response.status_code != HTTP_STATUS_OK:
        exc_msg = 'Server returned HTTP code ' + str(response.status_code)
        raise ProvisioningError(exc_msg)

    # TRUSTSTORE DOWNLOAD VERIFICATION
    verification_level: int = 0
    # Only allow for basic hash comparision verification if HMAC header is NOT included by Trustpoint
    # AND hexpass is not provided
    verification_level = 1 if hexpass or 'hmac-signature' in response.headers else 0

    if verification_level == 1:
        # Full HMAC + PBKDF2 verification
        click.echo('Using PBKDF2-HMAC verification')
        if 'hmac-signature' not in response.headers:
            exc_msg = 'HMAC signature header is required but missing in Trustpoint response headers.'
            raise ProvisioningError(exc_msg)
        if not hexpass:
            exc_msg = 'HMAC verification is required but --hexpass option was not provided.'
            raise ProvisioningError(exc_msg)
        # TODO(Air): this should be an option or given by a trustpoint header with a reasonable minimum sanity check
        pbkdf2_iter = 1000000
        pkey = hashlib.pbkdf2_hmac('sha256', bytes(hexpass, 'utf-8'), bytes(hexsalt, 'utf-8'), pbkdf2_iter, dklen=32)
        click.echo('Computed PBKDF2-key: ' + pkey.hex())
        h = hmac.new(pkey, response.content, hashlib.sha256)
        click.echo('Computed HMAC: ' + h.hexdigest())
        if not hmac.compare_digest(h.hexdigest(), response.headers['hmac-signature']):
            exc_msg = 'Truststore HMAC signature header and computed HMAC do not match.'
            raise ProvisioningError(exc_msg)
    elif verification_level == 0:
        # Simple SHA3 hash display
        _verify_hash(response.content)
    else:
        exc_msg = 'Invalid verification level.'
        raise ProvisioningError(exc_msg)

    with Path('trust-store.pem').open('wb') as f:  # write downloaded truststore to FS
        f.write(response.content)

    click.echo('Thank you, the trust store was downloaded successfully.')


def request_ldevid(host: str, url: str, otp: str, salt: str, sn: str) -> None:
    """Requests the LDevID certificate from the Trustpoint."""
    click.echo('Generating private key and CSR for LDevID')
    csr = key.generate_new_key_and_csr(sn)
    # Let Trustpoint sign our CSR (auth via OTP and salt as username via HTTP basic auth)
    click.echo('Uploading CSR to Trustpoint for signing')
    files = {'ldevid.csr': csr}
    crt = requests.post(
        'https://' + host + '/api/onboarding/ldevid/' + url,
        auth=(salt, otp),
        files=files,
        verify='trust-store.pem',
        timeout=6,
    )
    if crt.status_code != HTTP_STATUS_OK:
        exc_msg = 'Server returned HTTP code ' + str(crt.status_code)
        raise ProvisioningError(exc_msg)

    with Path('ldevid.pem').open('wb') as f:  # write downloaded certificate to FS
        f.write(crt.content)
        click.echo('LDevID certificate downloaded successfully')

    with Path('ldevid.pem').open('rb') as certfile:
        cert_unexpired = key.check_certificate_unexpired(certfile.read())
        if not cert_unexpired:
            exc_msg = 'Provided LDevID certificate is not currently valid.'
            raise ProvisioningError(exc_msg)


def request_cert_chain(host: str, url: str) -> None:
    """Requests the LDevID certificate chain from the Trustpoint."""
    click.echo('Downloading LDevID certificate chain')
    chain = requests.get(
        'https://' + host + '/api/onboarding/ldevid/cert-chain/' + url,
        verify='trust-store.pem',
        cert=('ldevid.pem', 'ldevid-private-key.pem'),
        timeout=6,
    )
    if chain.status_code != HTTP_STATUS_OK:
        exc_msg = 'Server returned HTTP code ' + str(chain.status_code)
        raise ProvisioningError(exc_msg)

    with Path('ldevid-certificate-chain.pem').open('wb') as f:  # write downloaded trust chain to FS
        f.write(chain.content)
        click.echo('Certificate chain downloaded successfully')


def provision(      # noqa: PLR0913
        otp: str,
        salt: str,
        url: str,
        host: str,
        hexpass: str,
        hexsalt: str,
        sn: str,
        callback: None | Callable = None) -> None:
    """Provisions the Trustpoint-Client software."""
    click.echo('Provisioning client...')
    if callback:
        callback(ProvisioningState.NOT_PROVISIONED)
    click.echo(
        'Current system time is ' + datetime.datetime.now(tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    )

    try:
        # Step 1: Get trustpoint Trust Store
        get_trust_store(host, url, hexpass, hexsalt)
        if callback:
            callback(ProvisioningState.HAS_TRUSTSTORE)
        # Step 2: Request locally significant device identifier (LDevID)
        request_ldevid(host, url, otp, salt, sn)
        if callback:
            callback(ProvisioningState.HAS_LDEVID)
        # Step 3: Download LDevID Certificate chain
        request_cert_chain(host, url)
        if callback:
            callback(ProvisioningState.HAS_CERT_CHAIN)
    except:
        if callback:
            callback(ProvisioningState.ERROR)
        raise
