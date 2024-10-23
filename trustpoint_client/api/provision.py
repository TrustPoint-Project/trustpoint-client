from __future__ import annotations

import click

import requests
import hashlib
import hmac
from pathlib import Path
import urllib3

from trustpoint_client.api.schema.inventory import SignatureSuite

HMAC_SIGNATURE_HTTP_HEADER = 'hmac-signature'

from trustpoint_client.api.base import TrustpointClientBaseClass
from trustpoint_client.api.schema import DomainInventory, Credential, PkiProtocol
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]

class TrustpointClientProvision(TrustpointClientBaseClass):

    _provision_data: dict
    _tls_trust_store_path: Path

    def provision(self, otp: str, device: str, host: str, port: int = 443) -> dict:

        self._provision_data = {
            'otp': otp,
            'device': device,
            'host': host,
            'port': port
        }

        self._provision_get_trust_store()
        click.echo('Trust store retrieved successfully, requesting LDevID...')

        self._tls_trust_store_path = (Path(__file__).parent / Path('tls_trust_store.pem'))
        self._tls_trust_store_path.write_text(self._provision_data['trust-store'])

        self._provision_get_ldevid()
        click.echo('LDevID retrieved successfully, requesting LDevID chain...')

        self._provision_get_ldevid_chain()
        click.echo('LDevID chain retrieved successfully, storing in inventory...')

        self._tls_trust_store_path.unlink()

        self._store_ldevid_in_inventory()

        return self._provision_data

    def _provision_get_trust_store(self) -> None:
        host = self._provision_data['host']
        url_extension = self._provision_data['device']
        otp = self._provision_data['otp'].encode()
        salt = self._provision_data['device'].encode()
        port = self._provision_data['port']

        # We do not yet check the TLS server certificate, thus verify=False is set on purpose here
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(
            f'https://{host}:{port}/api/onboarding/trust-store/{url_extension}',
            verify=False,
            timeout=10)
        if not HMAC_SIGNATURE_HTTP_HEADER in response.headers:
            raise ValueError('HMAC missing in HTTP header.')

        self._provision_data['domain'] = response.headers['domain']
        self._provision_data['signature-suite'] = SignatureSuite(response.headers['signature-suite'])
        self._provision_data['pki-protocol'] = PkiProtocol(response.headers['pki-protocol'])
        self._provision_data['crypto-key'] = self.generate_new_key(self._provision_data['signature-suite'])

        pbkdf2_iter = 1000000
        derived_key = hashlib.pbkdf2_hmac('sha256', otp, salt, pbkdf2_iter, dklen=32)
        calculated_hmac = hmac.new(derived_key, response.content, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated_hmac, response.headers[HMAC_SIGNATURE_HTTP_HEADER]):
            raise RuntimeError('HMACs do not match.')

        self._provision_data['trust-store'] = response.content.decode()

    @staticmethod
    def generate_new_key(signature_suite: SignatureSuite) -> PrivateKey:
        rsa_public_exponent = 65537
        if signature_suite == SignatureSuite.RSA2048:
            return rsa.generate_private_key(public_exponent=rsa_public_exponent, key_size=2048)
        if signature_suite == SignatureSuite.RSA3072:
            return rsa.generate_private_key(public_exponent=rsa_public_exponent, key_size=3072)
        if signature_suite == SignatureSuite.RSA4096:
            return rsa.generate_private_key(public_exponent=rsa_public_exponent, key_size=4096)
        if signature_suite == SignatureSuite.SECP256R1:
            return ec.generate_private_key(curve=ec.SECP256R1())
        if signature_suite == SignatureSuite.SECP384R1:
            return ec.generate_private_key(curve=ec.SECP384R1())

        raise ValueError('Algorithm not supported.')

    def _provision_get_ldevid(self) -> None:
        host = self._provision_data['host']
        url_extension = self._provision_data['device']
        otp = self._provision_data['otp'].encode()
        salt = self._provision_data['device'].encode()
        port = self._provision_data['port']
        key = self._provision_data['crypto-key']

        if self._provision_data['signature-suite'] == SignatureSuite.SECP384R1:
            hash_algo = hashes.SHA384
        else:
            hash_algo = hashes.SHA256

        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        x509.NameOID.COMMON_NAME,'Trustpoint LDevID')]))
        csr = csr_builder.sign(key, hash_algo()).public_bytes(serialization.Encoding.PEM)

        # Let Trustpoint sign our CSR (auth via OTP and salt as username via HTTP basic auth)
        files = {'ldevid.csr': csr}

        ldevid_response = requests.post(
            f'https://{host}:{port}/api/onboarding/ldevid/' + url_extension,
            auth=(salt, otp),
            files=files,
            verify=self._tls_trust_store_path,
            timeout=10
        )
        if ldevid_response.status_code != 200:
            error_message = 'Server returned HTTP code ' + str(ldevid_response.status_code)
            raise ValueError(error_message)

        self._provision_data['ldevid'] = ldevid_response.content.decode()

    def _provision_get_ldevid_chain(self) -> None:
        host = self._provision_data['host']
        url_extension = self._provision_data['device']
        port = self._provision_data['port']

        cert_chain = requests.get(
            f'https://{host}:{port}/api/onboarding/ldevid/cert-chain/{url_extension}',
            verify=self._tls_trust_store_path,
            # cert=('ldevid.pem', 'ldevid-private-key.pem'),
            timeout=10,
        )
        if cert_chain.status_code != 200:
            exc_msg = 'Server returned HTTP code ' + str(cert_chain.status_code)
            raise ValueError(exc_msg)

        self._provision_data['ldevid-cert-chain'] = cert_chain.content.decode()

    def _store_ldevid_in_inventory(self) -> None:
        config = self.config
        if self._provision_data['host'] == 'localhost':
            config.trustpoint_ipv4 = '127.0.0.1'
        else:
            config.trustpoint_ipv4 = self._provision_data['host']

        config.trustpoint_port = int(self._provision_data['port'])
        config.default_domain = self._provision_data['domain']
        self._store_config(config)

        ldevid_key_index = self.devid_module.insert_ldevid_key(self._provision_data['crypto-key'])
        self.devid_module.enable_devid_key(ldevid_key_index)

        ldevid_certificate_index = self.devid_module.insert_ldevid_certificate(self._provision_data['ldevid'])
        self.devid_module.enable_devid_certificate(ldevid_certificate_index)
        self.devid_module.insert_ldevid_certificate_chain(
            ldevid_certificate_index, self._provision_data['ldevid-cert-chain'])

        inventory = self.inventory
        ldevid_credential = Credential(
            active_certificate_index=ldevid_certificate_index,
            key_index=ldevid_key_index,
            certificate_indices=[]
        )
        inventory.domains[self._provision_data['domain']] = DomainInventory(
            signature_suite=self._provision_data['signature-suite'],
            pki_protocol = self._provision_data['pki-protocol'],
            ldevid_trust_store=self._provision_data['trust-store'],
            ldevid_credential=ldevid_credential,
            credentials={},
            trust_stores={},
        )
        self._store_inventory(inventory)
