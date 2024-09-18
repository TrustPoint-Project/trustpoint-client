from __future__ import annotations

import click
import traceback

import requests
import hashlib
import hmac

import urllib3

HMAC_SIGNATURE_HTTP_HEADER = 'hmac-signature'
DOMAIN= 'domain'

from trustpoint_client.api.base import TrustpointClientBaseClass
from trustpoint_client.api.schema import DomainInventory, Credential, PkiProtocol
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from enum import IntEnum

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]


class ProvisioningState(IntEnum):
    """Enum for the state of the provisioning process."""

    ERROR = -1
    NO_TRUST = 0
    ONESIDED_TRUST = 1
    MUTUAL_TRUST = 2


class TrustpointClientProvision(TrustpointClientBaseClass):

    _provisioning_state_callback = None

    _provision_data: dict

    def _callback(self, state: ProvisioningState) -> None:
        if self._provisioning_state_callback:
            self._provisioning_state_callback(state)

    def set_provisioning_state_callback(self, func: callable) -> None:
        self._provisioning_state_callback = func

    def set_provisioning_state(self, state: ProvisioningState) -> None:
        """Temporary method to call the callback from zero touch onboarding methods"""
        self._callback(state)

    def provision(self, otp: str, device: str, host: str, port: int = 443) -> dict:

        self._provision_data = {
            'otp': otp,
            'device': device,
            'host': host,
            'port': port
        }

        self._callback(ProvisioningState.NO_TRUST)
        
        self._provision_get_trust_store()
        click.echo('Trust store retrieved successfully, requesting LDevID...')
        self._callback(ProvisioningState.ONESIDED_TRUST)

        self._provision_get_ldevid()
        click.echo('LDevID retrieved successfully, requesting LDevID chain...')
        self._callback(ProvisioningState.MUTUAL_TRUST)

        self._provision_get_ldevid_chain()
        click.echo('LDevID chain retrieved successfully, storing in inventory...')

        self._store_ldevid_in_inventory()

        return self._provision_data

    def provision_zero_touch(self, otp: str, device: str,
                             host: str, port: int = 443, trust_store: str = '', domain : str = 'default') -> dict:
        """Temporary zero-touch compatibility layer."""

        self._provision_data = {
            'otp': otp,
            'device': device,
            'host': host,
            'port': port,
            'domain': domain
        }
        # TODO: Do not hardcode algo
        self._provision_data['algorithm'] = 'ECC'
        self._provision_data['curve'] = 'SECP256R1'
        self._provision_data['key-size'] = '256'
        self._provision_data['crypto-key'] = self._get_key(
            algorithm=self._provision_data['algorithm'],
            curve=self._provision_data['curve'],
            key_size=self._provision_data['key-size'])

        self._provision_data['default-pki-protocol'] = PkiProtocol('REST')

        self._provision_get_ldevid()
        self._callback(ProvisioningState.MUTUAL_TRUST)

        return self._provision_data

    def _provision_get_trust_store(self) -> None:
        host = self._provision_data['host']
        url_extension = self._provision_data['device']
        otp = self._provision_data['otp'].encode()
        salt = self._provision_data['device'].encode()
        port = self._provision_data['port']

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(
            f'https://{host}:{port}/api/onboarding/trust-store/{url_extension}', verify=False, timeout=10)
        # TODO: check http status code
        if not HMAC_SIGNATURE_HTTP_HEADER in response.headers:
            # TODO: ExceptionHandling
            raise ValueError('HMAC missing in HTTP header.')
        if not DOMAIN in response.headers:
            raise ValueError('Domain missing in HTTP header.')
        domain = response.headers[DOMAIN]
        self._provision_data['domain'] = domain
        self._provision_data['algorithm'] = response.headers['algorithm']
        self._provision_data['curve'] = response.headers['curve']
        self._provision_data['key-size'] = response.headers['key-size']
        self._provision_data['device-id'] = response.headers['device-id']
        self._provision_data['default-pki-protocol'] = PkiProtocol(response.headers['default-pki-protocol'])
        self._provision_data['crypto-key'] = self._get_key(
            algorithm=self._provision_data['algorithm'],
            curve=self._provision_data['curve'],
            key_size=self._provision_data['key-size'])
        pbkdf2_iter = 1000000
        derived_key = hashlib.pbkdf2_hmac('sha256', otp, salt, pbkdf2_iter, dklen=32)
        calculated_hmac = hmac.new(derived_key, response.content, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated_hmac, response.headers[HMAC_SIGNATURE_HTTP_HEADER]):
            raise RuntimeError('HMACs do not match.')

        self._provision_data['trust_store'] = response.content.decode()

    @staticmethod
    def _get_key(algorithm: str, curve: str, key_size: str) -> PrivateKey:
        if algorithm.upper() == 'RSA':
            if key_size == '2048':
                key_size = 2048
            elif key_size == '3072':
                key_size = 3072
            elif key_size == '4096':
                key_size = 4096
            else:
                raise ValueError('Key size not supported.')
            return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        if algorithm.upper() == 'ECC':
            if curve.upper() == 'SECP256R1':
                return ec.generate_private_key(curve=ec.SECP256R1())
            elif curve.upper() == 'SECP384R1':
                return ec.generate_private_key(curve=ec.SECP384R1())
            else:
                raise ValueError('Curve not supported.')

        raise ValueError('Algorithm not supported.')

    def _provision_get_ldevid(self) -> None:
        host = self._provision_data['host']
        url_extension = self._provision_data['device']
        otp = self._provision_data['otp'].encode()
        salt = self._provision_data['device'].encode()
        port = self._provision_data['port']
        key = self._provision_data['crypto-key']

        if self._provision_data['curve'].upper() == 'SECP384R1':
            hash_algo = hashes.SHA384
        else:
            hash_algo = hashes.SHA256

        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        x509.NameOID.COMMON_NAME,
                        f'trustpoint-client.ldevid.{self._provision_data["domain"]}')]))
        csr = csr_builder.sign(key, hash_algo()).public_bytes(serialization.Encoding.PEM)

        # Let Trustpoint sign our CSR (auth via OTP and salt as username via HTTP basic auth)
        files = {'ldevid.csr': csr}
        ldevid_response = requests.post(
            f'https://{host}:{port}/api/onboarding/ldevid/' + url_extension,
            auth=(salt, otp),
            files=files,
            # TODO
            verify=False,
            timeout=10
        )
        if ldevid_response.status_code != 200:
            exc_msg = 'Server returned HTTP code ' + str(ldevid_response.status_code)
            raise ValueError(exc_msg)

        self._provision_data['ldevid'] = ldevid_response.content.decode()

    def _provision_get_ldevid_chain(self) -> None:
        host = self._provision_data['host']
        url_extension = self._provision_data['device']
        port = self._provision_data['port']
        cert_chain = requests.get(
            f'https://{host}:{port}/api/onboarding/ldevid/cert-chain/{url_extension}',
            verify=False,
            # cert=('ldevid.pem', 'ldevid-private-key.pem'),
            timeout=10,
        )
        if cert_chain.status_code != 200:
            exc_msg = 'Server returned HTTP code ' + str(cert_chain.status_code)
            raise ValueError(exc_msg)

        self._provision_data['ldevid-cert-chain'] = cert_chain.content.decode()

    def _store_ldevid_in_inventory(self) -> None:
        config = self.config
        config.device_id = int(self._provision_data['device-id'])
        config.trustpoint_ipv4 = self._provision_data['host']
        config.trustpoint_port = int(self._provision_data['port'])
        config.default_domain = self._provision_data['domain']
        config.pki_protocol = self._provision_data['default-pki-protocol']
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
            ldevid_trust_store=self._provision_data['trust_store'],
            ldevid_credential=ldevid_credential,
            credentials={},
            trust_stores={}
        )
        self._store_inventory(inventory)
