"""Trustpoint-Client Onboarding API."""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import TYPE_CHECKING

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import oid

from trustpoint_client.api.schema import (
    CertificateType,
    CredentialModel,
    DomainConfigModel,
    DomainModel,
    PkiProtocol,
    SignatureSuite,
)

if TYPE_CHECKING:
    from typing import Any, Union

    from trustpoint_devid_module.serializer import CredentialSerializer
    from trustpoint_devid_module.service_interface import DevIdModule

    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]


HMAC_SIGNATURE_HTTP_HEADER = 'hmac-signature'
HTTP_STATUS_OK = 200


class TrustpointClientOnboardingMixin:
    """Mixin for the Trustpoint-Client that provides the onboarding features."""

    devid_module: DevIdModule
    inventory: property
    default_domain: property
    _store_inventory: callable

    def onboard_auto(
        self, otp: str, device: str, host: str, port: int = 443, extra_data: dict | None = None
    ) -> dict[str, int | str]:
        """Automatic onboarding using the Trustpoint-Client onboarding method.

        Args:
            otp: The required OTP to use in the onboarding process.
            device: The device name to use in the onboarding process.
            host: The host name or address (IPv4) of the Trustpoint.
            port: The port number of the Trustpoint.
            extra_data: Extra data to pass to the onboarding process.
        """
        onboard_data = {'otp': otp, 'device': device, 'host': host, 'port': port}

        if extra_data:  # trust store and protocol info already provided (e.g. by zero-touch demo)
            try:
                onboard_data['trust-store'] = extra_data['trust-store']
                onboard_data['domain'] = extra_data['domain']
                onboard_data['signature-suite'] = SignatureSuite(extra_data['signature-suite'])
                onboard_data['pki-protocol'] = PkiProtocol(extra_data['pki-protocol'])
            except KeyError as exception:
                err_msg = f'extra_data provided, but does not contain required key {exception}.'
                raise ValueError(err_msg) from exception
        else:
            self._onboard_get_trust_store(onboard_data=onboard_data)
        tls_trust_store_path = Path(__file__).parent / Path('tls_trust_store.pem')
        tls_trust_store_path.write_text(onboard_data['trust-store'])
        onboard_data['crypto-key'] = self.generate_new_key(onboard_data['signature-suite'])
        self._onboard_get_ldevid(onboard_data=onboard_data, tls_trust_store_path=tls_trust_store_path)
        self._onboard_get_ldevid_chain(onboard_data=onboard_data, tls_trust_store_path=tls_trust_store_path)
        tls_trust_store_path.unlink()

        loaded_cert = x509.load_pem_x509_certificate(onboard_data['ldevid'].encode())
        onboard_data['ldevid-subject'] = loaded_cert.subject.rfc4514_string()
        onboard_data['ldevid-certificate-type'] = CertificateType.LDEVID
        onboard_data['ldevid-not-valid-before'] = loaded_cert.not_valid_before_utc
        onboard_data['ldevid-not-valid-after'] = loaded_cert.not_valid_after_utc
        onboard_data['ldevid-expires-in'] = (
            onboard_data['ldevid-not-valid-after'] - onboard_data['ldevid-not-valid-before']
        )
        onboard_data['serial-number'] = loaded_cert.subject.get_attributes_for_oid(oid.NameOID.SERIAL_NUMBER)[0].value

        self._store_ldevid_in_inventory(onboard_data=onboard_data)

        result = {
            'Device': onboard_data['device'],
            'Serial-Number': onboard_data['serial-number'],
            'Host': onboard_data['host'],
            'Port': onboard_data['port'],
            'PKI-Protocol': onboard_data['pki-protocol'].value,
            'Signature-Suite': onboard_data['signature-suite'].value,
            'LDevID Subject': onboard_data['ldevid-subject'],
            'LDevID Certificate Type': onboard_data['ldevid-certificate-type'].value,
            'LDevID Not-Valid-Before': onboard_data['ldevid-not-valid-before'],
            'LDevID Not-Valid-After': onboard_data['ldevid-not-valid-after'],
            'LDevID Expires-In': onboard_data['ldevid-expires-in'],
        }

        if result['Host'] == 'localhost':
            result['Host'] = '127.0.0.1'

        return result

    def _onboard_get_trust_store(self, onboard_data: dict[str, Any]) -> None:
        host = onboard_data['host']
        url_extension = onboard_data['device']
        otp = onboard_data['otp'].encode()
        salt = onboard_data['device'].encode()
        port = onboard_data['port']

        # We do not yet check the TLS server certificate, thus verify=False is set on purpose here
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(
            f'https://{host}:{port}/api/onboarding/trust-store/{url_extension}',
            verify=False,   # noqa: S501
            timeout=10,
        )
        if HMAC_SIGNATURE_HTTP_HEADER not in response.headers:
            err_msg = 'HMAC missing in HTTP header.'
            raise ValueError(err_msg)

        onboard_data['domain'] = response.headers['domain']
        onboard_data['signature-suite'] = SignatureSuite(response.headers['signature-suite'])
        onboard_data['pki-protocol'] = PkiProtocol(response.headers['pki-protocol'])

        pbkdf2_iter = 1000000
        derived_key = hashlib.pbkdf2_hmac('sha256', otp, salt, pbkdf2_iter, dklen=32)
        calculated_hmac = hmac.new(derived_key, response.content, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated_hmac, response.headers[HMAC_SIGNATURE_HTTP_HEADER]):
            err_msg = 'HMACs do not match.'
            raise RuntimeError(err_msg)

        onboard_data['trust-store'] = response.content.decode()

    @staticmethod
    def generate_new_key(signature_suite: SignatureSuite) -> PrivateKey:
        """Generates a matching keypair for the given signature-suite.

        Args:
            signature_suite: Signature-suite that determines which type of key to generate.
        """
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

        err_msg = 'Algorithm not supported.'
        raise ValueError(err_msg)

    @staticmethod
    def _onboard_get_ldevid(onboard_data: dict[str, Any], tls_trust_store_path: Path) -> None:
        host = onboard_data['host']
        url_extension = onboard_data['device']
        otp = onboard_data['otp'].encode()
        salt = onboard_data['device'].encode()
        port = onboard_data['port']
        key = onboard_data['crypto-key']

        hash_algo = hashes.SHA384 if onboard_data['signature-suite'] == SignatureSuite.SECP384R1 else hashes.SHA256

        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Trustpoint LDevID')])
        )
        csr = csr_builder.sign(key, hash_algo()).public_bytes(serialization.Encoding.PEM)

        # Let Trustpoint sign our CSR (auth via OTP and salt as username via HTTP basic auth)
        files = {'ldevid.csr': csr}

        ldevid_response = requests.post(
            f'https://{host}:{port}/api/onboarding/ldevid/' + url_extension,
            auth=(salt, otp),
            files=files,
            verify=tls_trust_store_path,
            timeout=10,
        )
        if ldevid_response.status_code != HTTP_STATUS_OK:
            error_message = 'Server returned HTTP code ' + str(ldevid_response.status_code)
            raise ValueError(error_message)

        onboard_data['ldevid'] = ldevid_response.content.decode()

    @staticmethod
    def _onboard_get_ldevid_chain(onboard_data: dict[str, Any], tls_trust_store_path: Path) -> None:
        host = onboard_data['host']
        url_extension = onboard_data['device']
        port = onboard_data['port']

        cert_chain = requests.get(
            f'https://{host}:{port}/api/onboarding/ldevid/cert-chain/{url_extension}',
            verify=tls_trust_store_path,
            # TODO(AlexHx8472): add proper TLS server verification: cert=('ldevid.pem', 'ldevid-private-key.pem'),
            timeout=10,
        )
        if cert_chain.status_code != HTTP_STATUS_OK:
            exc_msg = 'Server returned HTTP code ' + str(cert_chain.status_code)
            raise ValueError(exc_msg)

        onboard_data['ldevid-cert-chain'] = cert_chain.content.decode()

    def _store_ldevid_in_inventory(self, onboard_data: dict[str, Any]) -> None:
        ldevid_key_index = self.devid_module.insert_ldevid_key(onboard_data['crypto-key'])
        self.devid_module.enable_devid_key(ldevid_key_index)
        ldevid_certificate_index = self.devid_module.insert_ldevid_certificate(onboard_data['ldevid'])
        self.devid_module.enable_devid_certificate(ldevid_certificate_index)
        self.devid_module.insert_ldevid_certificate_chain(ldevid_certificate_index, onboard_data['ldevid-cert-chain'])

        inventory = self.inventory
        ldevid_credential = CredentialModel(
            unique_name='domain-credential',
            certificate_index=ldevid_certificate_index,
            key_index=ldevid_key_index,
            subject=onboard_data['ldevid-subject'],
            certificate_type=onboard_data['ldevid-certificate-type'],
            not_valid_before=onboard_data['ldevid-not-valid-before'],
            not_valid_after=onboard_data['ldevid-not-valid-after'],
        )

        trustpoint_host = '127.0.0.1' if onboard_data['host'] == 'localhost' else onboard_data['host']

        domain_config = DomainConfigModel(
            device=onboard_data['device'],
            serial_number=onboard_data['serial-number'],
            domain=onboard_data['domain'],
            trustpoint_host=trustpoint_host,
            trustpoint_port=onboard_data['port'],
            signature_suite=onboard_data['signature-suite'],
            pki_protocol=onboard_data['pki-protocol'],
            tls_trust_store=onboard_data['trust-store'],
        )

        inventory.domains[onboard_data['domain']] = DomainModel(
            domain_config=domain_config,
            ldevid_credential=ldevid_credential,
            credentials={},
            trust_stores={},
        )
        self._store_inventory(inventory)

        if self.default_domain is None:
            self.default_domain = onboard_data['domain']

    def onboard_manual(
        self, trustpoint_host: str, trustpoint_port: int, pki_protocol: PkiProtocol, credential: CredentialSerializer
    ) -> dict[str, int | str]:
        """Onboards the trustpoint-client through importing the LDevID credential as file.

        Args:
            trustpoint_host: The host name or address (IPv4) of the trustpoint.
            trustpoint_port: The port number of the trustpoint.
            pki_protocol: The default pki protocol to use to manage certificates.
            credential: The credential to be used for onboarding.
        """
        cert = credential.credential_certificate.as_crypto()
        err_msg = 'Certificate does not seem to be an LDevID issued by a Trustpoint.'
        try:
            serial = cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
            pseudonym = cert.subject.get_attributes_for_oid(x509.OID_PSEUDONYM)[0].value
            domain = cert.subject.get_attributes_for_oid(x509.OID_DN_QUALIFIER)[0].value.split('.')
            if domain[0].lower() != 'trustpoint':
                raise ValueError(err_msg)
            domain = domain[-1]
        except KeyError as exception:
            raise ValueError(err_msg) from exception

        if domain in self.inventory.domains:
            err_msg = f'Domain with unique name {domain} already exists.'
            raise ValueError(err_msg)

        private_key = credential.credential_private_key.as_crypto()
        cert = credential.credential_certificate.as_crypto()
        cert_chain = credential.additional_certificates.as_crypto()

        ldevid_key_index = self.devid_module.insert_ldevid_key(private_key)
        self.devid_module.enable_devid_key(ldevid_key_index)
        ldevid_certificate_index = self.devid_module.insert_ldevid_certificate(cert)
        self.devid_module.enable_devid_certificate(ldevid_certificate_index)
        self.devid_module.insert_ldevid_certificate_chain(ldevid_certificate_index, cert_chain)

        inventory = self.inventory
        ldevid_credential = CredentialModel(
            unique_name='domain-credential',
            certificate_index=ldevid_certificate_index,
            key_index=ldevid_key_index,
            subject=cert.subject.rfc4514_string(),
            certificate_type=CertificateType.LDEVID,
            not_valid_before=cert.not_valid_before_utc,
            not_valid_after=cert.not_valid_after_utc,
        )

        if trustpoint_host == 'localhost':
            trustpoint_host = '127.0.0.1'

        domain_config = DomainConfigModel(
            device=pseudonym,
            serial_number=serial,
            domain=domain,
            trustpoint_host=trustpoint_host,
            trustpoint_port=trustpoint_port,
            signature_suite=SignatureSuite.get_signature_suite_by_public_key(cert.public_key()),
            pki_protocol=pki_protocol,
            tls_trust_store='None',
        )

        inventory.domains[domain] = DomainModel(
            domain_config=domain_config,
            ldevid_credential=ldevid_credential,
            credentials={},
            trust_stores={},
        )
        self._store_inventory(inventory)

        if self.default_domain is None:
            self.default_domain = domain

        return {
            'Device': pseudonym,
            'Serial-Number': serial,
            'Host': trustpoint_host,
            'Port': trustpoint_port,
            'PKI-Protocol': pki_protocol.value,
            'Signature-Suite': SignatureSuite.get_signature_suite_by_public_key(cert.public_key()).value,
            'LDevID Subject': cert.subject.rfc4514_string(),
            'LDevID Certificate Type': CertificateType.LDEVID.value,
            'LDevID Not-Valid-Before': cert.not_valid_before_utc,
            'LDevID Not-Valid-After': cert.not_valid_after_utc,
            'LDevID Expires-In': cert.not_valid_after_utc - cert.not_valid_before_utc,
        }
