"""Provides functions to onboard the Trustpoint-Client (device) into domains."""

import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from trustpoint_devid_module.service_interface import DevIdModule

from trustpoint_client.oid import SignatureSuite
from trustpoint_client.schema import DomainConfigModel, CredentialModel, CertificateType, DomainModel
from trustpoint_client.api import WORKING_DIR, TrustpointClientContext
from trustpoint_client.oid import PublicKeyInfo, KeyPairGenerator
import uuid
from ipaddress import IPv4Address, IPv6Address

from pathlib import Path


def onboard_with_shared_secret(
        host: str | IPv4Address | IPv6Address,
        domain: str, 
        device_id: int,
        shared_secret: str | bytes,
        public_key_info: PublicKeyInfo,
        port: int = 443) -> None:
    """Onboards the device into a domain using a shared secret.

    This function uses CMP with a password based mac to onboard the device and to acquire a domain credential (LDevID).

    Args:
        host:
        domain: The domain to onboard into.
        device_id: The shared secret reference, which will be required by the CMP endpoint.
        shared_secret: Shared secret to use for onboarding.
        public_key_info:
        port:
    """
    trustpoint_client_context = TrustpointClientContext()
    devid_module = DevIdModule()
    domain = domain.strip()

    inventory_model = trustpoint_client_context.inventory_model
    if domain in inventory_model.domains:
        raise ValueError('Domain already exists.')

    if isinstance(shared_secret, bytes):
        shared_secret = shared_secret.decode()

    new_private_key = KeyPairGenerator.generate_key_pair_for_public_key_info(public_key_info)

    tmp_file_name = str(uuid.uuid4())
    tmp_key_file_name = tmp_file_name + '-key.der'
    tmp_cert_file_name = tmp_file_name + '-cert.pem'
    tmp_extra_certs_file_name = tmp_file_name + '-extra-certs.pem'


    tmp_key_file_path = WORKING_DIR / Path(tmp_key_file_name)
    tmp_cert_file_path = WORKING_DIR / Path(tmp_cert_file_name)
    tmp_extra_certs_file_path = WORKING_DIR / Path(tmp_extra_certs_file_name)

    tmp_key_file_path.write_bytes(
            new_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
    )

    # TODO(AlexHx8472): http -> https as soon as possible after dev phase for container usage.
    ossl_cmp_cmd = (
        'openssl cmp '
        '-cmd ir '
        '-implicit_confirm '
        f'-server "http://{host}:{port}/.well-known/cmp/initialization/{domain}/" '
        f'-secret "pass:{shared_secret}" '
        f'-ref "{device_id}" '
        '-subject "/CN=Trustpoint Domain Credential" '
        f'-newkey "{tmp_key_file_path.resolve()}" '
        f'-certout "{tmp_cert_file_path.resolve()}" '
        f'-extracertsout "{tmp_extra_certs_file_path.resolve()}"'
    )

    subprocess.run(ossl_cmp_cmd, shell=True)

    tmp_key_file_path.unlink()

    # TODO(AlexHx8472): Properly verify the contents of the domain credential certificate
    # TODO(AlexHx8472): Properly verify the chain (extra-certs)

    domain_credential_certificate = x509.load_pem_x509_certificate(tmp_cert_file_path.read_bytes())
    certificate_chain = x509.load_pem_x509_certificates(tmp_extra_certs_file_path.read_bytes())

    serial_number = domain_credential_certificate.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)
    if len(serial_number) < 1:
        err_msg = 'Received domain credential certificate is missing the device serial number. Rejecting certificate.'
        raise ValueError(err_msg)
    if len(serial_number) > 1:
        err_msg = (
            'Received domain credential certificate has multiple serial number fields in the subject. '
            'Rejecting certificate.')
        raise ValueError(err_msg)

    serial_number_value = serial_number[0].value.strip()
    if inventory_model.device_serial_number is not None:
        if inventory_model.device_serial_number != serial_number_value:
            err_msg = (
                'Received domain credential certificate contains a device serial number '
                'that does not match this device. Rejecting certificate.'
            )
            raise ValueError(err_msg)
    else:
        inventory_model.device_serial_number = serial_number_value

    if inventory_model.default_domain is None:
        inventory_model.default_domain = domain

    # inserting private key, certificate and chain into the devid module
    key_index = devid_module.insert_ldevid_key(private_key=new_private_key)
    devid_module.enable_devid_key(key_index=key_index)

    cert_index = devid_module.insert_ldevid_certificate(certificate=domain_credential_certificate)
    devid_module.enable_devid_certificate(certificate_index=cert_index)

    devid_module.insert_ldevid_certificate_chain(certificate_index=cert_index, certificate_chain=certificate_chain)

    credential_model = CredentialModel(
        certificate_index=cert_index,
        key_index=key_index,
        subject=domain_credential_certificate.subject.rfc4514_string(
            attr_name_overrides={x509.NameOID.SERIAL_NUMBER: 'Serial-Number'}
        ),
        certificate_type=CertificateType.DOMAIN,
        not_valid_before=domain_credential_certificate.not_valid_before_utc,
        not_valid_after=domain_credential_certificate.not_valid_after_utc,
    )

    domain_config_model = DomainConfigModel(
        trustpoint_addresses=[str(host) + ':' + str(port)],
        tls_trust_store=[]
    )

    domain_model = DomainModel(
        domain_config=domain_config_model,
        idevid_credential=None,
        domain_credential=credential_model,
        credentials={},
        trust_stores={}
    )

    inventory_model.domains[domain] = domain_model
    trustpoint_client_context.store_inventory()
