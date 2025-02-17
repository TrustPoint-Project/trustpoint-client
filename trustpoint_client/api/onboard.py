"""Provides functions to onboard the Trustpoint-Client (device) into domains."""

import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from trustpoint_devid_module.service_interface import DevIdModule

from trustpoint_client.schema import DomainConfigModel, CredentialModel, CertificateType, DomainModel
from trustpoint_client.api import WORKING_DIR, TrustpointClientContext
from trustpoint_client.oid import PublicKeyInfo, KeyPairGenerator, SignatureSuite
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

    inventory_model = trustpoint_client_context.inventory_model

    if inventory_model.default_domain or inventory_model.domains:
        err_msg = (
            'Currently only a single domain is supported. '
            'In a future version it will be possible to onboard to arbitrary many domains simultaneously. '
            'If you want to onboard to a different domain use the \'purge\' command to reset the Trustpoint-Client.')
        raise ValueError(err_msg)
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
    domain_signature_suite = SignatureSuite.from_certificate(domain_credential_certificate)
    certificate_chain = x509.load_pem_x509_certificates(tmp_extra_certs_file_path.read_bytes())

    serial_numbers = domain_credential_certificate.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)
    if len(serial_numbers) < 1:
        err_msg = 'Received domain credential certificate is missing the device serial number. Rejecting certificate.'
        raise ValueError(err_msg)
    if len(serial_numbers) > 1:
        err_msg = (
            'Received domain credential certificate has multiple serial number fields in the subject. '
            'Rejecting certificate.')
        raise ValueError(err_msg)

    serial_number = serial_numbers[0].value
    if serial_number is None:
        err_msg = 'Found an empty Serial Number entry in the IDevID certificate subject.'
        raise ValueError(err_msg)
    elif isinstance(serial_number, bytes):
        try:
            serial_number = serial_number.decode()
        except Exception as exception:
            raise ValueError(
                'Failed to decode IDevID certificate subject serial number.'
                'ASN.1 / DER seems to be malformed.') from exception

    if inventory_model.device_serial_number is None:
        inventory_model.device_serial_number = serial_number
    elif inventory_model.device_serial_number != serial_number:
        err_msg = (
            f'Serial-number of this device does not match the serial number in the received '
            f'domain credential certificate. Rejecting certificate.'
        )
        raise ValueError(err_msg)

    if inventory_model.default_domain is None:
        inventory_model.default_domain = domain

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
        tls_trust_store=[],
        signature_suite=str(domain_signature_suite)
    )

    domain_model = DomainModel(
        domain_config=domain_config_model,
        idevid_available=False,
        domain_credential=credential_model,
        credentials={},
        trust_stores={}
    )

    inventory_model.domains[domain] = domain_model
    trustpoint_client_context.store_inventory()


def onboard_with_idevid(
        host: str | IPv4Address | IPv6Address,
        domain: str,
        signature_suite: SignatureSuite,
        port: int = 443) -> None:
    """Onboards the device into a domain using a shared secret.

    This function uses CMP with a password based mac to onboard the device and to acquire a domain credential (LDevID).

    Args:
        host:
        domain: The domain to onboard into.
        signature_suite:
        port:
    """
    trustpoint_client_context = TrustpointClientContext()
    devid_module = DevIdModule()

    inventory_model = trustpoint_client_context.inventory_model

    if inventory_model.default_domain or inventory_model.domains:
        err_msg = (
            'Currently only a single domain is supported. '
            'In a future version it will be possible to onboard to arbitrary many domains simultaneously. '
            'If you want to onboard to a different domain use the \'purge\' command to reset the Trustpoint-Client.')
        raise ValueError(err_msg)
    
    if domain in inventory_model.domains:
        raise ValueError('Domain already exists.')

    signature_suite_str = str(signature_suite)
    if signature_suite_str not in inventory_model.idevids:
        err_msg = f'No IDevID found for signature suite {signature_suite_str}.'
        raise ValueError(err_msg)

    idevid_key_index = inventory_model.idevids[signature_suite_str].key_index
    idevid_cert_index = inventory_model.idevids[signature_suite_str].certificate_index

    new_private_key = KeyPairGenerator.generate_key_pair_for_public_key_info(signature_suite.public_key_info)

    tmp_file_name = str(uuid.uuid4())
    tmp_key_file_name = tmp_file_name + '-key.der'
    tmp_cert_file_name = tmp_file_name + '-cert.pem'
    tmp_extra_certs_file_name = tmp_file_name + '-extra-certs.pem'
    tmp_idevid_private_key_file_name = tmp_file_name + '-idevid_private_key.der'
    tmp_idevid_certificate_file_name = tmp_file_name + '-idevid_certificate.pem'

    tmp_key_file_path = WORKING_DIR / Path(tmp_key_file_name)
    tmp_cert_file_path = WORKING_DIR / Path(tmp_cert_file_name)
    tmp_extra_certs_file_path = WORKING_DIR / Path(tmp_extra_certs_file_name)
    tmp_idevid_private_key_file_path = WORKING_DIR / Path(tmp_idevid_private_key_file_name)
    tmp_idevid_certificate_file_path = WORKING_DIR / Path(tmp_idevid_certificate_file_name)

    tmp_idevid_private_key_file_path.write_bytes(devid_module.inventory.devid_keys[idevid_key_index].private_key)
    tmp_idevid_certificate_file_path.write_bytes(
        devid_module.inventory.devid_certificates[idevid_cert_index].certificate)

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
        '-subject "/CN=Trustpoint Domain Credential" '
        '-popo 1 '
        f'-key "{tmp_idevid_private_key_file_path.resolve()}" '
        f'-cert "{tmp_idevid_certificate_file_path.resolve()}" '
        f'-newkey "{tmp_key_file_path.resolve()}" '
        f'-certout "{tmp_cert_file_path.resolve()}" '
        f'-extracertsout "{tmp_extra_certs_file_path.resolve()}"'
    )

    subprocess.run(ossl_cmp_cmd, shell=True)

    tmp_key_file_path.unlink()

    # # TODO(AlexHx8472): Properly verify the contents of the domain credential certificate
    # # TODO(AlexHx8472): Properly verify the chain (extra-certs)
    # 
    # domain_credential_certificate = x509.load_pem_x509_certificate(tmp_cert_file_path.read_bytes())
    # domain_signature_suite = SignatureSuite.from_certificate(domain_credential_certificate)
    # certificate_chain = x509.load_pem_x509_certificates(tmp_extra_certs_file_path.read_bytes())
    # 
    # serial_numbers = domain_credential_certificate.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)
    # if len(serial_numbers) < 1:
    #     err_msg = 'Received domain credential certificate is missing the device serial number. Rejecting certificate.'
    #     raise ValueError(err_msg)
    # if len(serial_numbers) > 1:
    #     err_msg = (
    #         'Received domain credential certificate has multiple serial number fields in the subject. '
    #         'Rejecting certificate.')
    #     raise ValueError(err_msg)
    # 
    # serial_number = serial_numbers[0].value
    # if serial_number is None:
    #     err_msg = 'Found an empty Serial Number entry in the IDevID certificate subject.'
    #     raise ValueError(err_msg)
    # elif isinstance(serial_number, bytes):
    #     try:
    #         serial_number = serial_number.decode()
    #     except Exception as exception:
    #         raise ValueError(
    #             'Failed to decode IDevID certificate subject serial number.'
    #             'ASN.1 / DER seems to be malformed.') from exception
    # 
    # if inventory_model.device_serial_number is None:
    #     inventory_model.device_serial_number = serial_number
    # elif inventory_model.device_serial_number != serial_number:
    #     err_msg = (
    #         f'Serial-number of this device does not match the serial number in the received '
    #         f'domain credential certificate. Rejecting certificate.'
    #     )
    #     raise ValueError(err_msg)
    # 
    # if inventory_model.default_domain is None:
    #     inventory_model.default_domain = domain
    # 
    # key_index = devid_module.insert_ldevid_key(private_key=new_private_key)
    # devid_module.enable_devid_key(key_index=key_index)
    # 
    # cert_index = devid_module.insert_ldevid_certificate(certificate=domain_credential_certificate)
    # devid_module.enable_devid_certificate(certificate_index=cert_index)
    # 
    # devid_module.insert_ldevid_certificate_chain(certificate_index=cert_index, certificate_chain=certificate_chain)
    # 
    # credential_model = CredentialModel(
    #     certificate_index=cert_index,
    #     key_index=key_index,
    #     subject=domain_credential_certificate.subject.rfc4514_string(
    #         attr_name_overrides={x509.NameOID.SERIAL_NUMBER: 'Serial-Number'}
    #     ),
    #     certificate_type=CertificateType.DOMAIN,
    #     not_valid_before=domain_credential_certificate.not_valid_before_utc,
    #     not_valid_after=domain_credential_certificate.not_valid_after_utc,
    # )
    # 
    # domain_config_model = DomainConfigModel(
    #     trustpoint_addresses=[str(host) + ':' + str(port)],
    #     tls_trust_store=[],
    #     signature_suite=str(domain_signature_suite)
    # )
    # 
    # domain_model = DomainModel(
    #     domain_config=domain_config_model,
    #     idevid_available=False,
    #     domain_credential=credential_model,
    #     credentials={},
    #     trust_stores={}
    # )
    # 
    # inventory_model.domains[domain] = domain_model
    # trustpoint_client_context.store_inventory()
