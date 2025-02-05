"""Methods concerning IDevID management."""
from __future__ import annotations

from trustpoint_client.api import TrustpointClientContext, DevIdModule
from trustpoint_client.schema import CredentialModel, CertificateType
from trustpoint_client import oid

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

def inject_idevid(p12_bytes: bytes, password: None | bytes = None) -> None:

    # TODO(AlexHx8472): Proper validation of the p12, matching certs etc.
    p12 = pkcs12.load_pkcs12(p12_bytes, password=password)

    serial_numbers = p12.cert.certificate.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)
    if not serial_numbers:
        err_msg = 'Not a valid IDevID. Missing (device) serial number in subject.'
        raise ValueError(err_msg)
    if len(serial_numbers) > 1:
        err_msg = 'Not a valid IDevID. Multiple (device) serial numbers found in subject.'
        raise ValueError(err_msg)
    serial_number = serial_numbers[0].value

    trustpoint_client_context = TrustpointClientContext()
    if trustpoint_client_context.inventory_model.device_serial_number:
        if trustpoint_client_context.inventory_model.device_serial_number != serial_number:
            err_msg = (
                'Not a valid IDevID. Device serial number does not match the device serial number of this client.'
            )
            raise ValueError(err_msg)
    else:
        trustpoint_client_context.inventory_model.device_serial_number = serial_number

    idevid_signature_suite = str(oid.SignatureSuite.from_certificate(p12.cert.certificate))
    if idevid_signature_suite in trustpoint_client_context.inventory_model.idevids:
        raise ValueError(f'IDevID for signature suite {idevid_signature_suite} already installed.')

    devid_module = DevIdModule()
    key_index = devid_module.insert_idevid_key(private_key=p12.key, password=None)
    devid_module.enable_devid_key(key_index=key_index)

    certificate_index = devid_module.insert_idevid_certificate(certificate=p12.cert.certificate)
    devid_module.enable_devid_certificate(certificate_index=certificate_index)

    devid_module.insert_idevid_certificate_chain(
        certificate_index=certificate_index,
        certificate_chain=[cert.certificate for cert in p12.additional_certs]
    )

    idevid_credential_model = CredentialModel(
        certificate_index=certificate_index,
        key_index=key_index,
        subject=p12.cert.certificate.subject.rfc4514_string(
            attr_name_overrides={x509.NameOID.SERIAL_NUMBER: 'Serial-Number'}),
        certificate_type=CertificateType.IDevID,
        not_valid_before=p12.cert.certificate.not_valid_before_utc,
        not_valid_after=p12.cert.certificate.not_valid_after_utc
    )

    trustpoint_client_context.inventory_model.idevids[idevid_signature_suite] = idevid_credential_model
    trustpoint_client_context.store_inventory()


def delete_idevid(signature_suite: str) -> None:

    trustpoint_client_context = TrustpointClientContext()
    if signature_suite not in trustpoint_client_context.inventory_model.idevids:
        raise ValueError(f'IDevID for signature suite {signature_suite} not installed. Nothin to delete.')

    trustpoint_client_context.inventory_model.idevids.pop(signature_suite)
    trustpoint_client_context.store_inventory()