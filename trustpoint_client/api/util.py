"""Utility methods and demo features."""
from __future__ import annotations


import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes, serialization

from trustpoint_client.schema import IdevidCredentialModel
from trustpoint_client import oid
from typing import cast

from typing import Union
SupportedHashAlgorithms = Union[
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
    hashes.SHA3_224,
    hashes.SHA3_256,
    hashes.SHA3_384,
    hashes.SHA3_512
]

from trustpoint_client.api import DemoIdevidContext
from trustpoint_client.schema import IdevidHierarchyModel

MIN_RSA_KEY_SIZE = 2048


def create_idevid_hierarchy(
        hierarchy_name: str,
        algorithm: oid.PublicKeyAlgorithmOid,
        hash_algorithm: oid.HashAlgorithm,
        named_curve: None | oid.NamedCurve = None,
        key_size: None | int = None,
) -> None:
    if not hierarchy_name.isidentifier():
        err_msg = 'Name must be a valid identifier. Must only contain letters, numbers and underscores.'
        raise ValueError(err_msg)

    if algorithm == oid.PublicKeyAlgorithmOid.NONE:
        err_msg = 'Algorithm must either be RSA or ECC.'
        raise ValueError(err_msg)

    if hash_algorithm.verbose_name in ['MD5', 'SHA1', 'Shake-128', 'Shake-256']:
        err_msg = f'Hash Algorithm {hash_algorithm.verbose_name} not supported for certificate signatures.'
        raise ValueError(err_msg)

    if algorithm == oid.PublicKeyAlgorithmOid.RSA:
        if key_size is None:
            err_msg = 'Key size must be provided for the RSA algorithm.'
            raise ValueError(err_msg)
        if key_size < MIN_RSA_KEY_SIZE:
            err_msg = 'Key size must at least be 2048 bits.'
            raise ValueError(err_msg)

        root_ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        issuing_ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    elif algorithm == oid.PublicKeyAlgorithmOid.ECC:
        if named_curve is None:
            err_msg = 'Named curve must be provided for the ECC algorithm.'
            raise ValueError(err_msg)

        root_ca_private_key = ec.generate_private_key(curve=named_curve.curve())
        issuing_ca_private_key = ec.generate_private_key(curve=named_curve.curve())

    else:
        err_msg = 'Algorithm must be either RSA or ECC.'
        raise ValueError(err_msg)

    root_ca_cn = 'Trustpoint Demo IDevID Hierarchy - Root CA'
    issuing_ca_cn = 'Trustpoint Demo IDevID Hierarchy - Issuing CA'
    validity_days = 5 * 365

    one_day = datetime.timedelta(1, 0, 0)

    root_ca_public_key = root_ca_private_key.public_key()
    issuing_ca_public_key = issuing_ca_private_key.public_key()

    root_ca_builder = x509.CertificateBuilder()
    root_ca_builder = root_ca_builder.subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, root_ca_cn),
        x509.NameAttribute(x509.NameOID.USER_ID, hierarchy_name)
    ]))
    root_ca_builder = root_ca_builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, root_ca_cn),
        x509.NameAttribute(x509.NameOID.USER_ID, hierarchy_name)
    ]))
    root_ca_builder = root_ca_builder.not_valid_before(datetime.datetime.today() - one_day)
    root_ca_builder = root_ca_builder.not_valid_after(datetime.datetime.today() + (one_day * validity_days))
    root_ca_builder = root_ca_builder.serial_number(x509.random_serial_number())
    root_ca_builder = root_ca_builder.public_key(root_ca_public_key)
    root_ca_builder = root_ca_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=1), critical=True,
    )
    root_ca_builder = root_ca_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(root_ca_public_key), critical=False
    )
    root_ca_builder = root_ca_builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root_ca_public_key), critical=False
    )
    root_ca_certificate = root_ca_builder.sign(
        private_key=root_ca_private_key, algorithm=cast(SupportedHashAlgorithms, hash_algorithm.hash_algorithm()),
    )

    validity_days = 3 * 365

    issuing_ca_builder = x509.CertificateBuilder()
    issuing_ca_builder = issuing_ca_builder.subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, issuing_ca_cn),
        x509.NameAttribute(x509.NameOID.USER_ID, hierarchy_name)
    ]))
    issuing_ca_builder = issuing_ca_builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, root_ca_cn),
        x509.NameAttribute(x509.NameOID.USER_ID, hierarchy_name)
    ]))
    issuing_ca_builder = issuing_ca_builder.not_valid_before(datetime.datetime.today() - one_day)
    issuing_ca_builder = issuing_ca_builder.not_valid_after(datetime.datetime.today() + (one_day * validity_days))
    issuing_ca_builder = issuing_ca_builder.serial_number(x509.random_serial_number())
    issuing_ca_builder = issuing_ca_builder.public_key(issuing_ca_public_key)
    issuing_ca_builder = issuing_ca_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True,
    )
    issuing_ca_builder = issuing_ca_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(issuing_ca_public_key), critical=False
    )
    issuing_ca_builder = issuing_ca_builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root_ca_public_key), critical=False
    )

    issuing_ca_certificate = issuing_ca_builder.sign(
        private_key=root_ca_private_key, algorithm=cast(SupportedHashAlgorithms, hash_algorithm.hash_algorithm()),
    )

    root_ca_pem = root_ca_certificate.public_bytes(encoding=serialization.Encoding.PEM).decode()
    issuing_ca_pem = issuing_ca_certificate.public_bytes(encoding=serialization.Encoding.PEM).decode()
    issuing_ca_private_key_pem = issuing_ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()).decode()

    demo_devid_context = DemoIdevidContext()
    if hierarchy_name in demo_devid_context.demo_idevid_model.hierarchies:
        raise ValueError(f'Hierarchy with name {hierarchy_name} already exists.')

    signature_suite = oid.SignatureSuite.from_certificate(root_ca_certificate)

    idevid_hierarchy_model = IdevidHierarchyModel(
        signature_suite=str(signature_suite),
        root_ca_certificate=root_ca_pem,
        issuing_ca_certificate=issuing_ca_pem,
        issuing_ca_private_key=issuing_ca_private_key_pem,
        issued_idevids={},
        device_serial_number_index_mapping={}
    )

    demo_devid_context.demo_idevid_model.hierarchies[hierarchy_name] = idevid_hierarchy_model
    demo_devid_context.store_demo_idevid_model()

def delete_idevid_hierarchy(hierarchy_name: str) -> None:
    demo_devid_context = DemoIdevidContext()
    if hierarchy_name in demo_devid_context.demo_idevid_model.hierarchies:
        demo_devid_context.demo_idevid_model.hierarchies.pop(hierarchy_name)
    else:
        err_msg = f'Hierarchy with name {hierarchy_name} does not exist.'
        raise ValueError(err_msg)
    demo_devid_context.store_demo_idevid_model()

def delete_idevid(hierarchy_name: str, index: int, device_serial_number: str) -> None:
    demo_devid_context = DemoIdevidContext()
    if hierarchy_name not in demo_devid_context.demo_idevid_model.hierarchies:
        err_msg = f'Hierarchy with name {hierarchy_name} does not exist. Nothing to delete.'
        raise ValueError(err_msg)
    hierarchy = demo_devid_context.demo_idevid_model.hierarchies[hierarchy_name]
    if index not in hierarchy.issued_idevids:
        err_msg = f'No IDevID with index {index} exists for hierarchy {hierarchy_name}. Nothing to delete.'
        raise ValueError(err_msg)
    if device_serial_number not in hierarchy.device_serial_number_index_mapping:
        err_msg = (
            f'No IDevID with device serial number {device_serial_number} exists for hierarchy {hierarchy_name}. '
            f'Nothing to delete.')
        raise ValueError(err_msg)

    hierarchy.issued_idevids.pop(index)
    hierarchy.device_serial_number_index_mapping.pop(device_serial_number)
    demo_devid_context.store_demo_idevid_model()

def export_idevid(hierarchy_name: str, index: int) -> bytes:
    demo_idevid_model = DemoIdevidContext().demo_idevid_model
    hierarchy = demo_idevid_model.hierarchies[hierarchy_name]
    idevid_model = hierarchy.issued_idevids[index]
    idevid_private_key = serialization.load_pem_private_key(idevid_model.private_key.encode(), password=None)
    idevid_certificate = x509.load_pem_x509_certificate(idevid_model.certificate.encode())

    issuing_ca_certificate = x509.load_pem_x509_certificate(
        demo_idevid_model.hierarchies[hierarchy_name].issuing_ca_certificate.encode())
    root_ca_certificate = x509.load_pem_x509_certificate(
        demo_idevid_model.hierarchies[hierarchy_name].root_ca_certificate.encode())

    return pkcs12.serialize_key_and_certificates(
        None,
        key=idevid_private_key,
        cert=idevid_certificate,
        cas=[issuing_ca_certificate, root_ca_certificate],
        encryption_algorithm=serialization.NoEncryption()
    )

def export_trust_store(hierarchy_name: str) -> str:
    demo_devid_context = DemoIdevidContext()
    if hierarchy_name not in demo_devid_context.demo_idevid_model.hierarchies:
        err_msg = f'Hierarchy with name {hierarchy_name} does not exist.'
        raise ValueError(err_msg)
    return (
            demo_devid_context.demo_idevid_model.hierarchies[hierarchy_name].issuing_ca_certificate +
            demo_devid_context.demo_idevid_model.hierarchies[hierarchy_name].root_ca_certificate
    )

def create_idevid(hierarchy_name: str, device_serial_number: str) -> None:
    demo_idevid_context = DemoIdevidContext()
    if hierarchy_name not in demo_idevid_context.demo_idevid_model.hierarchies:
        err_msg = f'Hierarchy with name {hierarchy_name} does not exist.'
        raise ValueError(err_msg)

    hierarchy = demo_idevid_context.demo_idevid_model.hierarchies[hierarchy_name]
    if device_serial_number in hierarchy.device_serial_number_index_mapping:
        err_msg = f'IDevID with device serial number {device_serial_number} already exists.'
        raise ValueError(err_msg)

    issuing_ca_certificate = x509.load_pem_x509_certificate(
        demo_idevid_context.demo_idevid_model.hierarchies[hierarchy_name].issuing_ca_certificate.encode())

    issuing_ca_private_key = serialization.load_pem_private_key(
        demo_idevid_context.demo_idevid_model.hierarchies[hierarchy_name].issuing_ca_private_key.encode(),
        password=None)

    signature_suite = oid.SignatureSuite.from_certificate(issuing_ca_certificate)
    if signature_suite.algorithm_identifier.hash_algorithm is None:
        raise ValueError('Incompatible signature suite algorithm found.')
    idevid_private_key = oid.KeyPairGenerator.generate_key_pair_for_private_key(issuing_ca_private_key)

    idevid_public_key = idevid_private_key.public_key()
    issuing_ca_public_key = issuing_ca_private_key.public_key()

    device_cn = 'Trustpoint Demo IDevID'
    validity_days = 5 * 365

    one_day = datetime.timedelta(1, 0, 0)

    idevid_builder = x509.CertificateBuilder()
    idevid_builder = idevid_builder.subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, device_cn),
        x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, device_serial_number)
    ]))
    idevid_builder = idevid_builder.issuer_name(issuing_ca_certificate.subject)
    idevid_builder = idevid_builder.not_valid_before(datetime.datetime.today() - one_day)
    idevid_builder = idevid_builder.not_valid_after(datetime.datetime.today() + (one_day * validity_days))
    idevid_builder = idevid_builder.serial_number(x509.random_serial_number())
    idevid_builder = idevid_builder.public_key(idevid_public_key)
    idevid_builder = idevid_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    idevid_builder = idevid_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(idevid_public_key), critical=False
    )
    idevid_public_key = idevid_builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuing_ca_public_key), critical=False
    )
    idevid_certificate = idevid_public_key.sign(
        private_key=issuing_ca_private_key, algorithm=cast(SupportedHashAlgorithms,
        signature_suite.algorithm_identifier.hash_algorithm.hash_algorithm()))

    idevid_credential_model = IdevidCredentialModel(
        device_serial_number=device_serial_number,
        private_key=idevid_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
        certificate=idevid_certificate.public_bytes(encoding=serialization.Encoding.PEM).decode(),
    )
    demo_idevid_model = demo_idevid_context.demo_idevid_model

    if not demo_idevid_model.hierarchies[hierarchy_name].issued_idevids:
        index = 0
    else:
        index = max(demo_idevid_model.hierarchies[hierarchy_name].issued_idevids) + 1

    demo_idevid_model.hierarchies[hierarchy_name].issued_idevids[index] = idevid_credential_model
    demo_idevid_model.hierarchies[hierarchy_name].device_serial_number_index_mapping[device_serial_number] = index
    demo_idevid_context.store_demo_idevid_model()
