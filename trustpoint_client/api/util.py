"""Utility methods and demo features."""
from __future__ import annotations


import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
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
from trustpoint_client.schema import IdevidHierarchyModel, IdevidCredentialModel

MIN_RSA_KEY_SIZE = 2048


def create_idevid_hierarchy(
        name: str,
        algorithm: oid.PublicKeyAlgorithmOid,
        hash_algorithm: oid.HashAlgorithm,
        named_curve: None | oid.NamedCurve = None,
        key_size: None | int = None,
) -> None:
    if not name.isidentifier():
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
        x509.NameAttribute(x509.NameOID.USER_ID, name)
    ]))
    root_ca_builder = root_ca_builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, root_ca_cn),
        x509.NameAttribute(x509.NameOID.USER_ID, name)
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

    issuing_ca_builder = x509.CertificateBuilder()
    issuing_ca_builder = issuing_ca_builder.subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, issuing_ca_cn),
        x509.NameAttribute(x509.NameOID.USER_ID, name)
    ]))
    issuing_ca_builder = issuing_ca_builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, root_ca_cn),
        x509.NameAttribute(x509.NameOID.USER_ID, name)
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

    demo_devid_context = DemoIdevidContext()
    if name in demo_devid_context.demo_idevid_model.hierarchies:
        raise ValueError(f'Hierarchy with name {name} already exists.')

    idevid_hierarchy_model = IdevidHierarchyModel(
        root_ca_certificate=root_ca_pem,
        issuing_ca_certificate=issuing_ca_pem,
        issued_idevids={}
    )

    demo_devid_context.demo_idevid_model.hierarchies[name] = idevid_hierarchy_model
    demo_devid_context.store_demo_idevid_model()


def delete_idevid_hierarchy(name: str) -> None:
    demo_devid_context = DemoIdevidContext()
    if name in demo_devid_context.demo_idevid_model.hierarchies:
        demo_devid_context.demo_idevid_model.hierarchies.pop(name)
    else:
        raise ValueError(f'Hierarchy with name {name} does not exist.')
    # TODO(AlexHx8472): Delete IDevIDs.
    demo_devid_context.store_demo_idevid_model()
