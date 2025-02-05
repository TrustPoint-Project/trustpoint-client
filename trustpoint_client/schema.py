"""Defines the pydantic models used for persistent data storage."""

from __future__ import annotations

import datetime  # noqa: TCH003
import enum
# from ipaddress import IPv4Address
#
# from cryptography.hazmat.primitives.asymmetric import ec, rsa
from trustpoint_client.oid import SignatureSuite
from pydantic import BaseModel, ConfigDict

KEY_2K = 2048
KEY_3K = 3072
KEY_4K = 4096


# class SignatureSuite(enum.Enum):
#     """Supported signature suites."""
#
#     RSA2048 = 'RSA2048SHA256'
#     RSA3072 = 'RSA3072SHA256'
#     RSA4096 = 'RSA4096SHA256'
#     SECP256R1 = 'SECP256R1SHA256'
#     SECP384R1 = 'SECP384R1SHA384'
#
#     @classmethod
#     def get_signature_suite_by_public_key(
#         cls, public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
#     ) -> SignatureSuite:
#         """Gets the matching signature suite for the given public key.
#
#         Args:
#             public_key: The public key to get the signature suite for.
#
#         Returns:
#             SignatureSuite: The matching signature suite for the given public key.
#         """
#         if isinstance(public_key, rsa.RSAPublicKey):
#             if public_key.key_size == KEY_2K:
#                 return cls.RSA2048
#             if public_key.key_size == KEY_3K:
#                 return cls.RSA3072
#             if public_key.key_size == KEY_4K:
#                 return cls.RSA4096
#             raise ValueError
#
#         if isinstance(public_key, ec.EllipticCurvePublicKey):
#             if isinstance(public_key.curve, ec.SECP256R1):
#                 return cls.SECP256R1
#             if isinstance(public_key.curve, ec.SECP384R1):
#                 return cls.SECP384R1
#             raise ValueError
#
#         raise ValueError


class CertificateType(enum.Enum):
    """Supported certificate types (templates)."""

    IDevID = 'IDevID Certificate'
    DOMAIN = 'Domain Credential Certificate'
    GENERIC = 'Generic Certificate'
    TLS_CLIENT = 'TLS Client Certificate'
    TLS_SERVER = 'TLS Server Certificate'
    MQTT_CLIENT = 'MQTT Client Certificate'
    MQTT_SERVER = 'MQTT Server Certificate'
    OPC_UA_CLIENT = 'OPC UA Client Certificate'
    OPC_UA_SERVER = 'OPC UA Server Certificate'


class DomainConfigModel(BaseModel):
    """The Domain Configuration Schema."""

    model_config = ConfigDict(strict=True, extra='forbid')

    trustpoint_addresses: list[str] = ...  # type: ignore[assignment]
    # signature_suite: SignatureSuite = ...  # type: ignore[assignment]
    tls_trust_store: list[str] = ...  # type: ignore[assignment]


class CredentialModel(BaseModel):
    """The credential model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    certificate_index: int = ...  # type: ignore[assignment]
    key_index: int = ...  # type: ignore[assignment]
    subject: str = ...  # type: ignore[assignment]
    certificate_type: CertificateType = ...  # type: ignore[assignment]
    not_valid_before: datetime.datetime = ...  # type: ignore[assignment]
    not_valid_after: datetime.datetime = ...  # type: ignore[assignment]

class DomainModel(BaseModel):
    """The domain model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    domain_config: DomainConfigModel = ...  # type: ignore[assignment]

    idevid_available: bool = ...  # type: ignore[assignment]
    domain_credential: CredentialModel = ...  # type: ignore[assignment]
    credentials: dict[str, CredentialModel] = ...  # type: ignore[assignment]
    trust_stores: dict[str, str] = ...  # type: ignore[assignment]


class InventoryModel(BaseModel):
    """The inventory model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    default_domain: None | str = ...  # type: ignore[assignment]
    device_serial_number: None | str = ...  # type: ignore[assignment]
    domains: dict[str, DomainModel] = ...  # type: ignore[assignment]
    idevids: dict[str, CredentialModel] = ...  # type: ignore[assignment]


class IdevidCredentialModel(BaseModel):
    """The IDevID Credential Model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    device_serial_number: str = ...  # type: ignore[assignment]
    private_key: str = ...  # type: ignore[assignment]
    certificate: str = ...  # type: ignore[assignment]


class IdevidHierarchyModel(BaseModel):
    """The IDevID Hierarchy Model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    signature_suite: str = ...  # type: ignore[assignment]
    root_ca_certificate: str = ...  # type: ignore[assignment]
    issuing_ca_certificate: str = ...   # type: ignore[assignment]
    issuing_ca_private_key: str = ...   # type: ignore[assignment]

    issued_idevids: dict[int, IdevidCredentialModel] = ...  # type: ignore[assignment]
    device_serial_number_index_mapping: dict[str, int] = ... # type: ignore[assignment]

class IdevidModel(BaseModel):
    """The IDevID model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    hierarchies: dict[str, IdevidHierarchyModel] = ...   # type: ignore[assignment]
