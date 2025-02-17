"""Defines the pydantic models used for persistent data storage."""

from __future__ import annotations

import datetime
import enum
from pydantic import BaseModel, ConfigDict, Field

KEY_2K = 2048
KEY_3K = 3072
KEY_4K = 4096


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

    trustpoint_addresses: list[str] = Field()
    signature_suite: None | str = Field()
    tls_trust_store: list[str] = Field()


class CredentialModel(BaseModel):
    """The credential model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    certificate_index: int = Field()
    key_index: int = Field()
    subject: str = Field()
    certificate_type: CertificateType = Field()
    not_valid_before: datetime.datetime = Field()
    not_valid_after: datetime.datetime = Field()

class DomainModel(BaseModel):
    """The domain model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    domain_config: DomainConfigModel = Field()

    idevid_available: bool = Field()
    domain_credential: CredentialModel = Field()
    credentials: dict[str, CredentialModel] = Field()
    trust_stores: dict[str, str] = Field()


class InventoryModel(BaseModel):
    """The inventory model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    default_domain: None | str = Field()
    device_serial_number: None | str = Field()
    domains: dict[str, DomainModel] = Field()
    idevids: dict[str, CredentialModel] = Field()


class IdevidCredentialModel(BaseModel):
    """The IDevID Credential Model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    device_serial_number: str = Field()
    private_key: str = Field()
    certificate: str = Field()


class IdevidHierarchyModel(BaseModel):
    """The IDevID Hierarchy Model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    signature_suite: str = Field()
    root_ca_certificate: str = Field()
    issuing_ca_certificate: str = Field()
    issuing_ca_private_key: str = Field()

    issued_idevids: dict[int, IdevidCredentialModel] = Field()
    device_serial_number_index_mapping: dict[str, int] = Field()

class IdevidModel(BaseModel):
    """The IDevID model."""

    model_config = ConfigDict(strict=True, extra='forbid')

    hierarchies: dict[str, IdevidHierarchyModel] = Field()
