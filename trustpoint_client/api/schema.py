from __future__ import annotations

import enum
from pydantic import BaseModel, ConfigDict
import datetime


class SignatureSuite(enum.Enum):

    RSA2048 = 'RSA2048SHA256'
    RSA3072 = 'RSA3072SHA256'
    RSA4096 = 'RSA4096SHA256'
    SECP256R1 = 'SECP256R1SHA256'
    SECP384R1 = 'SECP384R1SHA384'


class PkiProtocol(enum.Enum):

    CMP = 'CMP'
    EST = 'EST'
    SCEP = 'SCEP'
    REST = 'REST'


class CertificateType(enum.Enum):

    LDEVID = 'LDevID'
    GENERIC = 'Generic'
    TLS_CLIENT = 'TLS Client Certificate'
    TLS_SERVER = 'TLS Server Certificate'
    MQTT_CLIENT = 'MQTT Client Certificate'
    MQTT_SERVER = 'MQTT Server Certificate'
    OPC_UA_CLIENT = 'OPC UA Client Certificate'
    OPC_UA_SERVER = 'OPC UA Server Certificate'

class TrustpointClientConfigModel(BaseModel):
    """The Trustpoint Client Configuration Schema."""
    model_config = ConfigDict(strict=True, extra='allow')

    default_domain: None | str = ...


class DomainConfigModel(BaseModel):
    """The Domain Configuration Schema."""
    model_config = ConfigDict(strict=True, extra='forbid')

    device: str = ...
    serial_number: str = ...
    domain: str = ...
    trustpoint_host: None | str = ...
    trustpoint_port: None | int = ...
    signature_suite: SignatureSuite = ...
    pki_protocol: PkiProtocol = ...
    tls_trust_store: str = ...


class CredentialModel(BaseModel):
    """The credential model."""
    model_config = ConfigDict(strict=True, extra='forbid')

    unique_name: str = ...
    certificate_index: int = ...
    key_index: int = ...
    subject: str = ...
    certificate_type: CertificateType = ...
    not_valid_before: datetime.datetime = ...
    not_valid_after: datetime.datetime = ...


class DomainModel(BaseModel):
    """The domain model."""
    model_config = ConfigDict(strict=True, extra='forbid')

    domain_config: DomainConfigModel = ...

    ldevid_credential: CredentialModel = ...
    credentials: dict[str, CredentialModel] = ...
    trust_stores: dict[str, list[str]] = ...


class InventoryModel(BaseModel):
    """The inventory model."""
    model_config = ConfigDict(strict=True, extra='forbid')

    domains: dict[str, DomainModel] = ...