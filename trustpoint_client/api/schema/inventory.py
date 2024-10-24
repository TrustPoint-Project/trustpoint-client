"""Module that contains the pydantic models to store and load the Trustpoint Client data."""
from __future__ import annotations

import enum
from pydantic import BaseModel, ConfigDict, validator, field_validator


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


class Credential(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')

    active_certificate_index: int = ...
    key_index: int = ...
    certificate_indices:  list[int] = ...


class DomainInventory(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')

    signature_suite: SignatureSuite = ...
    pki_protocol: PkiProtocol = ...

    ldevid_trust_store: str = ...
    ldevid_credential: Credential = ...

    credentials: dict[str, Credential] = ...
    trust_stores: dict[str, list[str]] = ...


class Inventory(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')

    domains: dict[str, DomainInventory] = ...
