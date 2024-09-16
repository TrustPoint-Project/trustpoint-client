"""Module that contains the pydantic models to store and load the Trustpoint Client data."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Certificate(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')

    certificate_index: int = ...
    revoked: bool = ...


class Credential(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')

    active_certificate_index: int = ...
    key_index: int = ...
    certificate_indices:  list[int] = ...


class DomainInventory(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')

    ldevid_trust_store: str = ...
    ldevid_credential: Credential = ...

    credentials: dict[str, Credential] = ...
    trust_stores: dict[str, list[str]] = ...


class Inventory(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')

    domains: dict[str, DomainInventory] = ...
