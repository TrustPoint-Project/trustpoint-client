"""Module that contains the pydantic schema for the config file."""
from __future__ import annotations

import enum
from pydantic import BaseModel, ConfigDict


class PkiProtocol(enum.Enum):

    CMP = 'CMP'
    EST = 'EST'
    SCEP = 'SCEP'
    REST = 'REST'


class DomainConfig(BaseModel):

    model_config = ConfigDict(strict=True, extra='allow')
    # TODO(Alex8472): Validate str (name of domain)
    default_pki_protocol: str = ...


class TrustPointConfig(BaseModel):
    """The Trustpoint Client Configuration Schema."""

    model_config = ConfigDict(strict=True, extra='allow')

    default_domain: str = ...
    domain_config: dict[str, DomainConfig] = ...
