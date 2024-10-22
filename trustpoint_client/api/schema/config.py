"""Module that contains the pydantic schema for the config file."""
from __future__ import annotations

import enum
from pydantic import BaseModel, ConfigDict
import ipaddress


class PkiProtocol(enum.Enum):

    CMP = 'CMP'
    EST = 'EST'
    SCEP = 'SCEP'
    REST = 'REST'


class SignatureSuite(enum.Enum):

    RSA2048 = 'RSA2048SHA256'
    RSA3072 = 'RSA3072SHA256'
    RSA4096 = 'RSA4096SHA256'
    SECP256R1 = 'SECP256R1SHA256'
    SECP384R1 = 'SECP384R1SHA384'


class TrustpointConfigModel(BaseModel):
    """The Trustpoint Client Configuration Schema."""

    model_config = ConfigDict(strict=True, extra='allow')

    trustpoint_ipv4: None | ipaddress.IPv4Address = ...
    trustpoint_port: None | int = ...

    default_domain: None | str = ...
    default_pki_protocol: None | PkiProtocol = ...

    default_signature_suite: None | SignatureSuite = ...
