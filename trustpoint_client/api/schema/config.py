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

    RSA2048 = 'RSA2048'
    RSA3072 = 'RSA3072'
    RSA4096 = 'RSA4096'
    SECP256R1 = 'SECP256R1'
    SECP384R1 = 'SECP384R1'


class TrustpointConfigModel(BaseModel):
    """The Trustpoint Client Configuration Schema."""

    model_config = ConfigDict(strict=True, extra='allow')

    device_id: None | int = ...

    trustpoint_ipv4: None | ipaddress.IPv4Address = ...
    # trustpoint_ipv6: None | ipaddress.IPv6Address = ...
    # trustpoint_domain: None | str = ...
    trustpoint_port: None | int = ...

    default_domain: None | str = ...
    pki_protocol: None | PkiProtocol = ...
