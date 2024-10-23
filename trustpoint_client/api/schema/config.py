"""Module that contains the pydantic schema for the config file."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict
import ipaddress


class TrustpointConfigModel(BaseModel):
    """The Trustpoint Client Configuration Schema."""

    model_config = ConfigDict(strict=True, extra='allow')

    trustpoint_ipv4: None | ipaddress.IPv4Address = ...
    trustpoint_port: None | int = ...

    default_domain: None | str = ...

