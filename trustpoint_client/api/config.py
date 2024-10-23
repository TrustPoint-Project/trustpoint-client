from __future__ import annotations

import ipaddress

from trustpoint_client.api.base import TrustpointClientBaseClass

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

class TrustpointConfig(TrustpointClientBaseClass):

    def get_config_as_dict(self) -> dict[str, Any]:
        if self.config:
            return {key: value for key, value in self.config.model_dump().items()}
        return {}

    def sync_config(self) -> None:
        raise NotImplementedError

    @property
    def default_domain(self) -> None | str:
        if self.config:
            return self.config.default_domain
        return None

    @default_domain.setter
    def default_domain(self, default_domain: None | str) -> None:
        config = self.config
        config.default_domain = default_domain
        self._store_config(config)

    @default_domain.deleter
    def default_domain(self) -> None:
        config = self.config
        config.default_domain = None
        self._store_config(config)

    @property
    def trustpoint_ipv4(self) -> None | str:
        if self.config:
            return self.config.trustpoint_ipv4
        return None

    @trustpoint_ipv4.setter
    def trustpoint_ipv4(self, trustpoint_ipv4: None | ipaddress.IPv4Address) -> None:
        config = self.config
        config.trustpoint_ipv4 = trustpoint_ipv4
        self._store_config(config)

    @trustpoint_ipv4.deleter
    def trustpoint_ipv4(self) -> None:
        config = self.config
        config.trustpoint_ipv4 = None
        self._store_config(config)

    @property
    def trustpoint_port(self) -> None | int:
        if self.config:
            return self.config.trustpoint_port
        return None

    @trustpoint_port.setter
    def trustpoint_port(self, trustpoint_port: None | int) -> None:
        config = self.config
        config.trustpoint_port = trustpoint_port
        self._store_config(config)

    @trustpoint_port.deleter
    def trustpoint_port(self) -> None:
        config = self.config
        config.trustpoint_port = None
        self._store_config(config)

