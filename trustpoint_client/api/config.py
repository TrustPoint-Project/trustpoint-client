from pathlib import Path
import ipaddress

from trustpoint_client.api import CONFIG_FILE_PATH
from trustpoint_client.api.exceptions import ConfigDataWriteError
from trustpoint_client.api.schema import TrustpointConfigModel, PkiProtocol

class TrustpointClientConfig:

    _config_path: Path
    _config: TrustpointConfigModel

    def __init__(self, config_path: Path = CONFIG_FILE_PATH) -> None:
        self._config_path = config_path
        self._config = TrustpointConfigModel()
        with CONFIG_FILE_PATH.open('r') as f:
            self._config = TrustpointConfigModel.model_validate_json(f.read())

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def config(self) -> TrustpointConfigModel:
        return self._config.model_copy()

    def _store_config(self, config: TrustpointConfigModel) -> None:
        try:
            self._config_path.write_text(config.model_dump_json())
            self._config = config
        except Exception as exception:
            raise ConfigDataWriteError from exception

    def list_config(self) -> None:
        pass

    def sync_config(self) -> None:
        pass

    @property
    def trustpoint_ipv4(self) -> ipaddress.IPv4Address:
        """Returns the configured Trustpoint IPv4 Address."""
        return self.config.trustpoint_ipv4

    @trustpoint_ipv4.setter
    def trustpoint_ipv4(self, trustpoint_ipv4: ipaddress.IPv4Address) -> None:
        """Sets the configured Trustpoint IPv4 Address."""
        new_config = self.config
        new_config.trustpoint_ipv4 = trustpoint_ipv4
        self._store_config(new_config)

    @trustpoint_ipv4.deleter
    def trustpoint_ipv4(self) -> None:
        """Deletes the configured Trustpoint IPv4 Address."""
        new_config = self.config
        new_config.trustpoint_ipv4 = None
        self._store_config(new_config)

    @property
    def trustpoint_ipv6(self) -> ipaddress.IPv6Address:
        """Returns the configured Trustpoint IPv6 Address."""
        return self.config.trustpoint_ipv6

    @trustpoint_ipv6.setter
    def trustpoint_ipv6(self, trustpoint_ipv6: ipaddress.IPv6Address) -> None:
        """Sets the configured Trustpoint IPv6 Address."""
        new_config = self.config
        new_config.trustpoint_ipv6 = trustpoint_ipv6
        self._store_config(new_config)

    @trustpoint_ipv6.deleter
    def trustpoint_ipv6(self) -> None:
        """Deletes the configured Trustpoint IPv6 Address."""
        new_config = self.config
        new_config.trustpoint_ipv6 = None
        self._store_config(new_config)

    @property
    def trustpoint_domain(self) -> str:
        """Returns the configured Trustpoint domain."""
        return self.config.trustpoint_domain

    @trustpoint_domain.setter
    def trustpoint_domain(self, trustpoint_domain: str) -> None:
        """Sets the configured Trustpoint domain."""
        new_config = self.config
        new_config.trustpoint_domain = trustpoint_domain
        self._store_config(new_config)

    @trustpoint_domain.deleter
    def trustpoint_domain(self) -> None:
        """Deletes the configured Trustpoint domain."""
        new_config = self.config
        new_config.trustpoint_domain = None
        self._store_config(new_config)

    @property
    def trustpoint_port(self) -> int:
        """Returns the configured Trustpoint port."""
        return self._config.trustpoint_port

    @trustpoint_port.setter
    def trustpoint_port(self, trustpoint_port: int) -> None:
        """Sets the configured Trustpoint port."""
        new_config = self.config
        new_config.trustpoint_port = trustpoint_port
        self._store_config(new_config)

    @trustpoint_port.deleter
    def trustpoint_port(self) -> None:
        """Deletes the configured Trustpoint port."""
        new_config = self.config
        new_config.trustpoint_port = None
        self._store_config(new_config)

    @property
    def pki_protocol(self) -> PkiProtocol:
        """Gets the configured PKI protocol."""
        return self.config.pki_protocol

    @pki_protocol.setter
    def pki_protocol(self, pki_protocol: PkiProtocol) -> None:
        """Sets the PKI protocol to use."""
        new_config = self.config
        new_config.pki_protocol = pki_protocol
        self._store_config(new_config)

    @pki_protocol.deleter
    def pki_protocol(self) -> None:
        """Sets the configured PKI protocol to None."""
        new_config = self.config
        new_config.pki_protocol = None
        self._store_config(new_config)

    @property
    def default_domain(self) -> str:
        """Gets the configured default domain."""
        return self.config.default_domain

    @default_domain.setter
    def default_domain(self, default_domain: str) -> None:
        """Sets the default domain to use."""
        new_config = self.config
        new_config.default_domain = default_domain
        if default_domain not in new_config.available_domains:
            new_config.available_domains.append(default_domain)
        self._store_config(new_config)
