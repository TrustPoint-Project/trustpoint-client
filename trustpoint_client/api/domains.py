from __future__ import annotations


from trustpoint_client.api.schema import SignatureSuite, PkiProtocol
from trustpoint_devid_module.cli import DevIdModule
from trustpoint_client.api import TrustpointClientConfigModel
from trustpoint_client.api.schema import CredentialModel, InventoryModel


class TrustpointClientDomain:

    inventory: InventoryModel
    config: TrustpointClientConfigModel
    devid_module: DevIdModule
    default_domain: property
    _store_config: callable
    _store_inventory: callable

    def get_domain_info(self, domain: str) -> dict[str, dict[str, str]]:
        try:
            domain_model = self.inventory.domains[domain]
        except Exception:
            raise ValueError(f'Domain {domain} does not exist')

        if domain == self.default_domain:
            name = f'Default Domain: {domain}'
        else:
            name = f'Domain: {domain}'

        expires_in =    domain_model.ldevid_credential.not_valid_after \
                        - domain_model.ldevid_credential.not_valid_before
        return {
            name: {
                'Device': domain_model.domain_config.device,
                'Serial-Number': domain_model.domain_config.serial_number,
                'Trustpoint Host': domain_model.domain_config.trustpoint_host,
                'Trustpoint Port': str(domain_model.domain_config.trustpoint_port),
                'PKI-Protocol': domain_model.domain_config.pki_protocol.value,
                'Signature-Suite': domain_model.domain_config.signature_suite.value,
                'LDevID Subject': domain_model.ldevid_credential.subject,
                'LDevID Certificate Type': domain_model.ldevid_credential.certificate_type.value,
                'LDevID Not-Valid-Before': domain_model.ldevid_credential.not_valid_before,
                'LDevID Not-Valid-After': domain_model.ldevid_credential.not_valid_after,
                'LDevID Expires-In': expires_in
            }
        }

    def get_verbose_domain_info(self, domain: str) -> dict[str, dict[str, str]]:
        domain_info = self.get_domain_info(domain)
        domain_key = next(iter(domain_info))

        ldevid_credential = self.inventory.domains[domain].ldevid_credential
        cert_index = ldevid_credential.certificate_index
        key_index = ldevid_credential.key_index

        devid_certs = self.devid_module.inventory.devid_certificates
        devid_keys = self.devid_module.inventory.devid_keys

        domain_info[domain_key]['LDevID Certificate'] = devid_certs[cert_index].certificate.decode()
        domain_info[domain_key]['LDevID Public-Key'] = devid_keys[key_index].public_key.decode()
        domain_info[domain_key]['LDevID Certificate Chain'] = b''.join(devid_certs[cert_index].certificate_chain).decode()
        return domain_info

    def get_all_domain_info(self, verbose: bool= False) -> dict[str, dict[str, str]]:
        result = {}
        for domain in self.inventory.domains:
            if verbose:
                result = result | self.get_verbose_domain_info(domain)
            else:
                result = result | self.get_domain_info(domain)
        return result

    def delete_domain(self, domain: str) -> None:
        inventory = self.inventory
        try:
            domain_model = inventory.domains[domain]
        except Exception:
            raise ValueError(f'Domain {domain} does not exist. Nothing to delete.')

        for credential_model in domain_model.credentials.values():
            self._delete_credential(credential_model)

        self._delete_credential(domain_model.ldevid_credential)
        del inventory.domains[domain]
        self._store_inventory(inventory)

        config = self.config
        if config.default_domain == domain:
            config.default_domain = None
        self._store_config(config)

    def _delete_credential(self, credential_model: CredentialModel) -> None:
        self.devid_module.delete_ldevid_key(credential_model.key_index)


class DomainConfig:

    inventory: InventoryModel
    _store_inventory: callable

    def get_domain_trustpoint_host(self, domain: str) -> None | str:
        return self.inventory.domains[domain].domain_config.trustpoint_host

    def set_domain_trustpoint_host(self, domain: str, host: None | str) -> None:
        inventory = self.inventory
        inventory.domains[domain].domain_config.trustpoint_host = host
        self._store_inventory(inventory)

    def get_domain_trustpoint_port(self, domain: str) -> None | int:
        return self.inventory.domains[domain].domain_config.trustpoint_port

    def set_domain_trustpoint_port(self, domain: str, port: None | int) -> None:
        inventory = self.inventory
        inventory.domains[domain].domain_config.trustpoint_port = port
        self._store_inventory(inventory)

    def get_domain_signature_suite(self, domain: str) -> None | SignatureSuite:
        return self.inventory.domains[domain].domain_config.signature_suite

    def get_domain_pki_protocol(self, domain: str) -> None | PkiProtocol:
        return self.inventory.domains[domain].domain_config.pki_protocol

    def set_domain_pki_protocol(self, domain: str, pki_protocol: None | str | PkiProtocol) -> None:
        inventory = self.inventory
        if isinstance(pki_protocol, str):
            pki_protocol = PkiProtocol(pki_protocol)
        inventory.domains[domain].domain_config.pki_protocol = pki_protocol
        self._store_inventory(inventory)

    def get_domain_tls_trust_store(self, domain: str) -> None | str:
        return self.inventory.domains[domain].domain_config.tls_trust_store

    def set_domain_tls_trust_store(self, domain: str, tls_trust_store: None | str) -> None:
        inventory = self.inventory
        inventory.domains[domain].domain_config.tls_trust_store = tls_trust_store
        self._store_inventory(inventory)
