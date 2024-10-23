from __future__ import annotations

from trustpoint_client.api.base import TrustpointClientBaseClass
from trustpoint_client.api.schema.inventory import Credential


class TrustpointClientDomain(TrustpointClientBaseClass):

    def _get_domain_info_from_domain_model(self, domain: str) -> dict[str, str]:
        try:
            raw_domain_info = self.inventory.domains[domain].model_dump()
        except Exception:
            raise ValueError(f'Domain {domain} does not exist.')

        return {
            'Domain Name': domain,
            'Is Default Domain': self.config.default_domain == domain,
            'Signature Suite': raw_domain_info['signature_suite'].value,
            'PKI Protocol': raw_domain_info['pki_protocol'].value,
        }


    def list_all_domains(self) -> dict[str, dict[str, str]]:
        domain_info = {}
        inventory = self.inventory
        for domain in inventory.domains:
            domain_info[domain] = self._get_domain_info_from_domain_model(domain)

        return domain_info


    def list_domain(self, domain: None | str = None) -> dict[str, str]:
        if domain is None:
            domain = self.config.default_domain
            if domain is None:
                raise ValueError('No default domain configured.')

        return self._get_domain_info_from_domain_model(domain)

    def _delete_credential(self, credential: Credential) -> None:
        self.devid_module.delete_ldevid_certificate(credential.active_certificate_index)
        for cert_index in credential.certificate_indices:
            self.devid_module.delete_ldevid_certificate(cert_index)
        self.devid_module.delete_ldevid_key(credential.key_index)

    def delete_domain(self, domain: str) -> None:
        inventory = self.inventory
        try:
            domain_model = inventory.domains[domain]
        except Exception:
            raise ValueError(f'Domain {domain} does not exist. Nothing to delete.')

        config = self.config
        if config.default_domain == domain:
            config.default_domain = None
        self._store_config(config)

        self._delete_credential(domain_model.ldevid_credential)
        for credential in domain_model.credentials.values():
            self._delete_credential(credential)

        del inventory.domains[domain]
        self._store_inventory(inventory)

