from enum import unique

from trustpoint_client.api.schema.inventory import Credential

from trustpoint_client.api.base import TrustpointClientBaseClass


class TrustpointClientCredential(TrustpointClientBaseClass):

    default_domain: property

    def _domain_exists(self, domain: str) -> bool:
        if domain not in self.inventory.domains:
            return False
        return True

    def _get_domain_header(self, domain: str, is_default_domain: bool) -> dict[str, str]:
        return {
            'Domain': domain,
            'Is Default Domain': is_default_domain,
            'Signature Suite': self.inventory.domains[domain].signature_suite.value,
            'PKI Protocol': self.inventory.domains[domain].pki_protocol.value
        }

    def _get_credential_info(self, credential: Credential, is_domain_credential: bool) -> dict[str, None | str]:

        cert = self.devid_module.inventory.devid_certificates[
            credential.active_certificate_index
        ].certificate.decode()

        public_key = self.devid_module.inventory.devid_keys[
            credential.key_index
        ].public_key.decode()

        cert_chain = ''.join(cert.decode() for cert in self.devid_module.inventory.devid_certificates[
            credential.active_certificate_index
        ].certificate_chain)

        if is_domain_credential:
            return {
                f'Domain Credential Certificate': cert,
                f'Domain Credential Public Key': public_key,
                f'Domain Credential Certificate Chain': cert_chain,
            }

        return {
            f'Credential Certificate': cert,
            f'Credential Public Key': public_key,
            f'Credential Certificate Chain': cert_chain,
        }

    def list_credential(
            self,
            domain: None | str,
            domain_credential: bool,
            unique_name: None | str) -> dict[str, dict[str, None | str | dict[str, None | str]]]:

        # ignore the unique name if the domain credential option is provided
        if domain_credential and unique_name:
            unique_name = None

        is_default_domain = False
        if domain is None:
            domain = self.config.default_domain
            is_default_domain = True

        if not self._domain_exists(domain):
            if is_default_domain:
                raise ValueError('No domain configured. No credentials to list.')
            raise ValueError(f'Given domain {domain} does not exist.')

        result = {
            'header': self._get_domain_header(domain, is_default_domain),
            'credentials': {

            }
        }

        if domain_credential:
            result['credentials'][f'Domain {domain} Credential'] = self._get_credential_info(
                credential=self.inventory.domains[domain].ldevid_credential,
                is_domain_credential=True
            )
            return result

        if unique_name:
            result['credentials'][f'Domain {domain} - {unique_name} credential'] = self._get_credential_info(
                credential=self.inventory.domains[domain].credentials[unique_name],
                is_domain_credential=False
            )
            return result

        for unique_name in self.inventory.domains[domain].credentials:
            result['credentials'][f'Domain {domain} - {unique_name} credential'] = self._get_credential_info(
                credential=self.inventory.domains[domain].credentials[unique_name],
                is_domain_credential=False
            )
        return result

    def credential_exists(self, domain: str, unique_name: str) -> bool:
        domain_model = self.inventory.domains.get(domain)
        if not domain_model:
            return False
        credential = domain_model.credentials.get(unique_name)
        if not credential:
            return False
        return True

    def delete_credential(self, domain: None | str, unique_name: str) -> bool:
        if domain is None:
            domain = self.config.default_domain

        inventory = self.inventory
        domain_model = inventory.domains[domain]
        credential_model = domain_model.credentials[unique_name]
        key_index = credential_model.key_index

        self.devid_module.delete_ldevid_key(key_index)
        del inventory.domains[domain].credentials[unique_name]
        self._store_inventory(inventory)

        return True

    def export_credential(
            self, domain: None | str,
            domain_credential: bool,
            unique_name: None | str) -> None:
        pass
