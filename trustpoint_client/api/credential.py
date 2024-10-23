from trustpoint_client.api.base import TrustpointClientBaseClass


class TrustpointClientCredential(TrustpointClientBaseClass):

    def get_domain_credential_as_dict(self, domain: None | str) -> dict[str, str]:
        if domain is None:
            domain = self.config.default_domain
            if domain is None:
                raise ValueError('No default domain configured.')

        result = {}
        domain_model = self.inventory.domains[domain]
        result['signature_suite'] = domain_model.signature_suite
        pki_protocol = domain_model.pki_protocol
        domain_credential = self.inventory.domains[domain].ldevid_credential
        domain_trust_store = self.inventory.domains[domain].trust_store



