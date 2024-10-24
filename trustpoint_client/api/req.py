from __future__ import annotations

import re
import subprocess
from cryptography.hazmat.primitives import serialization
from pathlib import Path
from trustpoint_client.api.schema.inventory import Credential

from trustpoint_client.api.base import TrustpointClientBaseClass
from trustpoint_client.api.oid import NameOid

class TrustpointClientReq(TrustpointClientBaseClass):

    inventory_file_path: Path
    generate_new_key: callable
    trustpoint_ipv4: str
    trustpoint_port: str
    default_domain: str

    def reg_cmp_cert(self, domain_name: str, unique_name: str, subject: list[str], extension: list[str]) -> None:
        inventory = self.inventory
        inventory_domain = inventory.domains.get(domain_name)
        if inventory_domain is None:
            raise ValueError(f'Domain {domain_name} does not exist.')

        pattern = re.compile(r'^[a-zA-Z]+[a-zA-Z0-9_-]+$')
        match = pattern.match(unique_name)
        if match is None:
            raise ValueError(
                'The unique name must start with a letter and '
                'must only contain letters, digits, underscores and hyphens.\n')

        if unique_name in inventory_domain.credentials:
            raise ValueError(
                f'Credential already exists for the unique name {unique_name} in domain {domain_name} already exists.')

        subject_entries = {}
        for entry in subject:
            attribute_type, attribute_value = entry.split(':', 1)
            name_oid = NameOid.get_by_name(attribute_type)
            if name_oid is None:
                pattern = re.compile(r'^([0-2])((\.0)|(\.[1-9][0-9]*))*$')
                match = pattern.match(attribute_type)
                if match is None:
                    raise ValueError(f'Found an invalid subject attribute type: {attribute_type}.')
                oid = attribute_type
            else:
                oid = name_oid.dotted_string
            subject_entries[oid] = attribute_value

        # The serial number is not included by default, due to possible privacy concerns
        subject_cmp_str = f'/2.5.4.65=trustpoint.generic-cert.{self.default_domain}.{unique_name}'
        for key, value in subject_entries.items():
            subject_cmp_str += f'/{key}={value}'

        key_index = inventory_domain.ldevid_credential.key_index
        cert_index = inventory_domain.ldevid_credential.active_certificate_index

        key = self.devid_module.inventory.devid_keys[key_index].private_key
        cert = self.devid_module.inventory.devid_certificates[cert_index].certificate

        key_path = self.inventory_file_path.parent / 'key.pem'
        cert_path = self.inventory_file_path.parent / 'cert.pem'

        key_path.write_bytes(key)
        cert_path.write_bytes(cert)

        new_key_path = self.inventory_file_path.parent / 'new_key.pem'
        new_cert_path = self.inventory_file_path.parent / 'new_cert.pem'
        new_cert_chain_path = self.inventory_file_path.parent / 'new_cert_chain.pem'

        new_private_key = self.generate_new_key(inventory_domain.signature_suite)
        new_key_path.write_bytes(
            new_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
        ))



        cmd = (
            f'openssl cmp '
            f'-cmd ir '
            f'-server https://{self.trustpoint_ipv4}:{self.trustpoint_port} '
            f'-path /.well-known/cmp/p/{self.default_domain}/initialization/ '
            f'-newkey {new_key_path} '
            f'-key {key_path} '
            f'-cert {cert_path} '
            f'-certout {new_cert_path} '
            f'-chainout {new_cert_chain_path} '
            f'-implicit_confirm -disable_confirm '
            f'-unprotected_errors '
            f'-tls_used '
            f'-subject {subject_cmp_str}'
        )

        # TODO(AlexHx8472): Log result
        try:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            print(result)
        except subprocess.CalledProcessError as exception_:
            raise ValueError(f'CMP request failed: {exception_}')

        enrolled_private_key = new_key_path.read_bytes()
        enrolled_cert = new_cert_path.read_bytes()
        enrolled_cert_chain = new_cert_chain_path.read_bytes()

        new_key_index = self.devid_module.insert_ldevid_key(enrolled_private_key)
        self.devid_module.enable_devid_key(new_key_index)

        new_cert_index = self.devid_module.insert_ldevid_certificate(enrolled_cert)
        self.devid_module.enable_devid_certificate(new_cert_index)

        self.devid_module.insert_ldevid_certificate_chain(new_cert_index, enrolled_cert_chain)

        new_credential = Credential(
            active_certificate_index=new_cert_index,
            key_index=new_key_index,
            certificate_indices=[]
        )

        inventory_domain.credentials[unique_name] = new_credential
        self._store_inventory(inventory)
