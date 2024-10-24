from __future__ import annotations

from trustpoint_client.api.base import TrustpointClientBaseClass


class TrustpointClientProvision(TrustpointClientBaseClass):

    def _reg_cmp_cert(subject: list[str], extension: list[str]) -> None:

        inventory_domain = trustpoint_client.inventory.domains[trustpoint_client.default_domain]
        key_index = inventory_domain.ldevid_credential.key_index
        cert_index = inventory_domain.ldevid_credential.active_certificate_index

        key = trustpoint_client.devid_module.inventory.devid_keys[key_index].private_key
        cert = trustpoint_client.devid_module.inventory.devid_certificates[cert_index].certificate

        key_path = trustpoint_client.inventory_file_path.parent / 'key.pem'
        cert_path = trustpoint_client.inventory_file_path.parent / 'cert.pem'

        key_path.write_bytes(key)
        cert_path.write_bytes(cert)

        new_key_path = trustpoint_client.inventory_file_path.parent / 'new_key_path.pem'
        new_cert_path = trustpoint_client.inventory_file_path.parent / 'new_cert_path.pem'

        new_private_key = trustpoint_client.generate_new_key(inventory_domain.signature_suite)
        new_key_path.write_bytes(
            new_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
        ))

        cmd = (
            f'openssl cmp '
            f'-cmd ir '
            f'-server {trustpoint_client.trustpoint_ipv4}:{trustpoint_client.trustpoint_port} '
            f'-path /.well-known/cmp/p/{trustpoint_client.default_domain}/initialization/ '
            f'-newkey {new_key_path} '
            f'-key {key_path} '
            f'-cert {cert_path} '
            f'-certout {new_cert_path} '
            f'-implicit_confirm -disable_confirm '
            f'-unprotected_errors'
        )

        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        print(result)