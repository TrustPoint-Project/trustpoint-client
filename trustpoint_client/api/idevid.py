from __future__ import annotations

import secrets
import uuid
import datetime
import pydantic
from typing import TYPE_CHECKING

from cryptography import x509
from pathlib import Path

from trustpoint_client.api.exceptions import InventoryDataWriteError, TrustpointClientCorruptedError
from trustpoint_devid_module.serializer import CredentialSerializer, PrivateKeySerializer
from trustpoint_client.api.schema import (
    SignatureSuite,
    IdevIdHierarchyInventory,
    IdevIdHierarchy,
    IdevIdCredential,
    IdevIdInventory)
from trustpoint_client.api.decorator import handle_unexpected_errors


if TYPE_CHECKING:
    from trustpoint_devid_module.cli import DevIdModule


# TODO(AlexHx8472): The are several inconsistencies in this module that should be rectified.


class TrustpointClientIdevIdMixin:

    inventory_file_path: Path
    devid_module: DevIdModule


    _idevid_inventory_file_path: Path
    _idevid_inventory: IdevIdInventory

    _idevid_hierarchy_inventory_file_path: Path
    _idevid_hierarchy_inventory: IdevIdHierarchyInventory


    def __init__(self, *args, **kwargs) -> None:
        self._idevid_inventory_file_path = self.inventory_file_path.parent / Path('idevid_inventory.json')
        self._idevid_hierarchy_inventory_file_path = self.inventory_file_path.parent / Path(
            'idevid_hierarchy_inventory.json')

        if not self._idevid_hierarchy_inventory_file_path.exists():
            idevid_hierarchy_inventory = IdevIdHierarchyInventory(
                idevid_hierarchies={}
            )
            try:
                self._idevid_hierarchy_inventory_file_path.write_text(idevid_hierarchy_inventory.model_dump_json())
            except Exception as exception:
                raise InventoryDataWriteError from exception

        if not self._idevid_inventory_file_path.exists():
            idevid_inventory = IdevIdInventory(
                idevids={}
            )
            try:
                self._idevid_inventory_file_path.write_text(idevid_inventory.model_dump_json())
            except Exception as exception:
                raise InventoryDataWriteError from exception

        try:
            with self.idevid_hierarchy_inventory_file_path.open('r') as f:
                self._idevid_hierarchy_inventory = IdevIdHierarchyInventory.model_validate_json(f.read())
        except pydantic.ValidationError as exception:
            raise TrustpointClientCorruptedError from exception

        try:
            with self.idevid_inventory_file_path.open('r') as f:
                self._idevid_inventory = IdevIdInventory.model_validate_json(f.read())
        except pydantic.ValidationError as exception:
            raise TrustpointClientCorruptedError from exception

    @property
    def idevid_inventory_file_path(self) -> Path:
        return self._idevid_inventory_file_path

    @property
    def idevid_inventory(self) -> IdevIdHierarchyInventory:
        return self._idevid_inventory.model_copy()

    @property
    def idevid_hierarchy_inventory_file_path(self) -> Path:
        return self._idevid_hierarchy_inventory_file_path

    @property
    def idevid_hierarchy_inventory(self) -> IdevIdHierarchyInventory:
        return self._idevid_hierarchy_inventory.model_copy()

    @handle_unexpected_errors(message='Failed to store the IDevID Inventory.')
    def _store_idevid_inventory(self, idevid_inventory: IdevIdInventory) -> None:
        try:
            self._idevid_inventory_file_path.write_text(idevid_inventory.model_dump_json())
            self._idevid_inventory = idevid_inventory
        except Exception as exception:
            raise InventoryDataWriteError from exception

    @handle_unexpected_errors(message='Failed to store the IDevID Hierarchy Inventory.')
    def _store_idevid_hierarchy_inventory(self, idevid_hierarchy_inventory: IdevIdHierarchyInventory) -> None:
        try:
            self._idevid_hierarchy_inventory_file_path.write_text(idevid_hierarchy_inventory.model_dump_json())
            self._idevid_hierarchy_inventory = idevid_hierarchy_inventory
        except Exception as exception:
            raise InventoryDataWriteError from exception

    @staticmethod
    def _generate_idevid_root_ca_credential(signature_suite: SignatureSuite) -> CredentialSerializer:
        root_ca_private_key = signature_suite.get_new_private_key()
        root_ca_public_key = root_ca_private_key.public_key()

        name = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Manufacturer IDevID Root CA')]
        )

        root_ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(root_ca_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30 * 365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(root_ca_public_key), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_ca_public_key), critical=False
            )
            .sign(root_ca_private_key, signature_suite.get_hash_algorithm())
        )

        return CredentialSerializer(
            (root_ca_private_key, root_ca_certificate, None)
        )

    @staticmethod
    def _generate_idevid_issuing_ca_credential(
            signature_suite: SignatureSuite,
            root_ca_credential: CredentialSerializer
    ) -> CredentialSerializer:
        issuing_ca_private_key = signature_suite.get_new_private_key()
        issuing_ca_public_key = issuing_ca_private_key.public_key()

        root_ca_cn = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Manufacturer IDevID Root CA')]
        )
        issuing_ca_cn = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Manufacturer IDevID Issuing CA')]
        )

        issuing_ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(issuing_ca_cn)
            .issuer_name(root_ca_cn)
            .public_key(issuing_ca_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30 * 365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(issuing_ca_public_key), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    root_ca_credential.credential_private_key.as_crypto().public_key()),
                critical=False
            )
            .sign(root_ca_credential.credential_private_key.as_crypto(), signature_suite.get_hash_algorithm())
        )

        return CredentialSerializer(
            (issuing_ca_private_key, issuing_ca_certificate, [root_ca_credential.credential_certificate])
        )

    @staticmethod
    def _generate_idevid_credential(
            serial_number: str,
            issuing_ca_credential: CredentialSerializer
    ) -> CredentialSerializer:
        signature_suite = SignatureSuite.get_signature_suite_by_public_key(
            issuing_ca_credential.credential_private_key.public_key_serializer.as_crypto())

        idevid_private_key = signature_suite.get_new_private_key()
        idevid_public_key = idevid_private_key.public_key()

        issuing_ca_cn = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Manufacturer IDevID Issuing CA')]
        )
        idevid_subject = x509.Name(
            [x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, serial_number)]
        )

        idevid_certificate = (
            x509.CertificateBuilder()
            .subject_name(issuing_ca_cn)
            .issuer_name(idevid_subject)
            .public_key(idevid_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30 * 365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(issuing_ca_credential.credential_private_key.as_crypto(), signature_suite.get_hash_algorithm())
        )

        return CredentialSerializer(
            (
                idevid_private_key,
                idevid_certificate,
                [
                    issuing_ca_credential.credential_certificate,
                    issuing_ca_credential.additional_certificates.as_certificate_serializer_list()[0]
                ]
            )
        )

    # ----------------------------------------------------- IDevID -----------------------------------------------------

    def generate_idevid(
            self,
            unique_name: str,
            serial_number: None | str,
            idevid_hierarchy_unique_name: str) -> None:
        if unique_name in self.idevid_inventory.idevids:
            raise ValueError(f'IDevID with unique name {unique_name} already exists.')

        idevid_hierarchy_inventory = self.idevid_hierarchy_inventory

        idevid_hierarchy = idevid_hierarchy_inventory.idevid_hierarchies.get(idevid_hierarchy_unique_name)
        if idevid_hierarchy is None:
            raise ValueError(f'No IDevID Hierarchy found with unique name {idevid_hierarchy_unique_name}.')

        issuing_ca_credential = CredentialSerializer(
            (
                idevid_hierarchy.idevid_issuing_ca_private_key,
                idevid_hierarchy.idevid_issuing_ca_certificate,
                [idevid_hierarchy.idevid_root_ca_certificate]
            )
        )
        idevid = self._generate_idevid_credential(
            serial_number=serial_number,
            issuing_ca_credential=issuing_ca_credential
        )

        key_index = self.devid_module.insert_idevid_key(idevid.credential_private_key)
        self.devid_module.enable_devid_key(key_index)
        certificate_index = self.devid_module.insert_idevid_certificate(idevid.credential_certificate)
        self.devid_module.enable_devid_certificate(certificate_index)
        self.devid_module.insert_idevid_certificate_chain(certificate_index, idevid.additional_certificates)

        idevid_credential = IdevIdCredential(
            unique_name=unique_name,
            certificate_index=certificate_index,
            key_index=key_index,
            serial_number=serial_number,
            not_valid_before=idevid.credential_certificate.as_crypto().not_valid_before_utc,
            not_valid_after=idevid.credential_certificate.as_crypto().not_valid_after_utc,
            idevid_hierarchy=idevid_hierarchy_unique_name
        )

        idevid_inventory = self.idevid_inventory
        idevid_inventory.idevids[unique_name] = idevid_credential
        self._store_idevid_inventory(idevid_inventory)

        idevid_hierarchy.idevids.add(unique_name)
        self._store_idevid_hierarchy_inventory(idevid_hierarchy_inventory)

    def list_idevids(self) -> list[(str, str, str, str, str)]:
        return [
            (unique_name, idevid.serial_number, str(idevid.not_valid_before), str(idevid.not_valid_after), str(idevid.idevid_hierarchy))
            for unique_name, idevid
            in self.idevid_inventory.idevids.items()
        ]

    def delete_idevid(self, unique_name: str) -> None:
        if unique_name not in self.idevid_inventory.idevids:
            raise ValueError(f'DevID with {unique_name} does not exist.')

        idevid_inventory = self.idevid_inventory
        idevid_hierarchy_unique_name = idevid_inventory.idevids[unique_name].idevid_hierarchy
        if idevid_hierarchy_unique_name is not None:
            idevid_hierarchy_inventory = self.idevid_hierarchy_inventory
            idevid_hierarchy_inventory.idevid_hierarchies[idevid_hierarchy_unique_name].idevids.remove(unique_name)
            self._store_idevid_hierarchy_inventory(idevid_hierarchy_inventory)

        self.devid_module.delete_idevid_key(idevid_inventory.idevids[unique_name].key_index)
        idevid_inventory.idevids.pop(unique_name)
        self._store_idevid_inventory(idevid_inventory)

    def export_idevid_certificate_as_pem(self, unique_name: str) -> str:
        if unique_name not in self.idevid_inventory.idevids:
            raise ValueError(f'DevID with {unique_name} does not exist.')

        certificate_index = self.idevid_inventory.idevids[unique_name].certificate_index
        certificate = self.devid_module.inventory.devid_certificates[certificate_index].certificate.decode()

        return certificate

    def export_idevid_certificate_chain_as_pem(self, unique_name: str) -> list[str]:
        if unique_name not in self.idevid_inventory.idevids:
            raise ValueError(f'DevID with {unique_name} does not exist.')

        certificate_index = self.idevid_inventory.idevids[unique_name].certificate_index
        certificate_chain = self.devid_module.inventory.devid_certificates[certificate_index].certificate_chain

        return [certificate.decode() for certificate in certificate_chain]

    def export_idevid_public_key_as_pem(self, unique_name: str) -> str:
        if unique_name not in self.idevid_inventory.idevids:
            raise ValueError(f'DevID with {unique_name} does not exist.')

        key_index = self.idevid_inventory.idevids[unique_name].key_index
        public_key = self.devid_module.inventory.devid_keys[key_index].public_key.decode()

        return public_key

    def export_idevid_private_key_as_pkcs8_pem(self, unique_name: str, password: None | str) -> str:
        if unique_name not in self.idevid_inventory.idevids:
            raise ValueError(f'DevID with {unique_name} does not exist.')

        key_index = self.idevid_inventory.idevids[unique_name].key_index
        private_key = self.devid_module.inventory.devid_keys[key_index].private_key

        private_key_serializer = PrivateKeySerializer(private_key)

        return private_key_serializer.as_pkcs8_pem(password=password).decode()

    def export_idevid_credential_as_pkcs12(self, unique_name: str, password: None | str) -> bytes:
        if unique_name not in self.idevid_inventory.idevids:
            raise ValueError(f'DevID with {unique_name} does not exist.')

        certificate = self.export_idevid_certificate_as_pem(unique_name)
        certificate_chain = self.export_idevid_certificate_chain_as_pem(unique_name)
        private_key = self.export_idevid_private_key_as_pkcs8_pem(unique_name, None)

        credential = CredentialSerializer(
            (
                private_key,
                certificate,
                certificate_chain
            )
        )

        return credential.as_pkcs12(password=password)

    # ------------------------------------------------ IDevID Hierarchy ------------------------------------------------

    def generate_idevid_hierarchy(
            self,
            unique_name: str,
            signature_suite: SignatureSuite) -> None:

        if not unique_name:
            raise ValueError('A unique name is required.')

        if unique_name in self.idevid_hierarchy_inventory.idevid_hierarchies:
            raise ValueError(f'Hierarchy with the unique_name {unique_name} already exists.')

        root_ca_credential = self._generate_idevid_root_ca_credential(signature_suite)
        issuing_ca_credential = self._generate_idevid_issuing_ca_credential(
            signature_suite=signature_suite,
            root_ca_credential=root_ca_credential)

        idevid_root_ca_certificate = root_ca_credential.credential_certificate.as_pem().decode()
        idevid_root_ca_private_key = root_ca_credential.credential_private_key.as_pkcs8_pem().decode()
        idevid_issuing_ca_certificate = issuing_ca_credential.credential_certificate.as_pem().decode()
        idevid_issuing_ca_private_key = issuing_ca_credential.credential_private_key.as_pkcs8_pem().decode()

        idevid_hierarchy = IdevIdHierarchy(
            signature_suite=signature_suite,
            idevid_root_ca_certificate=idevid_root_ca_certificate,
            idevid_root_ca_private_key=idevid_root_ca_private_key,
            idevid_issuing_ca_certificate=idevid_issuing_ca_certificate,
            idevid_issuing_ca_private_key=idevid_issuing_ca_private_key,
            idevid_certificate_chain=''.join([idevid_issuing_ca_certificate, idevid_root_ca_certificate]),
            idevids=set()
        )

        idevid_hierarchy_inventory = self.idevid_hierarchy_inventory
        idevid_hierarchy_inventory.idevid_hierarchies[unique_name] = idevid_hierarchy
        self._store_idevid_hierarchy_inventory(idevid_hierarchy_inventory)

    def list_idevid_hierarchies(self) -> list[(str, str)]:
        return [
            (unique_name, hierarchy.signature_suite.value)
            for unique_name, hierarchy
            in self.idevid_hierarchy_inventory.idevid_hierarchies.items()
        ]

    def export_idevid_hierarchy_root_ca_as_pkcs12(self, unique_name: str, password: None | bytes) -> (bytes, bytes):
        if unique_name not in self.idevid_hierarchy_inventory.idevid_hierarchies:
            raise ValueError(f'IDevID hierarchy with unique name {unique_name} does not exist.')

        if password is None:
            password = secrets.token_urlsafe(12)
        if len(password) < 12:
            raise ValueError('Password must be at least 12 characters.')
        password = password.encode()

        root_ca_credential = CredentialSerializer(
            (
                self.idevid_hierarchy_inventory.idevid_hierarchies[unique_name].idevid_root_ca_private_key,
                self.idevid_hierarchy_inventory.idevid_hierarchies[unique_name].idevid_root_ca_certificate,
                []
             ),
        )
        print('this works still')
        return root_ca_credential.as_pkcs12(password=password), password

    def export_idevid_hierarchy_issuing_ca_as_pkcs12(self, unique_name: str, password: None | bytes) -> (bytes, bytes):
        if unique_name not in self.idevid_hierarchy_inventory.idevid_hierarchies:
            raise ValueError(f'IDevID hierarchy with unique name {unique_name} does not exist.')

        if password is None:
            password = secrets.token_urlsafe(12)
        if len(password) < 12:
            raise ValueError('Password must be at least 12 characters.')
        password = password.encode()

        issuing_ca_credential = CredentialSerializer(
            (
                self.idevid_hierarchy_inventory.idevid_hierarchies[unique_name].idevid_issuing_ca_private_key,
                self.idevid_hierarchy_inventory.idevid_hierarchies[unique_name].idevid_issuing_ca_certificate,
                [self.idevid_hierarchy_inventory.idevid_hierarchies[unique_name].idevid_root_ca_certificate]
            )
        )

        return issuing_ca_credential.as_pkcs12(password=password), password

    def export_idevid_hierarchy_trust_store_as_pem(self, unique_name: str) -> str:
        if unique_name not in self.idevid_hierarchy_inventory.idevid_hierarchies:
            raise ValueError(f'IDevID hierarchy with unique name {unique_name} does not exist.')

        return self.idevid_hierarchy_inventory.idevid_hierarchies[unique_name].idevid_certificate_chain
