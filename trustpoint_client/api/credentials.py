from __future__ import annotations

import abc
import ipaddress
import subprocess
import enum
import re
import secrets

from typing import TYPE_CHECKING

from trustpoint_devid_module.serializer import (
    CertificateSerializer,
    CertificateCollectionSerializer,
    PublicKeySerializer,
    PrivateKeySerializer,
    CredentialSerializer
)
from cryptography.hazmat.primitives import serialization
from trustpoint_client.enums import (
    CertificateFormat,
    CertificateCollectionFormat,
    PublicKeyFormat,
    PrivateKeyFormat
)

from pathlib import Path

from trustpoint_client.api.schema import CertificateType
from trustpoint_client.api.schema import PkiProtocol
from trustpoint_client.api.oid import NameOid, ExtendedKeyUsageOptionOid
from trustpoint_client.api.schema import CredentialModel
from cryptography import x509

if TYPE_CHECKING:
    from trustpoint_client.api.schema import InventoryModel
    from trustpoint_devid_module.service_interface import DevIdModule


class CertificateExtension(abc.ABC):

    _extension_config: str
    _openssl_config: None | str = None

    def __init__(self, extension_config: str) -> None:
        self._extension_config = extension_config
        self._parse_extension_config()

    @abc.abstractmethod
    def _parse_extension_config(self) -> None:
        pass

    @property
    def extension_config(self) -> str:
        return self._extension_config

    @property
    def openssl_config(self) -> str:
        return self._openssl_config

    @classmethod
    def _get_criticality_str(cls, critical: str) -> str:
        critical = critical.lower()
        if critical == 'c' or critical == 'critical':
            return 'critical, '
        elif critical == 'n' or critical == 'non-critical':
            return ''
        else:
            raise ValueError(f'{cls.__class__.__name__}: Failed to determine criticality of extension.')


class BasicConstraintsExtension(CertificateExtension):

    def __init__(self, extension_config: str) -> None:
        super().__init__(extension_config)

    def _parse_extension_config(self) -> None:
        critical = self._get_criticality_str(self.extension_config)

        # pathlen is not set on purpose, since it is not recommended for EE certs.
        self._openssl_config = f'basicConstraints = {critical}CA:FALSE'

class KeyUsageExtension(CertificateExtension):

    class KeyUsageOption(enum.Enum):

        DIGITAL_SIGNATURE = ('digitalsignature', 'digitalSignature')
        CONTENT_COMMITMENT = ('contentcommitment', 'contentCommitment')
        KEY_ENCIPHERMENT = ('keyencipherment', 'keyEncipherment')
        DATA_ENCIPHERMENT = ('dataencipherment', 'dataEncipherment')
        KEY_AGREEMENT = ('keyagreement', 'keyAgreement')
        KEY_CERT_SIGN = ('keycertsign', 'keyCertSign')
        CRL_SIGN = ('crlsign', 'cRLSign')
        ENCIPHER_ONLY = ('encipheronly', 'encipherOnly')
        DECIPHER_ONLY = ('decipheronly', 'decipherOnly')

        def __new__(cls, value, pretty_value):
            obj = object.__new__(cls)
            obj._value_ = value
            obj.pretty_value = pretty_value
            return obj

    def __init__(self, extension_config: str) -> None:
        super().__init__(extension_config)

    def _parse_extension_config(self) -> None:
        split_ext_config = self.extension_config.split(':')
        critical = self._get_criticality_str(split_ext_config.pop(0))

        options = ''
        if len(split_ext_config) == 1:
            try:
                int(split_ext_config[0], base=2)

                if len(split_ext_config[0]) == 9:
                    if split_ext_config[0][0] == '1':
                        options += self.KeyUsageOption.DIGITAL_SIGNATURE.pretty_value + ', '
                    if split_ext_config[0][1] == '1':
                        options += self.KeyUsageOption.CONTENT_COMMITMENT.pretty_value+ ', '
                    if split_ext_config[0][2] == '1':
                        options += self.KeyUsageOption.KEY_ENCIPHERMENT.pretty_value+ ', '
                    if split_ext_config[0][3] == '1':
                        options += self.KeyUsageOption.DATA_ENCIPHERMENT.pretty_value+ ', '
                    if split_ext_config[0][4] == '1':
                        options += self.KeyUsageOption.KEY_AGREEMENT.pretty_value+ ', '
                    if split_ext_config[0][5] == '1':
                        options += self.KeyUsageOption.KEY_CERT_SIGN.pretty_value+ ', '
                    if split_ext_config[0][6] == '1':
                        options += self.KeyUsageOption.CRL_SIGN.pretty_value+ ', '
                    if split_ext_config[0][7] == '1':
                        options += self.KeyUsageOption.ENCIPHER_ONLY.pretty_value+ ', '
                    if split_ext_config[0][8] == '1':
                        options += self.KeyUsageOption.DECIPHER_ONLY.pretty_value+ ' '

                    if split_ext_config[0][4] =='0' and split_ext_config[0][7] == '1':
                        raise RuntimeError(
                            f'{self.__class__.__name__}: Encipher only can only be set if key agreement is also set.')
                    if split_ext_config[0][4] == '0' and split_ext_config[0][8] == '1':
                        raise RuntimeError(
                            f'{self.__class__.__name__}: Decipher only can only be set if key agreement is also set.')

                if options:
                    options = options.strip()
                    if options[-1] == ',':
                        options = options[:-1]
                    self._openssl_config = ('keyUsage = ' + critical + options).strip()
                    return
                else:
                    raise ValueError(f'{self.__class__.__name__}: At least one key usage flag must be set to 1.')

            except ValueError:
                pass

        key_agreement_set = False
        for entry in split_ext_config:
            split_entry = entry.split('=')
            if len(split_entry) != 2:
                raise ValueError(f'{self.__class__.__name__}: Failed to parse --key-usage option.')
            try:

                usage_option = self.KeyUsageOption(split_entry[0].lower())
                if split_entry[1].lower() == 'true':
                    if usage_option == self.KeyUsageOption.KEY_AGREEMENT:
                        key_agreement_set = True
                    if key_agreement_set is False and usage_option == self.KeyUsageOption.ENCIPHER_ONLY:
                        raise RuntimeError(
                            f'{self.__class__.__name__}: Encipher only can only be set if key agreement is also set.')
                    if key_agreement_set is False and usage_option == self.KeyUsageOption.DECIPHER_ONLY:
                        raise RuntimeError(
                            f'{self.__class__.__name__}: Decipher only can only be set if key agreement is also set.')
                    options += usage_option.pretty_value + ', '
            except ValueError as e:
                raise ValueError(f'{self.__class__.__name__}: Failed to parse --key-usage option.')

        if options:
            options = options.strip()
            if options[-1] == ',':
                options = options[:-1]
            self._openssl_config = ('keyUsage = ' + critical + options).strip()
        else:
            raise ValueError(f'{self.__class__.__name__}: At least one key usage flag must be set to true.')


class ExtendedKeyUsageExtension(CertificateExtension):

    def __init__(self, extension_config: None | str) -> None:
        super().__init__(extension_config)

    def _parse_extension_config(self) -> None:
        split_ext_config = self.extension_config.split(':')
        critical = self._get_criticality_str(split_ext_config.pop(0))

        options = ''
        for entry in split_ext_config:
            try:
                extended_key_usage_option_oid = ExtendedKeyUsageOptionOid(entry).dotted_string
            except ValueError:
                try:
                    extended_key_usage_option_oid = x509.ObjectIdentifier(entry).dotted_string
                except ValueError:
                    raise ValueError(f'{self.__class__.__name__}: Failed to parse --extended-key-usage option.')
            options += extended_key_usage_option_oid + ', '

        if options:
            options = options.strip()
            if options[-1] == ',':
                options = options[:-1]
            self._openssl_config = ('extendedKeyUsage = ' + critical + options).strip()
        else:
            raise ValueError(f'{self.__class__.__name__}: At least one extended key usage option must be given.')


class AuthorityKeyIdentifier(CertificateExtension):

    _include_aki: bool

    def __init__(self, include_aki: bool) -> None:
        self._include_aki = include_aki
        super().__init__('')

    def _parse_extension_config(self) -> None:
        if self._include_aki is True:
            # This extension is always non-critical
            # For compatability reasons, we just force the keyid, the issuer u
            self._openssl_config = None
        else:
            self._openssl_config = f'authorityKeyIdentifier = none'


class SubjectKeyIdentifier(CertificateExtension):

    _include_ski: bool

    def __init__(self, include_ski: bool) -> None:
        self._include_ski = include_ski
        super().__init__('')

    def _parse_extension_config(self) -> None:
        if self._include_ski is True:
            # This extension is always non-critical
            self._openssl_config = None
        else:
            self._openssl_config = f'subjectKeyIdentifier = none'


class SubjectAlternativeNameExtension(CertificateExtension):

    _emails: None | list[str] = None
    _uris: None | list[str] = None
    _dnss: None | list[str] = None
    _rids: None | list[str] = None
    _ips: None | list[str] = None
    _dir_names: None | list[str] = None
    _other_names: None | list[str] = None

    def __init__(
            self,
            emails: None | list[str] = None,
            uris: None | list[str] = None,
            dnss: None | list[str]= None,
            rids: None | list[str] = None,
            ips: None | list[str] = None,
            dir_names: None | list[str] = None,
            other_names: None | list[str] = None) -> None:
        self._emails = emails
        self._uris = uris
        self._dnss = dnss
        self._rids = rids
        self._ips = ips
        self._dir_names = dir_names
        self._other_names = other_names
        super().__init__('')

    @staticmethod
    def _is_valid_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return re.match(pattern, email) is not None

    @staticmethod
    def _is_valid_uri(uri: str) -> bool:
        # TODO(AlexHx8472): Consider if we want to check if it is a valid uri or rather allow everything.
        return True

    @staticmethod
    def _is_valid_dns(dns: str) -> bool:
        # TODO(AlexHx8472): Consider if we want to check if it is a valid dns name or rather allow everything.
        return True

    @staticmethod
    def _is_valid_rid(rid: str) -> bool:
        pattern = r'^([0-2])((\.0)|(\.[1-9][0-9]*))*$'
        return re.match(pattern, rid) is not None

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        # ipaddress does take other types than str, hence, just to be sure.
        if not isinstance(ip, str):
            return False
        try:
            ipaddress.ip_address(ip)
            return True
        except ipaddress.AddressValueError:
            pass

        return False

    @staticmethod
    def _is_valid_other_name(other_name: str) -> bool:
        # TODO(AlexHx8472): This is not
        pattern = r'^([0-2])((\.0)|(\.[1-9][0-9]*))*;.+:.+$'
        return re.match(pattern, other_name) is not None

    def _parse_extension_config(self) -> None:
        options = ''
        dir_sect = ''

        if self._emails:
            for email in self._emails:
                if not self._is_valid_email(email):
                    raise ValueError(f'{self.__class__.__name__}: Invalid email address found: {email}')
                options += f'email:{email}, '

        if self._uris:
            for uri in self._uris:
                if not self._is_valid_uri(uri):
                    raise ValueError(f'{self.__class__.__name__}: Invalid URI found: {uri}')
                options += f'URI:{uri}, '

        if self._dnss:
            for dns in self._dnss:
                if not self._is_valid_dns(dns):
                    raise ValueError(f'{self.__class__.__name__}: Invalid DNS name found: {dns}')
                options += f'DNS:{dns}, '

        if self._rids:
            for rid in self._rids:
                if not self._is_valid_rid(rid):
                    raise ValueError(f'{self.__class__.__name__}: Invalid RID found: {rid}')
                options += f'RID:{rid}, '

        if self._ips:
            for ip in self._ips:
                if not self._is_valid_ip(ip):
                    raise ValueError(f'{self.__class__.__name__}: Invalid IP address found: {ip}')
                options += f'IP:{ip}, '

        if self._dir_names:
            options += 'dirName:dir_sect, '
            dir_sect = '[dir_sect]\n'
            for dir_name in self._dir_names:
                attribute_type, attribute_value = dir_name.split(':', 1)
                name_oid = NameOid.get_by_name(attribute_type)
                if name_oid is None:
                    if not self._is_valid_rid(attribute_type):
                        raise ValueError(f'{self.__class__.__name__}: Invalid OID for dir name found: {attribute_type}')
                else:
                    attribute_type = name_oid.dotted_string
                # TODO(AlexHx8472): Seems to be an OpenSSL bug. First character is dropped, hence the leading dot.
                dir_sect += f'.{attribute_type} = {attribute_value}\n'

        if self._other_names:
            for other_name in self._other_names:
                if not self._is_valid_other_name(other_name):
                    raise ValueError(f'{self.__class__.__name__}: Invalid other_name found: {other_name}')
                options += f'otherName:{other_name}, '

        if options:
            options = 'subjectAltName = ' + options.strip()
            if options[-1] == ',':
                options = options[:-1]

        options += f'\n\n{dir_sect}'
        self._openssl_config = options


class TrustpointClientCredential:

    inventory: InventoryModel
    devid_module: DevIdModule
    default_domain: str

    inventory_file_path: Path
    generate_new_key: callable
    _store_inventory: callable

    def credential_exists(self, domain: str, unique_name: str) -> bool:
        if domain not in self.inventory.domains:
            return False
        if unique_name == 'domain-credential':
            return True
        if unique_name not in self.inventory.domains[domain].credentials:
            return False
        return True

    def domain_exists(self, domain: str) -> bool:
        if domain not in self.inventory.domains:
            return False
        return True

    def _get_domain_header(self, domain: str) -> dict[str, str]:
        return {
            'Domain': domain,
            'Device': self.inventory.domains[domain].domain_config.device,
            'Serial-Number': self.inventory.domains[domain].domain_config.serial_number,
            'Is-Default-Domain': domain == self.default_domain,
            'Signature Suite': self.inventory.domains[domain].domain_config.signature_suite.value,
            'PKI Protocol': self.inventory.domains[domain].domain_config.pki_protocol.value,
            '# Credentials (excl. LDevID)': len(self.inventory.domains[domain].credentials)
        }

    @staticmethod
    def _get_credential_info(credential: CredentialModel) -> dict[str, str]:
        return {
            'Certificate Subject': credential.subject,
            'Certificate Certificate-Type': credential.certificate_type.value,
            'Certificate Not-Valid-Before': credential.not_valid_before,
            'Certificate Not-Valid-After': credential.not_valid_after,
            'Certificate Expires-in': credential.not_valid_after - credential.not_valid_before
        }

    def _get_verbose_credential_info(self, credential: CredentialModel) -> dict[str, None | str]:

        cert = self.devid_module.inventory.devid_certificates[
            credential.certificate_index
        ].certificate.decode()

        public_key = self.devid_module.inventory.devid_keys[
            credential.key_index
        ].public_key.decode()

        cert_chain = ''.join(cert.decode() for cert in self.devid_module.inventory.devid_certificates[
            credential.certificate_index
        ].certificate_chain)

        return self._get_credential_info(credential) | {
            f'Credential Certificate': cert,
            f'Credential Public-Key': public_key,
            f'Credential Certificate Chain': cert_chain,
        }

    def list_credential(
            self,
            domain: None | str,
            unique_name: None | str,
            verbose: bool) -> dict[str, dict[str, None | str | dict[str, None | str]]]:

        if domain is None and self.default_domain is None:
            raise ValueError('No default domain is configured. Nothing to list.')

        result = {
            'header': self._get_domain_header(domain),
            'credentials': {

            }
        }

        if domain is None:
            domain = self.default_domain

        if unique_name is None:

            if not verbose:
                result['credentials']['domain-credential'] = self._get_credential_info(
                    credential=self.inventory.domains[self.default_domain].ldevid_credential)

                for name, credential in self.inventory.domains[self.default_domain].credentials.items():
                    result['credentials'][name] = self._get_credential_info(credential)
                return result

            else:
                result['credentials']['domain-credential'] = self._get_verbose_credential_info(
                    credential=self.inventory.domains[self.default_domain].ldevid_credential)

                for name, credential in self.inventory.domains[self.default_domain].credentials.items():
                    result['credentials'][name] = self._get_verbose_credential_info(credential)
                return result

        if unique_name == 'domain-credential':
            credential = self.inventory.domains[domain].ldevid_credential
        else:
            credential = self.inventory.domains[domain].credentials[unique_name]

        if not verbose:
            result['credentials'][unique_name] = self._get_credential_info(
                credential=credential
            )
            return result

        result['credentials'][unique_name] = self._get_verbose_credential_info(
            credential=credential
        )
        return result

    def delete_credential(self, domain: None | str, unique_name: str) -> bool:
        if domain is None:
            domain = self.default_domain

        if unique_name == 'domain-credential':
            raise ValueError('The Domain Credential cannot be deleted unless the domain itself is removed.')

        inventory = self.inventory
        domain_model = inventory.domains[domain]
        credential_model = domain_model.credentials[unique_name]
        key_index = credential_model.key_index

        self.devid_module.delete_ldevid_key(key_index)
        del inventory.domains[domain].credentials[unique_name]
        self._store_inventory(inventory)
        return True

    def export_credential_as_pkcs12(
            self, domain: None | str, unique_name: str, password: None | bytes) -> (bytes, bytes):
        if domain is None:
            domain = self.default_domain
        if not self.credential_exists(domain, unique_name):
            raise ValueError(f'Credential {unique_name} does not exist for domain {domain}.')

        if password is None:
            password = secrets.token_urlsafe(12)
        if len(password) < 12:
            raise ValueError('Password must be at least 8 characters.')
        password = password.encode()

        credential = self.inventory.domains[domain].credentials[unique_name]

        cert = self.devid_module.inventory.devid_certificates[
            credential.certificate_index
        ].certificate

        priv_key = self.devid_module.inventory.devid_keys[
            credential.key_index
        ].private_key

        cert_chain = self.devid_module.inventory.devid_certificates[
            credential.certificate_index
        ].certificate_chain

        credential_serializer = CredentialSerializer(credential=(priv_key, cert, cert_chain))

        pkcs12_bytes = credential_serializer.as_pkcs12(password=password, friendly_name=b'')

        return pkcs12_bytes, password

    def export_certificate(self, domain: None | str, unique_name: str, cert_format: CertificateFormat) -> bytes:
        if domain is None:
            domain = self.default_domain
        if not self.credential_exists(domain, unique_name):
            raise ValueError(f'Credential {unique_name} does not exist for domain {domain}.')

        credential = self.inventory.domains[domain].credentials[unique_name]

        cert = self.devid_module.inventory.devid_certificates[
            credential.certificate_index
        ].certificate

        certificate_serializer = CertificateSerializer(cert)

        if cert_format == CertificateFormat.PEM:
            return certificate_serializer.as_pem()
        elif cert_format == CertificateFormat.DER:
            return certificate_serializer.as_pem()
        elif cert_format == CertificateFormat.PKCS7_PEM:
            return certificate_serializer.as_pkcs7_pem()
        elif cert_format == CertificateFormat.PKCS7_DER:
            return certificate_serializer.as_pkcs7_der()
        else:
            raise ValueError(f'Certificate format {cert_format.value} is not supported.')

    def export_certificate_chain(
            self,
            domain: None | str,
            unique_name: str,
            cert_chain_format: CertificateCollectionFormat) -> bytes:

        if domain is None:
            domain = self.default_domain
        if not self.credential_exists(domain, unique_name):
            raise ValueError(f'Credential {unique_name} does not exist for domain {domain}.')

        credential = self.inventory.domains[domain].credentials[unique_name]

        cert = self.devid_module.inventory.devid_certificates[
            credential.certificate_index
        ].certificate_chain

        certificate_collection_serializer = CertificateCollectionSerializer(cert)

        if cert_chain_format == CertificateCollectionFormat.PEM:
            return certificate_collection_serializer.as_pem()
        elif cert_chain_format == CertificateCollectionFormat.PKCS7_PEM:
            return certificate_collection_serializer.as_pkcs7_pem()
        elif cert_chain_format == CertificateCollectionFormat.PKCS7_DER:
            return certificate_collection_serializer.as_pkcs7_der()
        else:
            raise ValueError(f'Certificate chain format {cert_chain_format.value} is not supported.')

    def export_public_key(
            self,
            domain: None | str,
            unique_name: str,
            public_key_format: PublicKeyFormat) -> bytes:

        if domain is None:
            domain = self.default_domain
        if not self.credential_exists(domain, unique_name):
            raise ValueError(f'Credential {unique_name} does not exist for domain {domain}.')

        credential = self.inventory.domains[domain].credentials[unique_name]

        pub_key = self.devid_module.inventory.devid_keys[
            credential.key_index
        ].public_key

        public_key_serializer = PublicKeySerializer(pub_key)

        if public_key_format == PublicKeyFormat.PEM:
            return public_key_serializer.as_pem()
        elif public_key_format == PublicKeyFormat.DER:
            return public_key_serializer.as_der()
        else:
            raise ValueError(f'Public key format {public_key_format.value} is not supported.')

    def export_private_key(
            self,
            domain: None | str,
            unique_name: str,
            password: None | bytes,
            private_key_format: PrivateKeyFormat) -> (bytes, bytes):

        if domain is None:
            domain = self.default_domain
        if not self.credential_exists(domain, unique_name):
            raise ValueError(f'Credential {unique_name} does not exist for domain {domain}.')

        if password is None:
            password = secrets.token_urlsafe(12)
        if len(password) < 12:
            raise ValueError('Password must be at least 8 characters.')
        password = password.encode()

        credential = self.inventory.domains[domain].credentials[unique_name]

        priv_key = self.devid_module.inventory.devid_keys[
            credential.key_index
        ].private_key

        private_key_serializer = PrivateKeySerializer(priv_key)
        if private_key_format == PrivateKeyFormat.PKCS1_PEM:
            return private_key_serializer.as_pkcs1_pem(password=password), password
        elif private_key_format == PrivateKeyFormat.PKCS8_PEM:
            return private_key_serializer.as_pkcs8_pem(password=password), password
        elif private_key_format == PrivateKeyFormat.PKCS8_DER:
            return private_key_serializer.as_pkcs8_der(password=password), password
        elif private_key_format == PrivateKeyFormat.PKCS12:
            return private_key_serializer.as_pkcs12(password=password, friendly_name=b''), password
        else:
            raise ValueError(f'Private key format {private_key_format.value} is not supported.')

    def request_generic(
            self,
            domain: None | str,
            unique_name: str,
            subject: list[str],
            extensions: list[CertificateExtension],
            validity_days: int = 365) -> None:
        if domain is None:
            domain = self.default_domain
        if not self.domain_exists(domain):
            raise ValueError(f'Domain {domain} does not exist.')

        if unique_name in self.inventory.domains[domain].credentials:
            raise ValueError(f'Credentials with unique name {unique_name} already exists for domain {domain}.')

        pattern = re.compile(r'^[a-zA-Z]+[a-zA-Z0-9_-]+$')
        match = pattern.match(unique_name)
        if match is None:
            raise ValueError(
                'The unique name must start with a letter and '
                'must only contain letters, digits, underscores and hyphens.\n')

        if self.inventory.domains[domain].domain_config.pki_protocol == PkiProtocol.CMP:
            return self._request_generic_via_cmp(
                domain=domain,
                unique_name=unique_name,
                subject=subject,
                extensions=extensions,
                validity_days=validity_days)

    def _request_generic_via_cmp(
            self,
            domain: str,
            unique_name: str,
            subject: list[str],
            extensions: list[CertificateExtension],
            validity_days: int
            ) -> None:
        inventory = self.inventory
        inventory_domain = inventory.domains[domain]

        # TODO(AlexHx8472): Just a quick hack. This will be resolved / refactored.
        if len(subject) == 1 and subject[0] == 'trustpoint-tls-client':
            subject_cmp_str = f'/2.5.4.65=trustpoint.tls-client.{domain}.{unique_name}/2.5.4.3={unique_name}'
            cert_type = CertificateType.TLS_CLIENT
        elif len(subject) == 1 and subject[0] == 'trustpoint-tls-server':
            subject_cmp_str = f'/2.5.4.65=trustpoint.tls-server.{domain}.{unique_name}/2.5.4.3={unique_name}'
            cert_type = CertificateType.TLS_SERVER
        else:
            cert_type = CertificateType.GENERIC
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

            subject_cmp_str = f'/2.5.4.65=trustpoint.generic.{domain}.{unique_name}'
            subject_cmp_str += f'/2.5.4.5={self.inventory.domains[domain].domain_config.serial_number}'
            #TODO: Should the serial number of the device be included by default? Due to possible privacy concerns.
            subject_cmp_str += f'/2.5.4.65={self.inventory.domains[domain].domain_config.device}'
            for key, value in subject_entries.items():
                subject_cmp_str += f'/{key}={value}'

        key_index = inventory_domain.ldevid_credential.key_index
        cert_index = inventory_domain.ldevid_credential.certificate_index

        key = self.devid_module.inventory.devid_keys[key_index].private_key
        cert = self.devid_module.inventory.devid_certificates[cert_index].certificate
        cert_chain = self.devid_module.inventory.devid_certificates[cert_index].certificate_chain

        cert_chain_path = self.inventory_file_path.parent / 'trusted.pem'
        cert_chain_path.write_bytes(b''.join(cert_chain))

        key_path = self.inventory_file_path.parent / 'key.pem'
        cert_path = self.inventory_file_path.parent / 'cert.pem'

        key_path.write_bytes(key)
        cert_path.write_bytes(cert)

        new_key_path = self.inventory_file_path.parent / 'new_key.pem'
        new_cert_path = self.inventory_file_path.parent / 'new_cert.pem'
        new_cert_chain_path = self.inventory_file_path.parent / 'new_cert_chain.pem'

        if extensions:
            openssl_cmp_config_path = self.inventory_file_path.parent / 'cmp.cnf'
            content = '[cmp]\n'
            for extension in extensions:
                if extension.openssl_config:
                    content += extension.openssl_config + '\n'
            content += '\n'
            openssl_cmp_config_path.write_text(content)

            cmp_ext_cmd_option = f'-config {openssl_cmp_config_path.resolve()} -reqexts cmp '
        else:
            cmp_ext_cmd_option = '-config "" '

        new_private_key = self.generate_new_key(inventory_domain.domain_config.signature_suite)
        new_key_path.write_bytes(
            new_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        trustpoint_host = inventory_domain.domain_config.trustpoint_host
        trustpoint_port = inventory_domain.domain_config.trustpoint_port

        cmd = (
            f'openssl cmp '
            f'-cmd ir '
            f'-server https://{trustpoint_host}:{trustpoint_port} '
            f'-path /.well-known/cmp/p/{domain}/initialization/ '
            f'-newkey {new_key_path} '
            f'-key {key_path} '
            f'-cert {cert_path} '
            f'-certout {new_cert_path} '
            f'-chainout {new_cert_chain_path} '
            f'-implicit_confirm -disable_confirm '
            f'-unprotected_errors '
            f'-tls_used '
            f'-trusted {cert_chain_path} '
            f'-subject {subject_cmp_str} '
            f'-days {validity_days} '
            f'{cmp_ext_cmd_option}'
        )

        try:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as exception_:
            raise ValueError(f'CMP request failed.')

        enrolled_private_key = new_key_path.read_bytes()
        enrolled_cert = new_cert_path.read_bytes()
        enrolled_cert_chain = new_cert_chain_path.read_bytes()

        loaded_cert = x509.load_pem_x509_certificate(enrolled_cert)
        enrolled_subject = loaded_cert.subject.rfc4514_string()

        new_key_index = self.devid_module.insert_ldevid_key(enrolled_private_key)
        self.devid_module.enable_devid_key(new_key_index)

        new_cert_index = self.devid_module.insert_ldevid_certificate(enrolled_cert)
        self.devid_module.enable_devid_certificate(new_cert_index)

        self.devid_module.insert_ldevid_certificate_chain(new_cert_index, enrolled_cert_chain)

        new_credential = CredentialModel(
            unique_name=unique_name,
            certificate_index=new_cert_index,
            key_index=new_key_index,
            subject=enrolled_subject,
            certificate_type=cert_type,
            not_valid_before=loaded_cert.not_valid_before_utc,
            not_valid_after=loaded_cert.not_valid_after_utc
        )

        inventory_domain.credentials[unique_name] = new_credential
        self._store_inventory(inventory)
