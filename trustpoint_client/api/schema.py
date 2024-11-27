from __future__ import annotations

import enum
from pydantic import BaseModel, ConfigDict
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes


class SignatureSuite(enum.Enum):

    RSA2048 = 'RSA2048SHA256'
    RSA3072 = 'RSA3072SHA256'
    RSA4096 = 'RSA4096SHA256'
    SECP256R1 = 'SECP256R1SHA256'
    SECP384R1 = 'SECP384R1SHA384'

    @classmethod
    def get_signature_suite_by_public_key(
            cls, public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> SignatureSuite:
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size == 2048:
                return cls.RSA2048
            if public_key.key_size == 3072:
                return cls.RSA3072
            if public_key.key_size == 4096:
                return cls.RSA4096
            raise ValueError

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            if isinstance(public_key.curve, ec.SECP256R1):
                return cls.SECP256R1
            if isinstance(public_key.curve, ec.SECP384R1):
                return cls.SECP384R1
            raise ValueError

        raise ValueError

    def get_hash_algorithm(self) -> hashes.SHA256 | hashes.SHA384:
        """Returns the corresponding hash algorithm.

        SHA384 if for the SECP384R1 curve, SHA256 otherwise..
        """
        if self.name == 'SECP384R1':
            return hashes.SHA384()
        return hashes.SHA256()

    @staticmethod
    def _generate_rsa_key(key_size: int) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    def get_new_private_key(self) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        """Generates and returns a new corresponding private key."""
        if self.name == 'RSA2048':
            return self._generate_rsa_key(2048)
        if self.name == 'RSA3072':
            return self._generate_rsa_key(3072)
        if self.name == 'RSA4096':
            return self._generate_rsa_key(4096)
        if self.name == 'SECP256R1':
            return ec.generate_private_key(ec.SECP256R1())
        return ec.generate_private_key(ec.SECP384R1())


class PkiProtocol(enum.Enum):

    CMP = 'CMP'
    EST = 'EST'
    SCEP = 'SCEP'
    REST = 'REST'


class CertificateType(enum.Enum):

    IDEVID = 'IDevID'
    LDEVID = 'LDevID'
    GENERIC = 'Generic'
    TLS_CLIENT = 'TLS Client Certificate'
    TLS_SERVER = 'TLS Server Certificate'
    MQTT_CLIENT = 'MQTT Client Certificate'
    MQTT_SERVER = 'MQTT Server Certificate'
    OPC_UA_CLIENT = 'OPC UA Client Certificate'
    OPC_UA_SERVER = 'OPC UA Server Certificate'

class TrustpointClientConfigModel(BaseModel):
    """The Trustpoint Client Configuration Schema."""
    model_config = ConfigDict(strict=True, extra='allow')

    default_domain: None | str = ...


class DomainConfigModel(BaseModel):
    """The Domain Configuration Schema."""
    model_config = ConfigDict(strict=True, extra='forbid')

    device: str = ...
    serial_number: str = ...
    domain: str = ...
    trustpoint_host: None | str = ...
    trustpoint_port: None | int = ...
    signature_suite: SignatureSuite = ...
    pki_protocol: PkiProtocol = ...
    tls_trust_store: str = ...


class CredentialModel(BaseModel):
    """The credential model."""
    model_config = ConfigDict(strict=True, extra='forbid')

    unique_name: str = ...
    certificate_index: int = ...
    key_index: int = ...
    subject: str = ...
    certificate_type: CertificateType = ...
    not_valid_before: datetime.datetime = ...
    not_valid_after: datetime.datetime = ...


class DomainModel(BaseModel):
    """The domain model."""
    model_config = ConfigDict(strict=True, extra='forbid')

    domain_config: DomainConfigModel = ...

    ldevid_credential: CredentialModel = ...
    credentials: dict[str, CredentialModel] = ...
    trust_stores: dict[str, list[str]] = ...


class InventoryModel(BaseModel):
    """The inventory model."""
    model_config = ConfigDict(strict=True, extra='forbid')

    domains: dict[str, DomainModel] = ...


class IdevIdHierarchyInventory(BaseModel):
    """Hierarchy for IDevIDs."""
    model_config = ConfigDict(strict=True, extra='forbid')

    idevid_hierarchies: dict[str, IdevIdHierarchy] = ...


class IdevIdHierarchy(BaseModel):
    """IDevID CA Credential."""
    model_config = ConfigDict(strict=True, extra='forbid')

    signature_suite: SignatureSuite = ...
    idevid_root_ca_certificate: str = ...
    idevid_root_ca_private_key: str = ...
    idevid_issuing_ca_certificate: str = ...
    idevid_issuing_ca_private_key: str = ...
    idevid_certificate_chain: str = ...
    idevids: set[str] = ...


class IdevIdCredential(BaseModel):
    """IDevID Credential."""
    model_config = ConfigDict(strict=True, extra='forbid')

    unique_name: str = ...
    certificate_index: int = ...
    key_index: int = ...
    serial_number: str = ...
    not_valid_before: datetime.datetime = ...
    not_valid_after: datetime.datetime = ...
    idevid_hierarchy: None | str = ...


class IdevIdInventory(BaseModel):
    """IDevID Credential Inventory."""
    model_config = ConfigDict(strict=True, extra='forbid')

    idevids: dict[str, IdevIdCredential] = ...
