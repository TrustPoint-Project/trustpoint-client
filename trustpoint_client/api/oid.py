from __future__ import annotations

import enum


class NameOid(enum.Enum):

    COMMON_NAME = ('2.5.4.3', ['CN', 'commonName'])
    LOCALITY_NAME = ('2.5.4.6', ['L', 'lastName'])
    STATE_OR_PROVINCE_NAME = ('2.5.4.8', ['S', 'ST', 'stateOrProvinceName'])
    STREET_ADDRESS = ('2.5.4.9', ['streetAddress'])
    ORGANIZATION_NAME = ('2.5.4.10', ['O', 'organizationName'])
    ORGANIZATIONAL_UNIT_NAME = ('2.5.4.11', ['OU', 'organizationalUnitName'])
    SERIAL_NUMBER = ('2.5.4.5', ['serialNumber'])
    SURNAME = ('2.5.4.4', ['SN', 'surName'])
    GIVEN_NAME = ('2.5.4.42', ['GN', 'givenName'])
    TITLE = ('2.5.4.12', ['title'])
    INITIALS = ('2.5.4.43', ['initials'])
    GENERATION_QUALIFIER = ('2.5.4.44', ['generationQualifier'])
    X500_UNIQUE_IDENTIFIER = ('2.5.4.45', ['x500UniqueIdentifier'])
    DN_QUALIFIER = ('2.5.4.46', ['dnQualifier'])
    PSEUDONYM = ('2.5.4.65', ['pseudonym'])
    USER_ID = ('0.9.2342.19200300.100.1.1', ['userId'])
    DOMAIN_COMPONENT = ('0.9.2342.19200300.100.1.25', ['domainComponent'])
    EMAIL_ADDRESS = ('1.2.840.113549.1.9.1', ['emailAddress'])
    JURISDICTION_COUNTRY_NAME = ('1.3.6.1.4.1.311.60.2.1.3', ['jurisdictionCountryName'])
    JURISDICTION_LOCALITY_NAME = ('1.3.6.1.4.1.311.60.2.1.1', ['jurisdictionLocalityName'])
    JURISDICTION_STATE_OR_PROVINCE_NAME = ('1.3.6.1.4.1.311.60.2.1.2', ['jurisdictionStateOrProvinceName'])
    BUSINESS_CATEGORY = ('2.5.4.16', ['businessCategory'])
    POSTAL_CODE = ('2.5.4.17', ['postalCode'])
    UNSTRUCTURED_NAME = ('1.2.840.113549.1.9.2', ['unstructuredName'])
    UNSTRUCTURED_ADDRESS = ('1.2.840.113549.1.9.8', ['unstructuredAddress'])

    def __new__(cls, dotted_string, names):
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.names = names
        return obj

    @classmethod
    def get_by_name(cls, name: str) -> None | NameOid:
        for entry in cls:
            if name.lower() in [value.lower() for value in entry.names]:
                return entry


class CertificateExtensionOid(enum.Enum):

    SUBJECT_DIRECTORY_ATTRIBUTES = ('2.5.29.9', 'Subject Directory Attributes')
    SUBJECT_KEY_IDENTIFIER = ('2.5.29.14', 'Subject Key Identifier')
    KEY_USAGE = ('2.5.29.15', 'Key Usage')
    SUBJECT_ALTERNATIVE_NAME = ('2.5.29.17', 'Subject Alternative Name')
    ISSUER_ALTERNATIVE_NAME = ('2.5.29.18', 'Issuer Alternative Name')
    BASIC_CONSTRAINTS = ('2.5.29.19', 'Basic Constraints')
    NAME_CONSTRAINTS = ('2.5.29.30', 'Name Constraints')
    CRL_DISTRIBUTION_POINTS = ('2.5.29.31', 'Crl Distribution Points')
    CERTIFICATE_POLICIES = ('2.5.29.32', 'Certificate Policies')
    POLICY_MAPPINGS = ('2.5.29.33', 'Policy Mappings')
    AUTHORITY_KEY_IDENTIFIER = ('2.5.29.35', 'Authority Key Identifier')
    POLICY_CONSTRAINTS = ('2.5.29.36', 'Policy Constraints')
    EXTENDED_KEY_USAGE = ('2.5.29.37', 'Extended Key Usage')
    FRESHEST_CRL = ('2.5.29.46', 'Freshest CRL')
    INHIBIT_ANY_POLICY = ('2.5.29.54', 'Inhibit Any Policy')
    ISSUING_DISTRIBUTION_POINT = ('2.5.29.28', 'Issuing Distribution Point')
    AUTHORITY_INFORMATION_ACCESS = ('1.3.6.1.5.5.7.1.1', 'Authority Information Access')
    SUBJECT_INFORMATION_ACCESS = ('1.3.6.1.5.5.7.1.11', 'Subject Information Access')
    OCSP_NO_CHECK = ('1.3.6.1.5.5.7.48.1.5', 'OCSP No Check')
    TLS_FEATURE = ('1.3.6.1.5.5.7.1.24', 'TLS Feature')
    CRL_NUMBER = ('2.5.29.20', 'CRL Number')
    DELTA_CRL_INDICATOR = ('2.5.29.27', 'Delta CRL Indicator')
    PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS = ('1.3.6.1.4.1.11129.2.4.2', 'Precert Signed Certificate Timestamps')
    PRECERT_POISON = ('1.3.6.1.4.1.11129.2.4.3', 'Precert Poison')
    SIGNED_CERTIFICATE_TIMESTAMPS = ('1.3.6.1.4.1.11129.2.4.5', 'Signed Certificate Timestamps')
    MS_CERTIFICATE_TEMPLATE = ('1.3.6.1.4.1.311.21.7', 'Microsoft Certificate Template')

    @staticmethod
    def get_short_description_str() -> str:
        return 'Extension OID'

    def __new__(cls, dotted_string, verbose_name):
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        return obj

class EllipticCurveOid(enum.Enum):

    # OID, verbose_name, key_size

    NONE = ('None', '', 0)
    SECP192R1 = ('1.2.840.10045.3.1.1', 'SECP192R1', 192)
    SECP224R1 = ('1.3.132.0.33', 'SECP224R1', 224)
    SECP256K1 = ('1.3.132.0.10', 'SECP256K1', 256)
    SECP256R1 = ('1.2.840.10045.3.1.7', 'SECP256R1', 256)
    SECP384R1 = ('1.3.132.0.34', 'SECP384R1', 384)
    SECP521R1 = ('1.3.132.0.35', 'SECP521R1', 521)
    BRAINPOOLP256R1 = ('1.3.36.3.3.2.8.1.1.7', 'BRAINPOOLP256R1', 256)
    BRAINPOOLP384R1 = ('1.3.36.3.3.2.8.1.1.11', 'BRAINPOOLP384R1', 384)
    BRAINPOOLP512R1 = ('1.3.36.3.3.2.8.1.1.13', 'BRAINPOOLP512R1', 512)
    SECT163K1 = ('1.3.132.0.1', 'SECT163K1', 163)
    SECT163R2 = ('1.3.132.0.15', 'SECT163R2', 163)
    SECT233K1 = ('1.3.132.0.26', 'SECT233K1', 233)
    SECT233R1 = ('1.3.132.0.27', 'SECT233R1', 233)
    SECT283K1 = ('1.3.132.0.16', 'SECT283K1', 283)
    SECT283R1 = ('1.3.132.0.17', 'SECT283R1', 283)
    SECT409K1 = ('1.3.132.0.36', 'SECT409K1', 409)
    SECT409R1 = ('1.3.132.0.37', 'SECT409R1', 409)
    SECT571K1 = ('1.3.132.0.38', 'SECT571K1', 571)
    SECT571R1 = ('1.3.132.0.39', 'SECT571R1', 570)

    def __new__(cls, dotted_string, verbose_name, key_size):
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        obj.key_size = key_size
        return obj


class RsaPaddingScheme(enum.Enum):
    NONE = 'None'
    PKCS1v15 = 'PKCS#1 v1.5'
    PSS = 'PSS'

    def __new__(cls, verbose_name):
        obj = object.__new__(cls)
        obj._value_ = verbose_name
        obj.verbose_name = verbose_name
        return obj


class PublicKeyAlgorithmOid(enum.Enum):
    ECC = ('1.2.840.10045.2.1', 'ECC')
    RSA = ('1.2.840.113549.1.1.1', 'RSA')
    ED25519 = ('1.3.101.112', 'ED25519')
    ED448 = ('1.3.101.113', 'ED448')

    def __new__(cls, dotted_string, verbose_name):
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        return obj


class SignatureAlgorithmOid(enum.Enum):

    # OID, verbose_name, public_key_algorithm_oid, padding_scheme

    RSA_MD5 = ('1.2.840.113549.1.1.4', 'RSA with MD5', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA1 = ('1.2.840.113549.1.1.5', 'RSA with SHA1', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA1_ALT = ('1.3.14.3.2.29', 'RSA with SHA1', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA224 = ('1.3.14.3.2.29', 'RSA with SHA224', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA256 = ('1.2.840.113549.1.1.11', 'RSA with SHA256', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA384 = ('1.2.840.113549.1.1.12', 'RSA with SHA384', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA512 = ('1.2.840.113549.1.1.13', 'RSA with SHA512', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA3_224 = (
        '2.16.840.1.101.3.4.3.13', 'RSA with SHA3-224', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA3_256 = (
        '2.16.840.1.101.3.4.3.14', 'RSA with SHA3-256', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA3_384 = (
        '2.16.840.1.101.3.4.3.15', 'RSA with SHA3-384', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA3_512 = (
        '2.16.840.1.101.3.4.3.16', 'RSA with SHA3-512', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)

    RSASSA_PSS = (
        '1.2.840.113549.1.1.10', 'RSA (RSASSA-PSS), Padding: PSS', PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PSS)

    ECDSA_SHA1 = ('1.2.840.10045.4.1', 'ECDSA with SHA1', PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA224 = ('1.2.840.10045.4.3.1', 'ECDSA with SHA224', PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA256 = ('1.2.840.10045.4.3.2', 'ECDSA with SHA256', PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA384 = ('1.2.840.10045.4.3.3', 'ECDSA with SHA384', PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA512 = ('1.2.840.10045.4.3.4', 'ECDSA with SHA512', PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA3_224 = (
        '2.16.840.1.101.3.4.3.9', 'ECDSA with SHA3-224', PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA3_256 = (
        '2.16.840.1.101.3.4.3.10', 'ECDSA with SHA3-256', PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA3_384 = (
        '2.16.840.1.101.3.4.3.11', 'ECDSA with SHA3-384', PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA3_512 = (
        '2.16.840.1.101.3.4.3.12', 'ECDSA with SHA3-512', PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)

    def __new__(cls, dotted_string, verbose_name, public_key_algo_oid, padding_scheme):
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        obj.public_key_algo_oid = public_key_algo_oid
        obj.padding_scheme = padding_scheme
        return obj

class ExtendedKeyUsageOptionOid(enum.Enum):

    SERVER_AUTH = ('serverauth', 'serverAuth', '1.3.6.1.5.5.7.3.1')
    CLIENT_AUTH = ('clientauth', 'clientAuth', '1.3.6.1.5.5.7.3.2')
    CODE_SIGNING = ('codesigning', 'codeSigning', '1.3.6.1.5.5.7.3.3')
    EMAIL_PROTECTION = ('emailprotection', 'emailProtection', '1.3.6.1.5.5.7.3.4')
    TIME_STAMPING = ('timestamping', 'timeStamping', '1.3.6.1.5.5.7.3.8')
    OCSP_SIGNING = ('ocspsigning', 'ocspSigning', '1.3.6.1.5.5.7.3.9')
    ANY_EXTENDED_KEY_USAGE = ('anyextendedkeyusage', 'anyExtendedKeyUsage', '2.5.29.37.0')
    SMARTCARD_LOGON = ('smartcardlogon', 'smartcardLogon', '1.3.6.1.4.1.311.20.2.2')
    KERBEROS_PKINIT_KDC = ('kerberospkinitkdc', 'kerberosPkinitKdc', '1.3.6.1.5.2.3.5')
    IPSEC_IKE = ('ipsecike', 'ipsecIke', '1.3.6.1.5.5.7.3.17')
    CERTIFICATE_TRANSPARENCY = ('certificatetransparency', 'certificateTransparency', '1.3.6.1.4.1.11129.2.4.4')

    def __new__(cls, value: str, pretty_value: str, dotted_string: str) -> ExtendedKeyUsageOptionOid:
        obj = object.__new__(cls)
        obj._value_ = value
        obj.pretty_value = pretty_value
        obj.dotted_string = dotted_string
        return obj
