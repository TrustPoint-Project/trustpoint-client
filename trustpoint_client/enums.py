from __future__ import annotations

import enum


class CertificateFormat(enum.Enum):

    PEM = ('PEM', '.pem')
    DER = ('DER', '.der')
    PKCS7_PEM = ('PKCS7_PEM', '.pem.p7b')
    PKCS7_DER = ('PKCS7_DER', '.der.p7b')

    def __new__(cls, value, file_extension):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.file_extension = file_extension
        return obj


class CertificateCollectionFormat(enum.Enum):

    PEM = ('PEM', '.pem')
    PKCS7_PEM = ('PKCS7_PEM', '.pem.p7b')
    PKCS7_DER = ('PKCS7_DER', '.der.p7b')

    def __new__(cls, value, file_extension):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.file_extension = file_extension
        return obj


class PublicKeyFormat(enum.Enum):

    PEM = ('PEM', '.pem')
    DER = ('DER', '.der')

    def __new__(cls, value, file_extension):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.file_extension = file_extension
        return obj

class PrivateKeyFormat(enum.Enum):

    PKCS1_PEM = ('PKCS1_PEM', '.p1.pem')
    PKCS8_PEM = ('PKCS8_PEM', '.p8.pem')
    PKCS8_DER = ('PKCS8_DER', '.p8.der')
    PKCS12 = ('PKCS12', '.p12')

    def __new__(cls, value, file_extension):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.file_extension = file_extension
        return obj
