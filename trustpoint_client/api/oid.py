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
