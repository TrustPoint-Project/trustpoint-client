.. Trustpoint-Client documentation master file, created by
   sphinx-quickstart on Mon Jan  8 15:22:22 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. _quickstart_guide: quickstart-guide

Trustpoint-Client Documentation
===============================

The Trustpoint-Client is intended to simplify device onboarding, certificate requests and certificate management
while using the Trustpoint as a Registration Authority (RA) or a Certificate Authority (CA).

|

.. image:: _static/trustpoint_client_banner.png
   :align: center

|

Contents
--------

.. toctree::
   :maxdepth: 1

   Home<self>
   Quickstart<quickstart>

|

Introduction
------------

This section tries to give a quick summary of terms used in this documentation and the intended usage
of the Trustpoint-Client.

|

Terms
~~~~~

General concepts and terms are described in this introductory section.
To set-up and configure the Trustpoint itself, please refer to the
`Trustpoint-Documentation <https://trustpoint.readthedocs.io/en/latest/>`_.

|

Certificate
...........
A certificate refers to a X.509 certificate, which contains the corresponding public key.

|

Private Key
...........
A private key of an asymmetric key pair. A public key can usually be derived or is contained in a private key object.

|

Certificate Chain
.................
The certificate chain corresponding to a certificate, including the Root CA certificate, but excluding the
certificate itself that the certificate chain is concerned about.

|

Credential
..........
A credential is a set of a private key, corresponding certificate and certificate chain. Both the certificate and
private key implicitly include the public key.

|

Domain Credential
.................
A domain credential is the credential the Trustpoint-Client will acquire when onboarding to a domain. This
credential is then used to authenticate itself against the Trustpoint and thus allows the Trustpoint-Client to
request application certificates corresponding to that domain.

|

Issuing CA
..........
An Issuing CA is an entity on the Trustpoint that issues new certificates while forcing all certificates
in the certificate hierarchy to utilize the same Signature-Suite, that is the same signature algorithm and the same
hash function.

|

Onboarding
..........
Onboarding describes the process of acquiring a first credential , the domain credential, which allows
the device (Trustpoint-Client) to authenticate itself against the Trustpoint and thus request further application
certificates from that domain.

.. Note::

   The process of onboarding is currently called onboarding in the Trustpoint-Client context.

|

Domain
......
Domains are an abstraction on top of the Issuing CAs. Every Domain has exactly one Issuing CA assosiated to it,
while an Issuing CA can be part of multiple domains.

Certificates associated with a domain will always have the same Signature-Suite (compare Issuing-CA)

The Trustpoint-Client can onboard to one or more domains. After successful onboarding onto a domain,
the Trustpoint-Client has acquired a corresponding domain credential which allows it to request application
certificates issued by the associated Issuing CA.

.. Warning::

   The Trustpoint-Client currently only allows to onboard to a single domain. However, in the future the
   Trustpoint-Client will allow to to onboard to multiple domains and thus the device will be able to acquire
   certificates from different PKI-hierarchies.

|

Trust-Store
...........
Trust-Stores are sets of certificates that are trustworthy. The Trustpoint can be configured to offer arbitrary
Trust-Stores in any domain which can then be requested and stored within the Trustpoint-Client.

.. Warning::

   This feature is not yet implemented in neither the Trustpoint-Client and Trustpoint, but will be included in
   the first proper release of the Trustpoint-Client and Trustpoint.

|

Environment & Context
~~~~~~~~~~~~~~~~~~~~~

The Trustpoint-Client is intended to make the onboarding, application certificate requests and their management
much more comfortable, i.e. the user or admin will not require deep knowledge about
public key infrastructures to securely onboard a device into a domain and request and manage application certificates.

.. Note::

   It is not required to use the Trustpoint-Client to utilize the Trustpoint. However, without it, you will need to
   handle all the certificate requests and protocols by yourself. This includes onboarding the device manually and
   utilizing PKI protocols like EST and CMP directly to request, renew and revoke certificates for that device.

A simplified environment in which the Trustpoint and Trustpoint-Client may run in is depicted in the diagram below.
For more context and information about the Trustpoint and how to set it up, please refer to the
`Trustpoint-Documentation <https://trustpoint.readthedocs.io/en/latest/>`_.

|

.. image:: _static/trustpoint-client.drawio.svg
   :align: center
