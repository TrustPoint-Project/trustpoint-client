.. Trustpoint-Client documentation master file, created by
   sphinx-quickstart on Mon Jan  8 15:22:22 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Trustpoint-Client's documentation!
=============================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

|
|

List Commands
-------------

.. code-block:: text

   trustpoint-client list keys

| Lists all available LDevID keys
| Option: -d / --domain

.. code-block:: text

   trustpoint-client list certs

| Lists all available LDevID certificates
| Option: -d / --domain

.. code-block:: text

   trustpoint-client list trust-stores

| Lists all available trust-stores.
| Option: -d / --domain

|
|

Certificate Request Commands
----------------------------

.. code-block:: text

   trustpoint-client request <type of certificate> -n <name> <options depending on type of certificate>

Option: -d / --domain

.. code-block:: text

   trustpoint-client request renew -n <name>

Option: -d / --domain

.. code-block:: text

   trustpoint-client request revoke -n <name>

Option: -d / --domain

.. code-block:: text

   trustpoint-client request cacerts -n <name>

Option: -d / --domain

|
|

.. note::

   The name is only a reference used by the client

|
|

Trust-Store Request Commands
----------------------------

.. code-block:: text

   trustpoint-client request trust-store -n <name>

Option: -d / --domain

.. note::

   The name is not defined by the client, but the trustpoint profiles.
   It will be uniquely identified by the 2-tuple (domain, name).

|
|

Delete Commands
---------------

.. note::

   Delete commands are only available for revoked and/or expired certificates / keys.

.. code-block:: text

   trustpoint delete cacerts -n <name>

Option: -d / --domain

.. code-block:: text

   trustpoint delete cert -n <name>

| Option: -d / --domain
| This will also delete the corresponding cacerts.

.. code-block:: text

   trustpoint delete key -n <name>

| Option: -d / --domain
| This will also delete the corresponding certificate and cacerts.

|
|

Enable Commands
---------------

.. code-block:: text

   trustpoint enable cert -n <name>

Option: -d / --domain

.. code-block:: text

   trustpoint disable cert -n <name>

Option: -d / --domain

.. code-block:: text

   trustpoint enable key -n <name>

Option: -d / --domain

.. code-block:: text

   trustpoint disable key -n <name>

Option: -d / --domain

.. code-block:: text

   trustpoint enable trust-store -n <name>

Option: -d / --domain

.. code-block:: text

   trustpoint disable trust-store -n <name>

Option: -d / --domain

|
|

File Path Commands
..................

These commands will store the corresponding entity as a files in the required format (read-only) and return the path.
However, these files will stay under the management of the trustpoint-client and thus mitigate any issues that can
arise if these are exported and placed and unsupervised locations. (Read Only)

.. warning::

   If keys are used this way, the included password generator will be used to generate the password.
   It will only be printed to the CLI once on creation!

   For most cases, it is discouraged to overwrite the use of the included password generator.

.. code-block:: text

   trustpoint get-file-path public-key -n <name> -f <format>

Option: -d / --domain

.. code-block:: text

   trustpoint get-file-path private-key -n <name> -f <format>

| Option: -d / --domain
| Option: -o / --overwrite-password-generator <password>

.. code-block:: text

   trustpoint get-file-path cert -n <name> -f <format>

Option: -d / --domain

.. code-block:: text

   trustpoint get-file-path cacerts -n <name> -f <format>

Option: -d / --domain

.. code-block:: text

   trustpoint get-file-path trust-store -n <name> -f <format>

Option: -d / --domain

.. code-block:: text

   trustpoint get-file-path credential -n <name> -f <format>

| Option: -d / --domain
| Option: -o / --overwrite-password-generator <password>

|
|

Export Commands
...............

These commands allow the user to export the key, certificate, cacerts and/or trust-stores
to be exported in the desired format.

.. warning::

   Generally, it is discouraged to export data from this client, however, it may be required in some cases.
   If keys are exported, the included password generator will be used to generate the password.
   It will only be printed to the CLI once on creation!

   For most cases, it is discouraged to overwrite the use of the included password generator.

.. code-block:: text

   trustpoint export public-key -n <name> -f <format> <file_path/name>

Option: -d / --domain

.. code-block:: text

   trustpoint export private-key -n <name> -f <format> <file_path/name>

| Option: -d / --domain
| Option: -o / --overwrite-password-generator <password>

.. code-block:: text

   trustpoint export cert -n <name> -f <format> <file_path/name>

Option: -d / --domain

.. code-block:: text

   trustpoint export cacerts -n <name> -f <format> <file_path/name>

Option: -d / --domain

.. code-block:: text

   trustpoint export trust-store -n <name> -f <format> <file_path/name>

Option: -d / --domain

.. code-block:: text

   trustpoint export credential -n <name> -f <format> <file_path/name>

| Option: -d / --domain
| Option: -o / --overwrite-password-generator <password>

|
|


Other Considerations
--------------------

.. note::

   We could consider extending this by adding trustpoint defined certificate profiles, that basically bundle
   the certificate type and selected options.

|
|

Future Extensions
-----------------

PKCS#11 / HSM / TPM support
...........................

It is intended to support PKCS#11 so that the private keys are stored in the dedicated hardware.
The Trustpoint Client will then allow to get the corresponding PKCS#11 handles to access and/or use the objects
resident in the dedicated hardware.

This may or may not include exportability. This will likely be configurable.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
