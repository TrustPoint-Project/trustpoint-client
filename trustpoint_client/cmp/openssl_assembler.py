import logging


class MissingParameter(Exception):
    """Exception raised for missing parameters."""
    pass


class CompetingParameter(Exception):
    """Exception raised for competing parameters."""
    pass


class OpenSSLCommandBuilder:
    def __init__(self, ca_server, ca_path, cert=None, key=None, secret=None, trusted_cert_chain=None,
                 unprotected_requests=False, detailed_logging=False, implicit_confirm=False):
        """
        Initialize the OpenSSLCommandBuilder with CA server details and optional certificate/key information.

        :param ca_server: The CA server URL.
        :param ca_path: The CA path for the command.
        :param cert: Path to the certificate file (optional).
        :param key: Path to the key file (optional).
        :param secret: Secret for the CMP command (optional).
        :param trusted_cert_chain: Path to the trusted certificate chain (optional).
        :param unprotected_requests: Boolean to indicate unprotected requests (optional).
        :param detailed_logging: Boolean to enable detailed logging options
        :param implicit_confirm: Boolean to enable implicit confirm
        """
        self.ca_server = ca_server
        self.ca_path = ca_path
        self.cert = cert
        self.key = key
        self.secret = secret
        self.trusted_cert_chain = trusted_cert_chain
        self.unprotected_requests = unprotected_requests
        self.detailed_logging = detailed_logging
        self.implicit_confirm = implicit_confirm

        # Set up logging
        self.logger = logging.getLogger('cmp-client')
        self.logger.debug("OpenSSLCommandBuilder initialized.")

    def _assemble_base_command(self, cmd):
        """
        Assemble the base OpenSSL command with the provided command type.

        :param cmd: The type of CMP command (e.g., 'ir', 'cr', 'kur', etc.).
        :return: The base command string.
        """
        self.logger.debug(f"Assembling base command with cmd: {cmd}")
        return f"openssl cmp -cmd {cmd} -server {self.ca_server} -path {self.ca_path} "

    def _assemble_cert_key_part(self):
        """
        Assemble the certificate and key part of the command.

        :return: The command string for certificate and key.
        """
        command = ""
        if self.cert and self.key:
            self.logger.debug("Adding cert and key to command.")
            command += f"-cert {self.cert} -key {self.key} "
        elif self.secret:
            self.logger.debug("Adding secret to command.")
            command += f"-secret {self.secret} -ref 1 "
        elif self.unprotected_requests:
            self.logger.debug("Adding unprotected requests to command.")
            command += "-unprotected_requests "
        return command

    def _assemble_trusted_cert_part(self):
        """
        Assemble the trusted certificate chain part of the command.

        :return: The command string for the trusted certificate chain.
        """
        if self.trusted_cert_chain:
            self.logger.debug("Adding trusted certificate chain to command.")
            return f"-trusted {self.trusted_cert_chain} "
        return ""

    def _assemble_output_files_part(self, cert_out_file=None, chain_file=None, extra_certs_file=None,
                                    ca_certs_file=None, crlout=None):
        """
        Assemble the output files part of the command.

        :param cert_out_file: Path to the output certificate file (optional).
        :param chain_file: Path to the output chain file (optional).
        :param extra_certs_file: Path to the output extra certificates file (optional).
        :param ca_certs_file: Path to the output CA certificates file (optional).
        :param crlout: The file to save CRL received in a genp message of infoType crls (optional).
        :return: The command string for output files.
        """
        command = ""
        if cert_out_file:
            self.logger.debug("Adding certout to command.")
            command += f"-certout {cert_out_file} "
        if chain_file:
            self.logger.debug("Adding chainout to command.")
            command += f"-chainout {chain_file} "
        if extra_certs_file:
            self.logger.debug("Adding extracertsout to command.")
            command += f"-extracertsout {extra_certs_file} "
        if ca_certs_file:
            self.logger.debug("Adding cacertsout to command.")
            command += f"-cacertsout {ca_certs_file} "
        if crlout:
            self.logger.debug("Adding crlout to command.")
            command += f"-crlout {crlout} "
        return command

    def _assemble_detailed_logging(self):
        """
        Assemble the additional debugging options to the command

        :return: The command string for debugging options.
        """
        command = ""
        if self.detailed_logging:
            self.logger.debug("Adding unprotected_errors to command.")
            command += f"-unprotected_errors "

            self.logger.debug("Adding verbosity level 8 to command.")
            command += f"-verbosity 8 "

            self.logger.debug("Adding rspout to command. ASN1 repsonse is stored in asn1.rsp")
            command += f"-rspout asn1.rsp "

        return command

    def _assemble_implicit_confirm(self):
        """
        Assemble the implicit confirm command

        :return: The command string which enables implicit confirm.
        """
        command = ""
        if self.implicit_confirm:
            self.logger.debug("Adding -disable_confirm (Implicit Confirm) to command.")
            command += f"-disable_confirm "
        return command

    def assemble_initialization_command(self, cert_file, chain_file, extra_certs_file, ca_certs_file, key_path,
                                        csr_file):
        """
        Assemble the OpenSSL command for Initial Registration (IR).

        :param cert_file: Path to the output certificate file.
        :param chain_file: Path to the output chain file.
        :param extra_certs_file: Path to the output extra certificates file.
        :param ca_certs_file: Path to the output CA certificates file.
        :param key_path: Path to the key file.
        :param csr_file: Path to the CSR file.
        :return: The complete command string for IR.
        """
        self.logger.debug("Assembling IR command.")
        command = self._assemble_base_command("ir")
        command += self._assemble_cert_key_part()
        command += self._assemble_trusted_cert_part()
        command += (
                self._assemble_output_files_part(cert_file, chain_file, extra_certs_file, ca_certs_file) +
                f"-newkey {key_path} -csr {csr_file} "
        )
        command += self._assemble_detailed_logging()
        command += self._assemble_implicit_confirm()

        self.logger.debug(f"IR command assembled: {command}")
        return command

    def assemble_p10cr_command(self, cert_file, chain_file, key_path, csr_file):
        """
        Assemble the OpenSSL command for submitting a PKCS#10 Certificate Request (P10CR).

        :param cert_file: Path to the output certificate file.
        :param chain_file: Path to the output chain file.
        :param key_path: Path to the generated private key.
        :param csr_file: Path to the CSR file.
        :return: The complete command string for P10CR.
        """
        self.logger.debug("Assembling P10CR command.")
        command = self._assemble_base_command("p10cr")
        command += self._assemble_cert_key_part()
        command += self._assemble_trusted_cert_part()
        command += (
                f"-newkey {key_path} -csr {csr_file} " +
                self._assemble_output_files_part(cert_out_file=cert_file, chain_file=chain_file)
        )
        command += self._assemble_detailed_logging()
        command += self._assemble_implicit_confirm()

        self.logger.debug(f"P10CR command assembled: {command}")
        return command

    def assemble_certification_command(self, cert_file, chain_file, ca_cert_file, key_path, csr_file=None,
                                       old_cert=None):
        """
        Assemble the OpenSSL command for Certificate Renewal (CR).

        :param cert_file: Path to the output certificate file.
        :param chain_file: Path to the output chain file.
        :param ca_cert_file: Path to the output CA certificate file.
        :param key_path: Path to the key file.
        :param csr_file: Path to the CSR file (optional).
        :param old_cert: Path of the certificate to be renewed (optional)
        :return: The complete command string for CR.
        """
        self.logger.debug("Assembling CR command.")
        command = self._assemble_base_command("cr")
        command += (
                self._assemble_cert_key_part() +
                self._assemble_trusted_cert_part() +
                f"-newkey {key_path} " +
                self._assemble_output_files_part(cert_out_file=cert_file, chain_file=chain_file,
                                                 ca_certs_file=ca_cert_file)
        )
        if csr_file:
            self.logger.warning(
                "The use of csr_file is not recommended, as the subject and subject alternative name in the certificate to be renewed must match the original certificate. Use oldcert instead.")
            command += f"-csr {csr_file} "
        if old_cert:
            command += f"-oldcert {old_cert} "
        command += self._assemble_detailed_logging()
        command += self._assemble_implicit_confirm()
        self.logger.debug(f"CR command assembled: {command}")
        return command

    def assemble_keyupdate_command(self, cert_file, chain_file, key_path, csr_file=None):
        """
        Assemble the OpenSSL command for Key Update Request (KUR).

        :param cert_file: Path to the output certificate file.
        :param chain_file: Path to the output chain file.
        :param key_path: Path to the key file.
        :param csr_file: Path to the CSR file (optional). If not provided the information from self.cert is used.
        :return: The complete command string for KUR.
        """
        self.logger.debug("Assembling KUR command.")
        command = self._assemble_base_command("kur")
        command += (
                self._assemble_cert_key_part() +
                self._assemble_trusted_cert_part() +
                f"-newkey {key_path} " +
                self._assemble_output_files_part(cert_out_file=cert_file, chain_file=chain_file)
        )
        if csr_file:
            self.logger.warning(
                "The use of csr_file is not recommended, as the subject and subject alternative name in the certificate to be renewed must match the original certificate. For KUR the attributes from self.cert will betaken.")
            command += f"-csr {csr_file} "

        command += self._assemble_detailed_logging()
        command += self._assemble_implicit_confirm()
        self.logger.debug(f"KUR command assembled: {command}")
        return command

    def assemble_revocation_request_command(self, reason, serial=None, issuer=None, oldcert=None):
        """
        Assemble the OpenSSL command for Revocation Request (RR).

        For RR the certificate to be revoked can also be specified using csr. oldcert and csr is ignored if issuer and serial is provide

        :param serial: The serial number of the certificate to revoke.
        :param issuer: The issuer of the certificate.
        :param reason: The reason for revocation.
        :param oldcert: The certificate to be revoked
        :return: The complete command string for RR.
        """
        self.logger.debug("Assembling RR command.")
        command = self._assemble_base_command("rr")
        command += (
                self._assemble_cert_key_part() +
                self._assemble_trusted_cert_part() +
                f"-revreason {reason} "
        )
        if serial:
            command += f"-serial {serial} "
        if issuer:
            command += f"-issuer '{issuer}' "
        if oldcert and not serial and not issuer:
            command += f"-oldcert {oldcert} "
        elif oldcert:
            self.logger.warning("oldcert is ignored if issuer and serial is provided")

        command += self._assemble_detailed_logging()
        self.logger.debug(f"RR command assembled: {command}")
        return command

    def assemble_ca_certs_command(self, info_type, output_file):
        """
        Assemble the OpenSSL command for a caCerts General Message (GENM).

        :param info_type: The type of information requested.
        :param output_file: Path to the output file for CA and extra certificates.
        :return: The complete command string for GENM.
        """
        self.logger.debug("Assembling GENM command.")
        command = self._assemble_base_command("genm")
        command += f"-infotype {info_type} "
        command += self._assemble_output_files_part(extra_certs_file=output_file, ca_certs_file=output_file)

        command += self._assemble_cert_key_part()
        command += self._assemble_trusted_cert_part()
        command += self._assemble_detailed_logging()

        self.logger.debug(f"GENM command assembled: {command}")
        return command

    def assemble_root_ca_cert_command(self, info_type, output_file, newwithnew, oldwithnew=None):
        """
        Assemble the OpenSSL command for a rootCaCert General Message (GENM).

        :param info_type: The type of information requested.
        :param output_file: Path to the output file for CA and extra certificates.
        :param newwithnew: The file to save the newWithNew certificate received in a genp message of type rootCaKeyUpdate.
        :param: oldwithnew:The file to save any oldWithNew certificate received in a genp message of infoType rootCaKeyUpdate. If on success no such cert was received, this is indicated by deleting the file (optional).
        :return: The complete command string for GENM.
        """
        self.logger.debug("Assembling GENM command.")
        command = self._assemble_base_command("genm")
        command += f"-infotype {info_type} "
        command += self._assemble_output_files_part(extra_certs_file=output_file, ca_certs_file=output_file)

        if newwithnew:
            command += f"-newwithnew {newwithnew} "

        if oldwithnew:
            command += f"-oldwithnew {oldwithnew} "

        command += self._assemble_cert_key_part()
        command += self._assemble_trusted_cert_part()
        command += self._assemble_detailed_logging()

        self.logger.debug(f"GENM command assembled: {command}")
        return command

    def assemble_getcrls_command(self, info_type, crlout, crlcert=None, oldcrl=None):
        """
        Assemble the OpenSSL command for a getcrls General Message (GENM).

        :param info_type: The type of information requested.
        :param crlout: Path to the output file for CA and extra certificates.
        :param crlcert: filename for the certificate used for specifying a CRL issuer when requesting a CRL in a genm message with infoType crlStatusList (Optional)
        :param: oldcrl: filename of a CRL used for specifying a CRL issuer when requesting a CRL in a genm message with infoType crlStatusList (Optional)
        :return: The complete command string for GENM.
        """
        self.logger.debug("Assembling GENM command.")
        command = self._assemble_base_command("genm")
        command += f"-infotype {info_type} "
        command += self._assemble_output_files_part(crlout=crlout)

        if crlcert:
            command += f"-crlcert {crlcert} "
        if oldcrl:
            command += f"-oldcrl {oldcrl} "

        command += self._assemble_cert_key_part()
        command += self._assemble_trusted_cert_part()
        command += self._assemble_detailed_logging()

        self.logger.debug(f"GENM command assembled: {command}")
        return command
