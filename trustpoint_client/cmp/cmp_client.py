import os
from pathlib import Path
import subprocess
from datetime import datetime
from trustpoint_client.cmp.openssl_assembler import OpenSSLCommandBuilder
from trustpoint_client.cmp.crypto_utils import CryptoUtils
import logging
import traceback


class CMPClient:
    REVOCATION_REASONS = {
        0: "unspecified",
        1: "keyCompromise",
        2: "cACompromise",
        3: "affiliationChanged",
        4: "superseded",
        5: "cessationOfOperation",
        6: "certificateHold"
    }
    def __init__(self, ca_server, ca_path, cert=None, key=None, secret=None, trusted_cert_chain=None, unprotected_requests=None):
        """
        Initialize a CMPClient instance.

        :param ca_server: The CA server address (e.g. 74.74.74.74:80).
        :param ca_path: The CA server path (e.g. /ejbca/publicweb/cmp/your_cmp_profile).
        :param cert: Path to the client certificate (.pem). For KUR the certificate to be updated (optional)
        :param key: Path to the client private key (.pem). (optional)
        :param key: A secret. (optional)
        :param trusted_cert_chain: Path to the trusted certificate chain (.pem). (optional)
        :param unprotected_requests: Send messages without CMP-level protection. (optional)
        """
        self.ca_server = ca_server
        self.ca_path = ca_path
        self.cert = cert
        self.key = key
        self.secret = secret
        self.trusted_cert_chain = trusted_cert_chain
        self.unprotected_requests = unprotected_requests

        #logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

        self.logger = logging.getLogger('cmp-client')

        self.logger.info("CMPClient initialized with CA server: %s, CA path: %s", self.ca_server, self.ca_path)


    def _run_command(self, command, print_stdout=True):
        """
        Run a shell command and handle errors.

        :param command: The command to run.
        :return: The standard output from the command.
        :raises: Exception if the command fails.
        """
        self.logger.debug("Running command: %s", command)
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode().strip()
        if print_stdout:
            self.logger.info("Command output: %s", output)

        if result.returncode != 0:
            error_message = f"Command failed with error: {str(result.stderr.decode().strip())}"
            self.logger.error(error_message)
            self.logger.error(traceback.format_exc())
            raise Exception(error_message)

    def _create_directories(self, dir_name):
        """
        Create necessary directories for storing keys and certificates.

        :param dir_name: The name of the directory to create.
        :return: The path to the created directory.
        """
        base_dir = Path.cwd()
        bin_dir = base_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        target_dir = bin_dir / dir_name
        target_dir.mkdir(parents=True, exist_ok=True)
        self.logger.info("Created directory: %s", target_dir)
        return target_dir

    def initialization(self, dn_info, san_info, key_algorithm, key_size=None, curve=None, implicit_confirm=False, detailed_logging=False):
        """
        Enroll a new certificate.

        :param dn_info: The distinguished name information.
        :param san_info: The subject alternative name information.
        :param key_algorithm: The key algorithm ('RSA' or 'EC').
        :param key_size: The size of the RSA key (optional).
        :param curve: The EC curve (optional).
        :param implicit_confirm: Whether to use implicit confirmation. Default is False.
        :param detailed_logging: Enable detailed logging. Default is False.
        :return: Paths to the certificate and certificate chain files.
        """
        self.logger.info("Starting initialization process")

        target_dir = self._create_directories(f"initialization_{datetime.now().strftime('%Y%m%d%H%M%S')}")

        crypto_utils = CryptoUtils()
        key_path, private_key = crypto_utils.generate_key(target_dir, key_algorithm, key_size, curve)
        csr_file = crypto_utils.generate_csr(target_dir, dn_info, san_info, private_key)
        cert_file = os.path.join(target_dir, "cert.pem")
        chain_file = os.path.join(target_dir, "chain.pem")
        extra_certs_file = os.path.join(target_dir, "extracerts.pem")
        ca_certs_file = os.path.join(target_dir, "ca.pem")

        command = OpenSSLCommandBuilder(ca_server=self.ca_server, ca_path=self.ca_path, cert=self.cert, key=self.key, trusted_cert_chain=self.trusted_cert_chain, implicit_confirm=implicit_confirm, detailed_logging=detailed_logging)
        command = command.assemble_initialization_command(cert_file, chain_file, extra_certs_file, ca_certs_file, key_path, csr_file)

        self._run_command(command)

        self.logger.info("Initialization process completed")

        return cert_file, chain_file

    def p10cr(self, dn_info, san_info=None, key_algorithm='RSA', key_size=2048, curve=None, implicit_confirm=False,
              detailed_logging=False):
        """
        Create a PKCS#10 certificate request and send it to the CA server.

        :param dn_info: The distinguished name information.
        :param san_info: The subject alternative name information (optional).
        :param key_algorithm: The key algorithm ('RSA' or 'EC'). Default is 'RSA'.
        :param key_size: The size of the RSA key (optional). Default is 2048.
        :param curve: The EC curve (optional).
        :param implicit_confirm: Whether to use implicit confirmation. Default is False.
        :param detailed_logging: Enable detailed logging. Default is False.
        :return: Paths to the certificate and certificate chain files.
        """
        self.logger.info("Starting PKCS#10 certificate request process")

        target_dir = self._create_directories(f"p10cr_{datetime.now().strftime('%Y%m%d%H%M%S')}")

        crypto_utils = CryptoUtils()
        key_path, private_key = crypto_utils.generate_key(target_dir, key_algorithm, key_size, curve)
        csr_file = crypto_utils.generate_csr(target_dir, dn_info, san_info, private_key)
        cert_file = os.path.join(target_dir, "cert.pem")
        chain_file = os.path.join(target_dir, "chain.pem")

        command = OpenSSLCommandBuilder(ca_server=self.ca_server, ca_path=self.ca_path, cert=self.cert, key=self.key,
                                        trusted_cert_chain=self.trusted_cert_chain, implicit_confirm=implicit_confirm,
                                        detailed_logging=detailed_logging)
        command = command.assemble_p10cr_command(cert_file, chain_file, key_path, csr_file)

        self._run_command(command)

        self.logger.info("PKCS#10 certificate request process completed")

        return cert_file, chain_file

    def certification(self, key_path, old_cert=None, dn_info=None, san_info=None, key_password=None, implicit_confirm=False, detailed_logging=False):
        """
        Renew an existing certificate.

        :param key_path: The path to the existing key.
        :param old_cert: The path to the certificate to be renewed (optional)
        :param dn_info: The distinguished name information (optional).
        :param san_info: The subject alternative name information (optional).
        :param key_password: The password for the existing key (optional).
        :param implicit_confirm: Whether to use implicit confirmation. Default is False.
        :param detailed_logging: Enable detailed logging. Default is False.
        :return: Paths to the new certificate and certificate chain files.
        """
        self.logger.info("Starting certification process")
        target_dir = self._create_directories(f"certification_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        crypto_utils = CryptoUtils()
        try:
            private_key = crypto_utils.load_private_key(key_path, key_password)
        except Exception as e:
            self.logger.error("Failed to load private key: %s", e)
            raise

        csr_file = None
        if dn_info and not old_cert:
            csr_file = crypto_utils.generate_csr(target_dir, dn_info, san_info, private_key)
        elif dn_info and old_cert:
            self.logger.warning("old_cert is preferred over a given dn_info. ")
        elif not dn_info and not old_cert:
            err_msg = "Either old_cert or a dn_info must be defined"
            self.logger.error(err_msg)
            raise Exception(err_msg)

        cert_file = os.path.join(target_dir, "new_cert.pem")
        chain_file = os.path.join(target_dir, "chain.pem")
        ca_cert_file = os.path.join(target_dir, "ca.pem")

        command = OpenSSLCommandBuilder(ca_server=self.ca_server, ca_path=self.ca_path, cert=self.cert, key=self.key, trusted_cert_chain=self.trusted_cert_chain, implicit_confirm=implicit_confirm, detailed_logging=detailed_logging)
        command = command.assemble_certification_command(cert_file, chain_file, ca_cert_file, key_path, csr_file=csr_file, old_cert=old_cert)
        self._run_command(command)

        self.logger.info("Certification process completed")

        return cert_file, chain_file

    def keyupdate(self, dn_info=None, san_info=None, key_algorithm=None, key_size=None, curve=None, implicit_confirm=False, detailed_logging=False):
        """
        Rekey an existing certificate.

        :param dn_info: The distinguished name information (optional).
        :param san_info: The subject alternative name information (optional).
        :param key_algorithm: The key algorithm ('RSA' or 'EC') (optional).
        :param key_size: The size of the RSA key (optional).
        :param curve: The EC curve (optional).
        :param implicit_confirm: Whether to use implicit confirmation. Default is False.
        :param detailed_logging: Enable detailed logging. Default is False.
        :return: Paths to the new certificate and certificate chain files.
        """
        self.logger.info("Starting key update process")

        target_dir = self._create_directories(f"keyupdate_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        crypto_utils = CryptoUtils()

        if not key_algorithm:
            self.logger.warning("key_algorithm has been defined. The preferred way is to derive the key_algorithm (and key length for RSA or curve type for EC) from the certificate that is to be renewed")
            key_algorithm, key_size, curve = crypto_utils.extract_key_information(self.cert)

        key_path, private_key = crypto_utils.generate_key(target_dir, key_algorithm, key_size, curve)
        csr_file=None
        if dn_info:
            csr_file = crypto_utils.generate_csr(target_dir, dn_info, san_info, private_key)

        cert_file = os.path.join(target_dir, "new_cert.pem")
        chain_file = os.path.join(target_dir, "chain.pem")

        command = OpenSSLCommandBuilder(ca_server=self.ca_server, ca_path=self.ca_path, cert=self.cert, key=self.key,
                                        trusted_cert_chain=self.trusted_cert_chain, implicit_confirm=implicit_confirm, detailed_logging=detailed_logging)
        command = command.assemble_keyupdate_command(cert_file, chain_file, key_path, csr_file)

        self._run_command(command)

        self.logger.info("Key update process completed")

        return cert_file, chain_file

    def revocation(self, reason, issuer=None, serial=None, oldcert=None):
        """
        Revoke a certificate.

        :param reason: The reason for revocation.
                The possible revocation reasons are:
                0 - unspecified
                1 - keyCompromise
                2 - cACompromise
                3 - affiliationChanged
                4 - superseded
                5 - cessationOfOperation
                6 - certificateHold
        :param issuer: The issuer of the certificate (optional).
        :param serial: The serial number of the certificate (optional).
        :param oldcert: The path to the certificate to be revoked
        :raises: Exception if the command fails.
        """
        reason_text = self.REVOCATION_REASONS.get(reason, "unspecified")
        self.logger.info("Starting revocation process for serial: %s, reason: %s", serial, reason_text)

        command = OpenSSLCommandBuilder(ca_server=self.ca_server, ca_path=self.ca_path, cert=self.cert, key=self.key,
                                        trusted_cert_chain=self.trusted_cert_chain)
        command = command.assemble_revocation_request_command(reason=reason, serial=serial, issuer=issuer, oldcert=oldcert)

        self._run_command(command)

        self.logger.info("CMP revocation request sent successfully for serial %s with reason %s", serial, reason_text)

    def getcacerts(self):
        """
        Retrieve CA certificates.

        :return: The path to the retrieved CA certificates.
        """
        info_type = 'caCerts'
        self.logger.info("Retrieving CA certificates")

        target_dir = self._create_directories(f"retrieve_{info_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        output_file = os.path.join(target_dir, f"{info_type}.pem")

        command = OpenSSLCommandBuilder(ca_server=self.ca_server, ca_path=self.ca_path, cert=self.cert, key=self.key,
                                        trusted_cert_chain=self.trusted_cert_chain)
        command = command.assemble_ca_certs_command(info_type, output_file)

        self._run_command(command)

        self.logger.info("CA certificates retrieved and saved at: %s", output_file)
        return output_file

    def getrootupdate(self, newwithnew, oldwithnew=None):
        info_type = 'rootCaCert'
        self.logger.info("Retrieving Root CA Update")

        target_dir = self._create_directories(f"retrieve_{info_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        output_file = os.path.join(target_dir, f"{info_type}.pem")

        command = OpenSSLCommandBuilder(ca_server=self.ca_server, ca_path=self.ca_path, cert=self.cert, key=self.key,
                                        trusted_cert_chain=self.trusted_cert_chain)
        command = command.assemble_root_ca_cert_command(info_type, output_file, newwithnew, oldwithnew)

        self._run_command(command)

    def getcertreqtemplate(self):
        """
        Retrieve a certTemplate.


        :return: The path to the retrieved certTemplate.
        """
        info_type = 'certReqTemplate'
        self.logger.info("Retrieving certReqTemplate")

        target_dir = self._create_directories(f"retrieve_{info_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        output_file = os.path.join(target_dir, f"{info_type}.txt")

        command = OpenSSLCommandBuilder(ca_server=self.ca_server, ca_path=self.ca_path, cert=self.cert, key=self.key,
                                        trusted_cert_chain=self.trusted_cert_chain)
        command = command.assemble_cert_req_template_command(info_type, output_file)

        self._run_command(command)

        self.logger.info("CA certificates retrieved and saved at: %s", output_file)
        return output_file


    def getcrls(self):
        info_type = 'crls'
        self.logger.info("Retrieving CRL")

        target_dir = self._create_directories(f"retrieve_{info_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        output_file = os.path.join(target_dir, f"{info_type}.pem")

        command = OpenSSLCommandBuilder(ca_server=self.ca_server, ca_path=self.ca_path, cert=self.cert, key=self.key,
                                        trusted_cert_chain=self.trusted_cert_chain)
        command = command.assemble_getcrls_command(info_type, output_file)

        self._run_command(command)

        self.logger.info("CA certificates retrieved and saved at: %s", output_file)
        return output_file

