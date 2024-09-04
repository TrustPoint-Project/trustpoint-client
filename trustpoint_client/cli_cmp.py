import click
import logging
import os
import traceback

try:
    from trustpoint_client.cmp_client.cmp_client import CMPClient
    from trustpoint_client.cmp_client.crypto_utils import CryptoUtils
    _cmp_client_imported = True
except ImportError:
    _cmp_client_imported = False
    raise

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger('cmp_client')


class CMPClientOperations:
    """CMP client operation implementations."""

    _host: str = ''
    _domain: str = ''
    _cert_path: str = './secret_trustpoint/cmp_client_cert.pem'
    _key_path: str = './secret_trustpoint/cmp_client_key.pem'
    _trusted_cert_chain_path: str = './secret_trustpoint/ca_cert.pem'

    def _ensure_prerequisites(self) -> bool:
        """Ensures that all prerequisites for CMP operations are met."""
        global _cmp_client_imported
        if not _cmp_client_imported:
            click.echo('CMP client import failed.')
            return False
        if not self._host:
            click.echo('Host not set.')
            return False
        if not self._domain:
            click.echo('Domain not set.')
            return False
        # if not os.path.exists(self._cert_path):
        #     click.echo(f'CMP client certificate file not found at {self._cert_path}.')
        #     return False
        # if not os.path.exists(self._key_path):
        #     click.echo(f'CMP client key file not found at {self._key_path}.')
        #     return False
        # if not os.path.exists(self._trusted_cert_chain_path):
        #     click.echo(f'CMP trust cert chain file not found at {self._trusted_cert_chain_path}.')
        #     return False
        return True

    def set_host(self, host: str) -> None:
        self._host = host
    
    def set_domain(self, domain: str) -> None:
        self._domain = domain

    def cmp_initialization(self, alias: str = 'mqtt_client', key_algorithm='RSA', key_size=4096) -> None:
        """Performs CMP initialization."""
        if not self._ensure_prerequisites():
            return
        
        if alias:
            initialization_path = f'/.well-known/cmp/p/{self._domain}/initialization/{alias}/'
        else:
            initialization_path = f'/.well-known/cmp/p/{self._domain}/initialization/'

        dn_info = {
            'C': 'DE',
            'ST': 'BW',
            'L': 'Freudenstadt',
            'O': 'Campus Schwarzwald',
            'OU': 'Trustpoint',
            'CN': 'client.trustpoint.com'
        }

        san_info = {
            'DNS': ['example.com', 'www.example.com'],
            'IP': ['192.168.1.1'],
            'URI': ['http://example.com']
        }

        initialization_client = CMPClient(self._host, initialization_path,
                                          self._cert_path, self._key_path, self._trusted_cert_chain_path)
        
        try:
            cert_file, chain_file = initialization_client.initialization(
                dn_info, san_info, key_algorithm, key_size=key_size, implicit_confirm=True, detailed_logging=True)
            log.info(f"Certificate saved at: {cert_file}")
            log.info(f"Certificate chain saved at: {chain_file}")
        except Exception as e:
            log.error("Failed to enroll new certificate")
            log.error(e)
            log.debug(traceback.format_exc())
            


_cmp_client_operations = CMPClientOperations()

@click.group()
@click.option('--host', '-h', required=False, type=str, help='The IP or domain address of the Trustpoint.')
@click.option('--domain', '-d', required=False, type=str, help='The domain to run CMP operations on.')
def cmp(host: str = '', domain: str = '') -> None:
    """CMP operations."""
    if host:
        _cmp_client_operations.set_host(host)
    if domain:
        _cmp_client_operations.set_domain(domain)


@cmp.command()
@click.option('--alias', '-a', required=False, type=str, help='The alias to use for initialization.')
def initialization(alias: str = '') -> None:
    """Performs CMP initialization."""
    _cmp_client_operations.cmp_initialization(alias)

@cmp.command()
def certification() -> None:
    """Performs CMP certification."""

@cmp.command()
def revocation() -> None:
    """Performs CMP revocation."""

@cmp.command()
def keyupdate() -> None:
    """Performs CMP key update."""

@cmp.command()
def getcacerts() -> None:
    """Performs CMP get CA certificates operation."""

@cmp.command()
def getrootupdate() -> None:
    """Performs CMP get root CA update operation."""