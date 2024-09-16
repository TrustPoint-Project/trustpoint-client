import os

import click

from trustpoint_client.api import TrustpointClient, WORKING_DIR, CONFIG_FILE_PATH
from trustpoint_client.api.config import TrustpointClientConfig
from trustpoint_client.cli.version import version_id
from pathlib import Path

from trustpoint_client.cli.decorator import handle_cli_error

CLI_DIRECTORY = str(Path(__file__).resolve().parent)

class TrustPointClientCli(click.MultiCommand):

    def list_commands(self, ctx: click.core.Context) -> list[str]:
        return [
            filename[:-3].replace('_', '-') for filename in os.listdir(CLI_DIRECTORY)
            if filename.endswith('.py') and filename not in ['__init__.py', 'decorator.py']
        ]

    @handle_cli_error
    def get_command(self, ctx: click.core.Context, name: str) -> dict:
        ns = {}
        if name not in self.list_commands(ctx):
            # TODO(AlexHx8472)
            raise ValueError(f'\n\tCommand \'{name}\' does not exist.\n')
        name = name.replace('-', '_')
        fn = Path(CLI_DIRECTORY + '/' + name + '.py')
        with fn.open() as f:
            code_object = compile(f.read(), fn, 'exec')
            eval(code_object, ns, ns)
        if name == 'list':
            return ns['list_']
        if name == 'del':
            return ns['del_']
        else:
            return ns[name]


TRUSTPOINT_LOGO = r"""
      ________________________________  
     /    _                      _    \ 
    |   _| |_  ____ _   _  ___ _| |_   |
    |  (_   _)/ ___) | | |/___|_   _)  |
    |    | |_| |   | |_| |___ | | |_   |
    |     \__)_|   |____/(___/   \__)  |  
     \________________________________/   
                      _            
                     (_)         _   
        ____   ___   __    ___ _| |_ 
       |  _ \ / _ \ (  |  / _ (_   _)
       | |_| | |_| | | | | | | || |_ 
       |  __/ \___/ (___)|_| |_| \__)
       |_|

    """


def draw_ascii_logo() -> None:
    """Draws the Trustpoint ASCII logo."""
    click.echo(TRUSTPOINT_LOGO)

def draw_tp_client_description() -> None:
    """Draws the Trustpoint client description."""
    click.echo(f'\nWelcome to the Trustpoint Client Certificate Manager (tp-crt-mgr) - v{version_id}!')
    # draw_ascii_logo()
    click.echo('')


cli = TrustPointClientCli(help='Trust point client')


def get_trustpoint_client(working_dir: Path = WORKING_DIR) -> TrustpointClient:
    """Instantiates the TrustpointClient class with the desired working directory.

    Args:
        working_dir: Path to the desired working directory.

    Returns:
        TrustpointClient: An instance of the TrustpointClient class.
    """
    return TrustpointClient(working_dir=working_dir, purge_init=False)


def get_trustpoint_client_for_purge(working_dir: Path = WORKING_DIR) -> TrustpointClient:
    """Instantiates the TrustpointClient class with the desired working directory and the purge flag set to True.

    Args:
        working_dir: Path to the desired working directory.

    Returns:
        TrustpointClient: An instance of the TrustpointClient class.
    """
    return TrustpointClient(working_dir=working_dir, purge_init=True)


def get_initialized_trustpoint_client(working_dir: Path = WORKING_DIR) -> None | TrustpointClient:
    """Instantiates the TrustpointClient class and tries to load the stored DevID Module data.

    Args:
        working_dir: Path to the desired working directory.

    Returns:
        None | TrustpointClient:
            An instance of the TrustpointClient class if the initialization
            with existing data was successful, None otherwise.
    """
    trustpoint_client = TrustpointClient(working_dir)
    if trustpoint_client.inventory is None:
        click.echo('Trustpoint Client is not yet initialized.')
        return None
    return trustpoint_client


def get_client_config(config_file_path: Path = CONFIG_FILE_PATH) -> TrustpointClientConfig:
    """Gets the initialized Trustpoint Client Config object.

    Args:
        config_file_path: Path to the configuration file.

    """
    return TrustpointClientConfig(config_file_path)
