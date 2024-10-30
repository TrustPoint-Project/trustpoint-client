import os
from pathlib import Path

import click

from trustpoint_client.cli.version import version_id

CLI_DIRECTORY = str(Path(__file__).resolve().parent)

domain_option_required = click.option(
    '--domain', '-d',
    type=str,
    required=True,
    help='Handle of the desired domain.')
domain_option_optional = click.option(
    '--domain', '-d',
    type=str,
    required=False,
    help='Handle of the desired domain.')
verbose_option = click.option('--verbose', '-v', is_flag=True, required=False, default=False, help='Enable verbose mode.')

class TrustPointClientCli(click.MultiCommand):

    def list_commands(self, ctx: click.core.Context) -> list[str]:
        command_list =  [
            filename[:-3].replace('_', '-') for filename in os.listdir(CLI_DIRECTORY)
            if filename.endswith('.py') and filename not in ['__init__.py', 'decorator.py']
        ]
        return sorted(command_list)

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
        if name == 'domain':
            return ns['domain_']
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