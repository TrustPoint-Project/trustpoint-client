import os

import click
from trustpoint_client.cli.version import version_id
from pathlib import Path

CLI_DIRECTORY = str(Path(__file__).resolve().parent)

class TrustPointClientCli(click.MultiCommand):

    def list_commands(self, ctx: click.core.Context) -> list[str]:
        return [
            filename[:-3].replace('_', '-') for filename in os.listdir(CLI_DIRECTORY)
            if filename.endswith('.py') and filename != '__init__.py'
        ]

    def get_command(self, ctx: click.core.Context, name: str) -> dict:
        ns = {}
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


TRUSTPOINT_LOGO = """\b
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@
    @@@@     @@ @   @@ @@@ @@@   @@@     @@@@
    @@@@@ @@@@@  @@@@@ @@@ @@ @@@ @@@ @@@@@@@
    @@@@@ @@@@@ @@@@@@ @@@ @@@  @@@@@ @@@@@@@
    @@@@@ @@ @@ @@@@@@ @@  @@@@@  @@@ @@ @@@@
    @@@@@@  @@@ @@@@@@@  @ @@    @@@@@  @@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    \b
                        @
                                     @
        @ @@    @@@   @@@    @ @@   @@@@@
        @@  @  @   @    @    @@  @   @
        @   @  @   @    @    @   @   @  @
        @@@@    @@@   @@@@@  @   @    @@
        @
        @
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
