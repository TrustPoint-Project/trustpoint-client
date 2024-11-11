"""Trustpoint-Client CLI Package."""

from __future__ import annotations

import importlib.metadata
import os
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING

import click

try:
    version_id = importlib.metadata.version('trustpoint_client')
except Exception as exception:
    raise click.ClickException(str(exception)) from exception

if TYPE_CHECKING:
    from typing import Any

CLI_DIRECTORY = str(Path(__file__).resolve().parent)

domain_option_required = click.option('--domain', '-d', type=str, required=True, help='Handle of the desired domain.')
domain_option_optional = click.option('--domain', '-d', type=str, required=False, help='Handle of the desired domain.')
verbose_option = click.option(
    '--verbose', '-v', is_flag=True, required=False, default=False, help='Enable verbose mode.'
)


def handle_exception(func: callable) -> callable:
    """Handles exceptions gracefully for the CLI application.

    Args:
        func: The decorated function.
    """

    @wraps(func)
    @click.pass_context
    def _wrapper_function(ctx: click.Context, *args: Any, **kwargs: dict[str, Any]) -> Any:
        try:
            return ctx.invoke(func, *args, **kwargs)
        except Exception as exc:
            err_msg = str(exc)
            raise click.ClickException(err_msg) from exc

    return _wrapper_function


class TrustPointClientCli(click.MultiCommand):
    """Abstraction of the TrustPointClientCli program.

    Compare with Python Click documentation.
    """

    def list_commands(self, ctx: click.core.Context) -> list[str]:  # noqa: ARG002
        """Lists the commands.

        Compare with Python Click documentation.
        """
        command_list = [
            filename[:-3].replace('_', '-')
            for filename in os.listdir(CLI_DIRECTORY)
            if filename.endswith('.py') and filename not in ['__init__.py', 'decorator.py']
        ]
        return sorted(command_list)

    def get_command(self, ctx: click.core.Context, name: str) -> dict:
        """Gets a command.

        Compare with Python Click documentation.
        """
        ns = {}
        if name not in self.list_commands(ctx):
            err_msg = f"\n\tCommand '{name}' does not exist.\n"
            raise ValueError(err_msg)
        name = name.replace('-', '_')
        fn = Path(CLI_DIRECTORY + '/' + name + '.py')
        with fn.open() as f:
            code_object = compile(f.read(), fn, 'exec')
            # TODO(AlexHx8472): Investigate if the call of eval may be a security issue in this case specifically.
            eval(code_object, ns, ns)  # noqa: S307
        if name == 'list':
            return ns['list_']
        if name == 'del':
            return ns['del_']
        if name == 'domain':
            return ns['domain_']
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
    click.echo('')


cli = TrustPointClientCli(help='Trust point client')
