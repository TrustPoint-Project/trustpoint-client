import click
import importlib.metadata


version = importlib.metadata.version('trustpoint_client')

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
    click.echo(f'\nWelcome to the Trustpoint Client Certificate Manager (tp-crt-mgr) - v{version}!')
    # draw_ascii_logo()
    click.echo('')


@click.group(help=draw_tp_client_description())
def cli() -> None:
    pass


@cli.command()
def version() -> None:
    """Displays the version of Trustpoint-Client."""
    draw_ascii_logo()
    click.echo(f'Welcome to the Trustpoint Client Certificate Manager (tp-crt-mgr) v {version}!')
