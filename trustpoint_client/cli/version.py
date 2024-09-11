import importlib.metadata
import click


version_id = importlib.metadata.version('trustpoint_client')


@click.command()
def version():
    """Displays the version of Trustpoint-Client."""
    click.echo(f'\n\tTrustpoint Client Version: v{version_id}\n')
