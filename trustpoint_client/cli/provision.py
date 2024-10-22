"""Command-line interface for the Trustpoint-Client."""
from __future__ import annotations


import click

from trustpoint_client.api import TrustpointClient
from trustpoint_client.cli import handle_cli_error


@click.command
@click.option('--otp', '-o', required=True, type=str, help='The One-Time Password to use.')
@click.option('--device', '-d', required=True, type=str, help='The device name.')
@click.option('--host', '-h', required=True, type=str, help='The domain name or IP address of the trustpoint.')
@click.option('--port', '-p', required=False, type=int, default=443, help='The port of the trustpoint if not 443.')
def provision(otp: str, device: str, host: str, port: int) -> None:
    """Provisions this device."""
    trustpoint_client = TrustpointClient()
    # check if host contains a port
    if ':' in host:
        host, port = host.split(':')
        port = int(port)
    result = trustpoint_client.provision(otp, device, host, port)

    click.echo('\n\tTrustpoint Client successfully provisioned.\n')
    click.echo(f'\tDevice: {result["device"]}.')
    click.echo(f'\tTrustpoint-Host: {result["host"]}:{result["port"]}.')
    click.echo(f'\tDefault-Domain: {result["domain"]}.')
    click.echo(f'\tDefault-PKI-Protocol: {result["default-pki-protocol"].value}.')
    click.echo(f'\tDefault-Signature-Suite: {result["default-signature-suite"].value}.')
    click.echo()
