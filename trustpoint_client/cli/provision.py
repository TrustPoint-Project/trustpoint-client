"""Command-line interface for the Trustpoint-Client."""
from __future__ import annotations


import click
from trustpoint_client.cli import get_trustpoint_client, handle_cli_error
from trustpoint_client.demo.callback_demo_leds import callback_demo


@click.command
@click.option('--otp', '-o', required=True, type=str, help='The One-Time Password to use.')
@click.option('--device', '-d', required=True, type=str, help='The device name.')
@click.option('--host', '-h', required=True, type=str, help='The domain name or IP address of the trustpoint.')
@click.option('--port', '-p', required=False, type=int, default=443, help='The port of the trustpoint if not 443.')
@handle_cli_error
def provision(otp: str, device: str, host: str, port: int) -> None:
    """Provisions this device."""
    trustpoint_client = get_trustpoint_client()
    trustpoint_client.set_provisioning_state_callback(callback_demo)
    result = trustpoint_client.provision(otp, device, host, port)

    click.echo('\n\tTrustpoint Client successfully provisioned.\n')
    click.echo(f'\tDevice: {result["device"]}.')
    click.echo(f'\tTrustpoint-Host: {result["host"]}:{result["port"]}.')
    click.echo(f'\tDefault-Domain: {result["domain"]}.')
    click.echo(f'\tDefault-PKI-Protocol: {result["default-pki-protocol"].value}.')
    if result['algorithm'] == 'RSA':
        click.echo(f'\tSignature-Suite: RSA{result["key-size"]}-SHA256.')
    if result['algorithm'] == 'ECC':
        if result['curve'] == 'SECP256R1':
            click.echo(f'\tSignature-Suite: SECP256R1-SHA256.')
        else:
            click.echo(f'\tSignature-Suite: SECP384R1-SHA384.')
    click.echo()
