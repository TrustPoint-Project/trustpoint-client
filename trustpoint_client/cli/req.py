import click
from pathlib import Path

BASE_PATH = Path('__file__').resolve().parent / 'trustpoint_client/demo_data'


@click.group
def req():
    """Request a new certificate or trust-store."""


# TODO(AlexHx8472, Aircoookie): All req cert commands:
# TODO(AlexHx8472, Aircoookie): 1. generate key with requested signature suite (devid module)
# TODO(AlexHx8472, Aircoookie): 2. enable key (devid module)
# TODO(AlexHx8472, Aircoookie): 3. perform the request (trustpoint)
# TODO(AlexHx8472, Aircoookie):     Failure: Remove the key from DevID module
# TODO(AlexHx8472, Aircoookie):     Success:
# TODO(AlexHx8472, Aircoookie):         Store certificate in devid module
# TODO(AlexHx8472, Aircoookie):         Enable certificate in devid module
# TODO(AlexHx8472, Aircoookie):         Store indices in client with the corresponding domain and name
# TODO(AlexHx8472, Aircoookie): 4. Add ca-certs if contained in response
# TODO(AlexHx8472, Aircoookie):     If not contained, echo a remark
# TODO(AlexHx8472, Aircoookie):     and offer with a click.confirm to execute get ca certs

@req.command(name='generic-cert')
def req_generic_cert():
    """Request a new generic certificate."""


@req.command(name='tls-client-cert')
@click.option('--name', '-n', type=str, required=True, help='The name (handle) to identify the new certificate.')
@click.option('--common-name', '-c', type=str, required=False, help='The common name to use.')
@click.option('--subject', '-s', type=str, required=False, help='The subject to use.')
def req_tls_client_cert(name:str, common_name: str, subject: str):
    """Request a new tls client certificate."""
    if not name.isidentifier():
        raise click.BadParameter('Name must be a valid identifier.')

    click.echo('\n\tTLS Client Certificate Issued.\n')
    click.echo('\tCertificate Type: TLS Client Certificate.')
    click.echo(f'\tName (handle): {name}.')
    click.echo(f'\tSignature-Suite: RSA2048-SHA256')
    if common_name:
        click.echo(f'\tCommon Name: {common_name}.')
    else:
        click.echo(f'\tCommon Name: {name}.')
    if subject:
        click.echo(f'\tSubject: {subject}.')

    click.echo()

    click.echo('\tTLS Client Certificate:\n')
    with (BASE_PATH / 'rsa2048-ee-cert.pem').open('r') as f:
        click.echo(f.read())
        click.echo('\n')

    click.echo('\tTLS Client Certificate Chain:\n')
    with (BASE_PATH / 'rsa2048-chain.pem').open('r') as f:
        click.echo(f.read())

    # TODO: Show certs


@req.command(name='tls-server-cert')
@click.option('--name', '-n', type=str, required=True, help='The name (handle) to identify the new certificate.')
@click.option('--common-name', '-c', type=str, required=False, help='The common name to use.')
@click.option('--subject', '-s', type=str, required=False, help='The subject to use.')
@click.option('--domains', '-d', type=str, required=False, help='The domains for the TLS Server Certificate.')
@click.option('--ipv4-addresses', '-i', type=str, required=False, help='The IPv4 addresses for the TLS Server Certificate.')
@click.option('--ipv6-addresses', '-j', type=str, required=False, help='The IPv6 addresses for the TLS Server Certificate.')
def req_tls_server_cert(name: str, common_name: str, subject: str, domains: str, ipv4_addresses: str, ipv6_addresses: str):
    """Request a new tls server certificate."""

    click.echo('\n\tTLS Server Certificate Issued.\n')
    click.echo('\tCertificate Type: TLS Server Certificate.')
    click.echo(f'\tName (handle): {name}.')
    click.echo(f'\tSignature-Suite: RSA2048-SHA256')
    if common_name:
        click.echo(f'\tCommon Name: {common_name}.')
    else:
        click.echo(f'\tCommon Name: {name}.')
    if subject:
        click.echo(f'\tSubject: {subject}.')
    if domains:
        click.echo(f'\tDomains: {domains}.')
    if ipv4_addresses:
        click.echo(f'\tIPv4 Addresses: {ipv4_addresses}.')
    if ipv6_addresses:
        click.echo(f'\tIPv6 Addresses: {ipv6_addresses}.')

    click.echo()

    click.echo('\tTLS Server Certificate:\n')
    with (BASE_PATH / 'rsa2048-ee-cert.pem').open('r') as f:
        click.echo(f.read())
        click.echo('\n')

    click.echo('\tTLS Server Certificate Chain:\n')
    with (BASE_PATH / 'rsa2048-chain.pem').open('r') as f:
        click.echo(f.read())



@req.command(name='mqtt-client-cert')
def req_mqtt_client_cert():
    """Request a new mqtt client certificate."""


@req.command(name='mqtt-server-cert')
def req_mqtt_server_cert():
    """Request a new mqtt server certificate."""


@req.command(name='opc-ua-client-cert')
def req_opc_ua_client_cert():
    """Request a new opc ua client certificate."""


@req.command(name='opc-ua-server-cert')
def req_opc_ua_server_cert():
    """Request a new opc ua server certificate."""


@req.command(name='ca-certs')
def req_ca_certs():
    """Requests the certificate chain for the issuing ca in use."""


@req.command(name='trust-store')
def req_trust_store():
    """Request a trust-store."""