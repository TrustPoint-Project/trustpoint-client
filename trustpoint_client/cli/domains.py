import click

from pathlib import Path

from trustpoint_client.api import TrustpointClient
from trustpoint_client.cli import domain_option_required, domain_option_optional, verbose_option

import prettytable

@click.group()
def domains():
    """Commands concerning domains."""


def echo_domain_info_tables(dict_: dict[str, dict[str, str]]) -> None:
    for key, value in dict_.items():
        cert = value.pop('LDevID Certificate', None)
        public_key = value.pop('LDevID Public-Key', None)
        cert_chain = value.pop('LDevID Certificate Chain', None)
        click.echo()
        click.echo(key)
        table = prettytable.PrettyTable(['Property', 'Value'])
        table.align = 'l'
        for k, v in dict_[key].items():
            table.add_row([k.title(), v])
        click.echo(table)
        if cert and public_key:
            click.echo()

            click.echo('LDevID Certificate')
            click.echo(64 * '-' + '\n')
            click.echo(cert)

            click.echo('\nLDevID Public-Key')
            click.echo(64 * '-' + '\n')
            click.echo(public_key)
            if cert_chain:
                click.echo()
                click.echo('LDevID Certificate Chain')
                click.echo(64 * '-' + '\n')
                click.echo(cert_chain)
        else:
            click.echo()


@domains.command(name='list')
@click.option('--all', '-a', 'all_domains', is_flag=True, required=False, default=False)
@domain_option_optional
@verbose_option
def domain_list(domain: None | str, verbose: bool, all_domains: bool) -> None:
    """Lists information about the configured domains."""
    trustpoint_client = TrustpointClient()
    if all_domains and domain:
        raise click.ClickException(
            'To list all domains use the --all flag. To list a specific domain use --domain <name>.')
    if all_domains:
        if verbose:
            domain_info = trustpoint_client.get_all_domain_info(verbose=True)
            if domain_info:
                echo_domain_info_tables(domain_info)
            else:
                click.echo('\nNo domains configured. Nothing to list.\n')
        else:
            domain_info = trustpoint_client.get_all_domain_info(verbose=False)
            if domain_info:
                echo_domain_info_tables(domain_info)
            else:
                click.echo('\nNo domains configured. Nothing to list.\n')
        return

    if not domain:
            domain = trustpoint_client.default_domain

    if domain is None:
        click.echo('\nNo default domain configured. Nothing to list.\n')
        return

    try:
        if verbose:
            echo_domain_info_tables(trustpoint_client.get_verbose_domain_info(domain=domain))
        else:
            echo_domain_info_tables(trustpoint_client.get_domain_info(domain=domain))
    except Exception as exception:
        click.echo(f'\n{exception}.\n')


@domains.command(name='delete')
@domain_option_required
def domain_delete(domain: str) -> None:
    """Deletes the specific domain and all corresponding credentials.

    \b
    Remark:
    -------
        Certificates are currently not revoked, but just deleted.
    """
    trustpoint_client = TrustpointClient()
    if domain not in trustpoint_client.inventory.domains:
        click.echo()
        raise click.ClickException(f'Domain {domain} does not exist. Nothing to delete.\n')
    if click.confirm(
            f'\nAre you sure you want to delete the domain {domain}? '
            f'This will delete all corresponding credentials and data.\n'):
        try:
            trustpoint_client.delete_domain(domain)
        except ValueError as exception:
            click.echo(f'\n{exception}\n')
            return
        click.echo(f'\nSuccessfully deleted domain {domain} and all corresponding credentials and data.\n')
        return
    click.echo('Aborted.')

@domains.group(name='config')
def domain_config() -> None:
    """Commands concerning configurations of specific domains."""

@domain_config.group(name='get')
def domain_config_get() -> None:
    """"""

@domain_config_get.command(name='host')
@domain_option_required
def domain_config_get_host(domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        host = trustpoint_client.get_domain_trustpoint_host(domain)
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

    if host:
        click.echo(f'\nTrustpoint host (host): {host}\n')
    else:
        click.echo('\nNo Trustpoint host (host) configured.\n')

@domain_config_get.command(name='port')
@domain_option_required
def domain_config_get_port(domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        port = trustpoint_client.get_domain_trustpoint_port(domain)
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

    if port:
        click.echo(f'\nTrustpoint Port: {port}\n')
    else:
        click.echo('\nNo Trustpoint port configured.\n')

@domain_config_get.command(name='signature-suite')
@domain_option_required
def domain_config_get_signature_suite(domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        signature_suite = trustpoint_client.get_domain_signature_suite(domain)
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

    if signature_suite:
        click.echo(f'\nSignature Suite: {signature_suite}\n')
    else:
        click.echo('\nNo signature suite configured.\n')

@domain_config_get.command(name='pki-protocol')
@domain_option_required
def domain_config_get_pki_protocol(domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        pki_protocol = trustpoint_client.get_domain_pki_protocol(domain)
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

    if pki_protocol:
        click.echo(f'\nPKI Protocol: {pki_protocol}\n')
    else:
        click.echo('\nNo pki protocol configured.\n')

@domain_config_get.command(name='tls-trust-store')
@domain_option_required
def domain_config_get_tls_trust_store(domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        tls_trust_store = trustpoint_client.get_domain_tls_trust_store(domain)
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

    if tls_trust_store:
        click.echo(f'\nTLS Trust-Store:\n{tls_trust_store}\n')
    else:
        click.echo('\nNo TLS trust-store configured.\n')

@domain_config.group(name='set')
def domain_config_set() -> None:
    """"""

@domain_config_set.command(name='host')
@click.option('--host', '-h', type=str, required=True, help='The host name to set.')
@domain_option_required
def domain_config_set_host(host: str, domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        trustpoint_client.set_domain_trustpoint_host(domain, host)
        click.echo(f'\nSuccessfully set host name {host} for domain {domain}.')
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

@domain_config_set.command(name='port')
@click.option('--port', '-p', type=int, required=True, help='The port to set.')
@domain_option_required
def domain_config_set_port(port: int, domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        trustpoint_client.set_domain_trustpoint_port(domain, port)
        click.echo(f'\nSuccessfully set port {port} for domain {domain}.')
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

@domain_config_set.command(name='pki-protocol')
@click.option('--pki-protocol', '-p', type=str, required=True, help='The pki protocol to set.')
@domain_option_required
def domain_config_set_pki_protocol(pki_protocol: str, domain: str) -> None:
    trustpoint_client = TrustpointClient()
    pki_protocol = pki_protocol.upper()

    try:
        trustpoint_client.set_domain_pki_protocol(domain, pki_protocol)
        click.echo(f'\nSuccessfully set pki protocol {pki_protocol} for domain {domain}.')
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

@domain_config_set.command(name='tls-trust-store')
@click.option(
    '--tls-trust-store', '-t',
    type=click.Path(),
    required=True,
    help='The TLS trust-store file path.')
@domain_option_required
def domain_config_set_tls_trust_store(tls_trust_store: str, domain: str) -> None:
    trustpoint_client = TrustpointClient()

    tls_trust_store_path = Path(tls_trust_store).resolve()
    # TODO(AlexHx8472): Implement TLS trust-store loading

@domain_config.group(name='clear')
def domain_config_clear() -> None:
    """"""

@domain_config_clear.command(name='host')
@domain_option_required
def domain_config_clear_host(domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        trustpoint_client.set_domain_trustpoint_host(domain, None)
        click.echo(f'\nSuccessfully cleared host name for domain {domain}.')
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

@domain_config_clear.command(name='port')
@domain_option_required
def domain_config_set_port(domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        trustpoint_client.set_domain_trustpoint_port(domain, None)
        click.echo(f'\nSuccessfully cleared port for domain {domain}.')
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

@domain_config_clear.command(name='pki-protocol')
@domain_option_required
def domain_config_set_pki_protocol(domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        trustpoint_client.set_domain_pki_protocol(domain, None)
        click.echo(f'\nSuccessfully cleared pki protocol for domain {domain}.')
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return

@domain_config_clear.command(name='tls-trust-store')
@domain_option_required
def domain_config_set_tls_trust_store(domain: str) -> None:
    trustpoint_client = TrustpointClient()

    try:
        trustpoint_client.set_domain_tls_trust_store(domain, None)
        click.echo(f'\nSuccessfully cleared TLS trust-store for domain {domain}.')
    except KeyError:
        click.echo(f'\nDomain {domain} does not exist.\n')
        return
