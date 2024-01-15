import click
from trustpoint_client.trustpoint_client import provision as _provision

version = "0.1.0"

asciiLogo : str = """\b
 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@
@@@@     @@ @   @@ @@@ @@@   @@@     @@@@
@@@@@ @@@@@  @@@@@ @@@ @@ @@@ @@@ @@@@@@@
@@@@@ @@@@@ @@@@@@ @@@ @@@  @@@@@ @@@@@@@
@@@@@ @@ @@ @@@@@@ @@  @@@@@  @@@ @@ @@@@
@@@@@@  @@@ @@@@@@@  @ @@    @@@@@  @@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ 
 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ 
    
                    @            
                                 @
    @ @@    @@@   @@@    @ @@   @@@@@
    @@  @  @   @    @    @@  @   @
    @   @  @   @    @    @   @   @  @
    @@@@    @@@   @@@@@  @   @    @@
    @
    @
"""

def drawAsciiLogo() -> None:
    click.echo("""\b
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
     
                        @            
                                     @
        @ @@    @@@   @@@    @ @@   @@@@@
        @@  @  @   @    @    @@  @   @
        @   @  @   @    @    @   @   @  @
        @@@@    @@@   @@@@@  @   @    @@
        @
        @
    
    """)
    click.echo("Welcome to the Trustpoint Client Certificate Manager (tp-crt-mgr) v" + version +"!\n")
    3+3

@click.group()
def cli() -> None:
    asciiLogo


@cli.command()
@click.option('--otp', '-o', required=True, type=str, help='The OTP for provisioning.')
@click.option('--salt', '-s', required=True, type=str, help='The salt for provisioning.')
@click.option('--url', '-u', required=True, type=str, help='The url endpoint for provisioning.')
@click.option('--tpurl', '-t', required=False, type=str, help='The IP or domain address of the Trustpoint.')
@click.option('--uriext', '-e', required=False, type=str, help='The uri extension for obtaining the trust store.')
@click.option('--hexpass', '-p', required=False, type=str, help='The OTP for deriving the trust store key.')
@click.option('--hexsalt', '-z', required=False, type=str, help='The salt for deriving the trust store key.') # TODO: Analyze if OK to re-use or derive from main salt
def provision(otp: str, salt: str, url: str, tpurl :str ="127.0.0.1:5000", uriext: str ="", hexpass: str="", hexsalt: str="") -> None:
    """Provisions the Trustpoint-Client software."""
    try:
        _provision(otp, salt, url, tpurl, uriext, hexpass, hexsalt) # TODO: Quite a lot of parameters. Maybe better to pass an options list?
    except Exception as e:
        click.echo(f'Failed to provision the Trustpoint-Client.\n{e}')
        return
    click.echo('Successfully provisioned the Trustpoint-Client.')

@cli.command()
def logo() -> None:
    click.echo('The subcommand')
    drawAsciiLogo()

if __name__ == '__main__':
    cli()
