import click
from trustpoint_client.trustpoint_client import provision as _provision
import trustpoint_client.callback_test as cb

versionID = "0.1.0"

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
    """\b
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


@cli.command()
@click.option('--otp', '-o', required=True, type=str, help='The OTP for provisioning.')
@click.option('--salt', '-s', required=True, type=str, help='The salt for provisioning.')
@click.option('--url', '-u', required=True, type=str, help='The url endpoint for provisioning.')
@click.option('--tpurl', '-t', required=False, type=str, help='The IP or domain address of the Trustpoint.')
@click.option('--uriext', '-e', required=False, type=str, help='The uri extension for obtaining the trust store.')
@click.option('--tsotp', '-p', required=False, type=str, help='The OTP for deriving the trust store key.')
@click.option('--tssalt', '-z', required=False, type=str, help='The salt for deriving the trust store key.') # TODO: Analyze if OK to re-use or derive from main salt
@click.option('--sn', '-n', required=False, type=str, help='The serial number of the device.')
def provision(otp: str, salt: str, url: str, tpurl :str ="127.0.0.1:5000", uriext: str ="", tsotp: str="", tssalt: str="", sn: str="") -> None:
    """Provisions the Trustpoint-Client software."""
    try:
        _provision(otp, salt, url, tpurl, uriext, tsotp, tssalt, sn, cb.testCallback) # TODO: Quite a lot of parameters. Maybe better to pass an options list?
    except Exception as e:
        click.echo(f'Failed to provision the Trustpoint-Client.\n{e}')
        return
    click.echo('Successfully provisioned the Trustpoint-Client.')

# TODO perhaps consider ACME for renewal (is quite complex though)
@cli.command()
@click.option('--percentage','-p', required=False, type=int, help='The percentage of certificate lifetime after which renewal should be attempted.')
@click.option('--interval','-i', required=False, type=int, help='The interval in seconds how often to check for expiration')
def autorenew() -> None:
    """Monitors certificates for expiry and automatically requests new ones."""
    # Prerequisites: A currently valid LDevID and  Trustpoint server truststore
    
    pass

@cli.command()
def version() -> None:
    """Displays the version of Trustpoint-Client."""
    drawAsciiLogo()
    click.echo("Welcome to the Trustpoint Client Certificate Manager (tp-crt-mgr) v" + str(versionID) +"!\n")
    
if __name__ == '__main__':
    cli()
