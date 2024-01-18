import click
from os.path import exists
import requests
import hashlib
import hmac
import trustpoint_client.key as key
import datetime
from enum import IntEnum

class ProvisioningState(IntEnum):
    NOT_PROVISIONED =  0
    HAS_TRUSTSTORE  =  1
    HAS_LDEVID      =  2
    HAS_CERT_CHAIN  =  3
    ERROR           = -1

def getTrustStore(tpurl :str ="127.0.0.1:5000", uriext: str ="", hexpass: str="", hexsalt: str="") -> bool:
    click.echo('Retrieving Trustpoint Trust Store')
    if exists("trust-store.pem"): # TODO it might be a security risk to have this (write) accessible on the filesystem
        click.echo('trust-store.pem file present locally')
        with open('trust-store.pem', 'rb') as certfile:
            certUnexpired = key.checkCertificateUnexpired(certfile.read())
            if certUnexpired: return True
    
    # Truststore file not present, obtain it
    click.echo('trust-store.pem missing, downloading from Trustpoint...')
    response = requests.get('https://' + tpurl + '/trust-point/rest/provision/trust-store/' + uriext, verify=False)
    if response.status_code != 200: raise Exception("Server returned HTTP code " + str(response.status_code))

    # DEBUG USE ONLY!!!
    # response.headers["hmac-signature"] = "fe411166f41436e81edd3303f74858979f01a993f98998891f4f8c514f0fe7b8" # (for content "It's a Truststore baby." with pass "abc" and salt "def")

    # TRUSTSTORE DOWNLOAD VERIFICATION
    verificationLevel: int = 0
    # Only allow for basic hash comparision verification if HMAC header is NOT included by Trustpoint AND hexpass is not provided
    if hexpass or "hmac-signature" in response.headers: verificationLevel = 1

    if verificationLevel == 1:
        # Full HMAC + PBKDF2 verification
        click.echo("Using PBKDF2-HMAC verification")
        if not "hmac-signature" in response.headers: raise Exception("HMAC signature header is required but missing in Trustpoint response headers.")
        if not hexpass: raise Exception("HMAC verification is required but --hexpass option was not provided.")
        pbkdf2_iter = 1000000 # TODO this should be an option or given by a trustpoint header with a reasonable minimum sanity check
        pkey = hashlib.pbkdf2_hmac('sha256', bytes(hexpass,'utf-8'), bytes(hexsalt,'utf-8'), pbkdf2_iter, dklen=32)
        h = hmac.new(pkey, response.content, hashlib.sha256)
        #click.echo(pkey.hex())
        click.echo("Computed HMAC: " + h.hexdigest())
        if not hmac.compare_digest(h.hexdigest(), response.headers["hmac-signature"]): raise Exception("Truststore HMAC signature header and computed HMAC do not match.")
    elif verificationLevel == 0:
        # Simple SHA3 hash display
        click.echo("Using simple hash verification")
        s = hashlib.sha3_256()
        s.update(response.content)
        hash = s.hexdigest()
        explicitVerificationBytes = 3 # how many bytes of the hash the admin has to explicitely enter for checking, TODO this should be determined by trustpoint
        if explicitVerificationBytes > 0:
            value = click.prompt("Please enter the first " + str(explicitVerificationBytes*2) + " characters of the trust store hash displayed by Trustpoint")
            if value != hash[:explicitVerificationBytes*2]: raise Exception("Downloaded and entered hash portion do not match.")
        click.echo("\nPLEASE VERIFY BELOW HASH AGAINST THAT DISPLAYED BY TRUSTPOINT\n")
        click.echo(hash)
        feedback = click.prompt("\nDo the hashes match EXACTLY? (y/n)")
        # TODO maybe consider adding https://github.com/ansemjo/randomart (not as lib, but as src)
        if feedback != 'Y' and feedback != 'y': raise Exception("Hash does not match the one displayed by Trustpoint, aborting.")
    else:
        raise Exception("Invalid verification level.")
    
    with open('trust-store.pem', 'wb') as f: # write downloaded truststore to FS
        f.write(response.content)
    
    click.echo('Thank you, the trust store was downloaded successfully.')
    return True


def requestLDevID(tpurl: str, otp: str, salt: str, url: str):
    click.echo("Generating private key and CSR for LDevID")
    csr = key.generateNewKeyAndCSR()
    # Let Trustpoint sign our CSR (auth via OTP and salt as username via HTTP basic auth)
    click.echo("Uploading CSR to Trustpoint for signing")

    files = {'file': csr}
    crt = requests.post('https://' + tpurl + '/trust-point/rest/provision/ldevid/' + url, auth=(salt, otp), files=files, verify='trust-store.pem')
    if crt.status_code != 200: raise Exception("Server returned HTTP code " + str(crt.status_code))

    with open('ldevid.pem', 'wb') as f: # write downloaded certificate to FS
        f.write(crt.content)
        click.echo("LDevID certificate downloaded successfully")


def requestCertChain(tpurl: str) -> None:
    click.echo("Downloading LDevID certificate chain")
    chain = requests.get('https://' + tpurl + '/trust-point/rest/provision/ldevid/cert-chain', verify='trust-store.pem', cert=('ldevid.pem','ldevid-private-key.pem'))
    if chain.status_code != 200: raise Exception("Server returned HTTP code " + str(chain.status_code))

    with open('ldevid-certificate-chain.pem', 'wb') as f: # write downloaded trust chain to FS
        f.write(chain.content)
        click.echo("Certificate chain downloaded successfully")


def provision(otp: str, salt: str, url: str, tpurl :str, uriext: str, hexpass: str, hexsalt: str, callback=None) -> None:
    """Provisions the Trustpoint-Client software."""
    click.echo('Provisioning client...')
    click.echo('Current system time is ' + datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    try:
        # Step 1: Get trustpoint Trust Store
        res = getTrustStore(tpurl, uriext, hexpass, hexsalt)
        if callback: callback(ProvisioningState.HAS_TRUSTSTORE)
        # Step 2: Request locally significant device identifier (LDevID)
        requestLDevID(tpurl, otp, salt, url)
        if callback: callback(ProvisioningState.HAS_LDEVID)
        # Step 3: Download LDevID Certificate chain
        requestCertChain(tpurl)
        if callback: callback(ProvisioningState.HAS_CERT_CHAIN)
    except:
        if callback: callback(ProvisioningState.ERROR)
        raise
