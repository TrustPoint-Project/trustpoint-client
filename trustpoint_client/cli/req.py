import click


@click.group
def req():
    """Request a new certificate or trust-store."""


@req.group(name='cert')
def req_cert():
    """Request a new certificate."""


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

@req_cert.command(name='generic')
def req_cert_generic():
    """Request a new generic certificate."""


@req_cert.command(name='tls-client-cert')
def req_tls_client_cert():
    """Request a new tls client certificate."""


@req_cert.command(name='tls-server-cert')
def req_tls_server_cert():
    """Request a new tls server certificate."""


@req_cert.command(name='mqtt-client-cert')
def req_mqtt_client_cert():
    """Request a new mqtt client certificate."""


@req_cert.command(name='mqtt-server-cert')
def req_mqtt_server_cert():
    """Request a new mqtt server certificate."""


@req_cert.command(name='opc-ua-client-cert')
def req_opc_ua_client_cert():
    """Request a new opc ua client certificate."""


@req_cert.command(name='opc-ua-server-cert')
def req_opc_ua_server_cert():
    """Request a new opc ua server certificate."""


@req.command(name='ca-certs')
def req_ca_certs():
    """Requests the certificate chain for the issuing ca in use."""


@req.command(name='trust-store')
def req_trust_store():
    """Request a trust-store."""