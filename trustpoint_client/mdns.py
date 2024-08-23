"""mDNS service to discover the Trustpoint server on the local network."""

import socket
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf


class TpServiceListener(ServiceListener):
    """Listener defining callback methods for mDNS service discovery."""

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f'Service {name} updated')

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f'Service {name} removed')

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        print(f'Service {name} added, service info: {info}')
        if (name.startswith('trustpoint')):
            print(f'Trustpoint detected at {socket.inet_ntoa(info.addresses[0])}:{info.port}')

def find():
    """CLI command for an mDNS service discovery."""
    print('mDNS is not secure! Anyone on the network may pretend to be a Trustpoint server.')
    zeroconf = Zeroconf()
    listener = TpServiceListener()
    browser = ServiceBrowser(zeroconf, '_http._tcp.local.', listener)
    try:
        input("Press enter to exit...\n\n")
    finally:
        zeroconf.close()