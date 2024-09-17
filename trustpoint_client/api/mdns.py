"""mDNS service to discover the Trustpoint server on the local network."""

import socket
import sys
import threading
from trustpoint_client.api.zero_touch_aoki import aoki_onboarding
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

exit_event = threading.Event()

class TpServiceListener(ServiceListener):
    """Listener defining callback methods for mDNS service discovery."""

    do_aoki_onboarding = False

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f'Service {name} updated')

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f'Service {name} removed')

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        print(f'Service {name} added')  #, service info: {info}')
        if (name.startswith('trustpoint')):
            print(f'Trustpoint detected at {socket.inet_ntoa(info.addresses[0])}:{info.port}')
            if (self.do_aoki_onboarding):
                if aoki_onboarding(socket.inet_ntoa(info.addresses[0]), info.port):
                    print('AOKI onboarding successful!')
                    exit_event.set()

def wait_for_user_input():
    try:
        input("Press enter to exit...\n\n")
    finally:
        exit_event.set()

def find_services(zero_touch: bool = False):
    """CLI command for an mDNS service discovery and zero-touch onboarding."""
    print('mDNS is not secure! Anyone on the network may pretend to be a Trustpoint server.')
    zeroconf = Zeroconf()
    listener = TpServiceListener()
    listener.do_aoki_onboarding = zero_touch
    browser = ServiceBrowser(zeroconf, '_http._tcp.local.', listener)

    input_thread = threading.Thread(target=wait_for_user_input, daemon=True)
    input_thread.start()

    exit_event.wait()
    zeroconf.close()
