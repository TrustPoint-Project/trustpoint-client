"""Module to test the callback functionality of the trustpoint_client module.

Sets LEDs on the RevPi Connect 4 to indicate the state of the provisioning process.
"""

import trustpoint_client.demo.revpi_led as led
import trustpoint_client.demo.rpi_led as rpi

from trustpoint_client.api.provision import ProvisioningState


# optional callback functionality so that an external process can be triggered after part of provisioning is complete
def callback_demo_leds_revpi(a: ProvisioningState) -> None:
    """Sets LEDs on the RevPi Connect 4 to indicate the state of the provisioning process."""
    led.clear()
    if a == ProvisioningState.ERROR:
        led.set_led(3, led.RevPiLEDColor.RED)
        led.set_led(4, led.RevPiLEDColor.RED)
        led.set_led(5, led.RevPiLEDColor.RED)
    elif a == ProvisioningState.NO_TRUST:
        led.set_led(3, led.RevPiLEDColor.RED)
    elif a == ProvisioningState.ONESIDED_TRUST:
        led.set_led(4, led.RevPiLEDColor.YELLOW)
    elif a == ProvisioningState.MUTUAL_TRUST:
        led.set_led(5, led.RevPiLEDColor.GREEN)

def callback_demo_leds_pi(a: ProvisioningState) -> None:
    """Sets LEDs on the Raspberry Pi to indicate the state of the provisioning process."""
    rpi.clear()
    if a == ProvisioningState.ERROR:
        rpi.set_led(1, True)
        rpi.set_led(2, True)
    elif a == ProvisioningState.NO_TRUST:
        rpi.set_led(1, True)
    elif a == ProvisioningState.ONESIDED_TRUST:
        rpi.set_led(2, True)
    elif a == ProvisioningState.MUTUAL_TRUST:
        rpi.set_led(3, True)

def callback_demo_print(a: ProvisioningState) -> None:
    """Printout demo for testing callback functionality"""
    state_str = 'Unknown state'

    if a == ProvisioningState.ERROR:
        state_str = 'ERROR'
    elif a == ProvisioningState.NO_TRUST:
        state_str = 'NO_TRUST'
    elif a == ProvisioningState.ONESIDED_TRUST:
        state_str = 'ONESIDED_TRUST'
    elif a == ProvisioningState.MUTUAL_TRUST:
        state_str = 'MUTUAL_TRUST'

    print(f'Provisioning State callback: [{state_str}]')

def callback_demo(a: ProvisioningState) -> None:
    callback_demo_print(a)
    callback_demo_leds_pi(a)
    #callback_demo_leds_revpi(a)