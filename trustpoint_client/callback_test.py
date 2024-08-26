"""Module to test the callback functionality of the trustpoint_client module.

Sets LEDs on the RevPi Connect 4 to indicate the state of the provisioning process.
"""

import trustpoint_client.api as tc
import trustpoint_client.revpi_led as led
import trustpoint_client.rpi_led as rpi


# optional callback functionality so that an external process can be triggered after part of provisioning is complete
def test_callback_revpi(a: tc.ProvisioningState) -> None:
    """Sets LEDs on the RevPi Connect 4 to indicate the state of the provisioning process."""
    led.clear()
    if a == tc.ProvisioningState.ERROR:
        led.set_led(3, led.RevPiLEDColor.RED)
        led.set_led(4, led.RevPiLEDColor.RED)
        led.set_led(5, led.RevPiLEDColor.RED)
    elif a == tc.ProvisioningState.NOT_PROVISIONED:
        led.set_led(3, led.RevPiLEDColor.RED)
    elif a == tc.ProvisioningState.HAS_TRUSTSTORE:
        led.set_led(4, led.RevPiLEDColor.YELLOW)
    elif a == tc.ProvisioningState.HAS_LDEVID:
        led.set_led(5, led.RevPiLEDColor.GREEN)
    elif a == tc.ProvisioningState.HAS_CERT_CHAIN:
        led.set_led(3, led.RevPiLEDColor.GREEN)
        led.set_led(4, led.RevPiLEDColor.GREEN)
        led.set_led(5, led.RevPiLEDColor.GREEN)


def test_callback(a: tc.ProvisioningState) -> None:
    """Sets LEDs on the Raspberry Pi to indicate the state of the provisioning process."""
    rpi.clear()
    if a == tc.ProvisioningState.ERROR:
        rpi.set_led(1, True)
        rpi.set_led(2, True)
    elif a == tc.ProvisioningState.NOT_PROVISIONED:
        rpi.set_led(1, True)
    elif a == tc.ProvisioningState.HAS_TRUSTSTORE:
        rpi.set_led(2, True)
    elif a == tc.ProvisioningState.HAS_LDEVID:
        rpi.set_led(2, True)
        rpi.set_led(3, True)
    elif a == tc.ProvisioningState.HAS_CERT_CHAIN:
        rpi.set_led(3, True)
