"""Module to test the callback functionality of the trustpoint_client module.

Sets LEDs on the RevPi Connect 4 to indicate the state of the provisioning process.
"""

import trustpoint_client.revpi_led as led
import trustpoint_client.trustpoint_client as tc


# optional callback functionality so that an external process can be triggered after part of provisioning is complete
def test_callback(a: tc.ProvisioningState) -> None:
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
