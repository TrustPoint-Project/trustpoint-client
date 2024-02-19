import trustpoint_client.trustpoint_client as tc
import trustpoint_client.revpi_led as led

# callback functionality so that some external process can be optionally triggered after part of provisioning is complete
def testCallback(a :tc.ProvisioningState):
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
