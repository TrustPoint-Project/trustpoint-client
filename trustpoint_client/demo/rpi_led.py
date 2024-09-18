"""This module provides a simple interface to control the LEDs on a Raspberry Pi."""

PIN_RED = 23
PIN_YELLOW = 24
PIN_GREEN = 25

COLOR_RED = 1
COLOR_YELLOW = 2
COLOR_GREEN = 3


try:
    from RPi import GPIO

    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN_RED, GPIO.OUT)
    GPIO.setup(PIN_YELLOW, GPIO.OUT)
    GPIO.setup(PIN_GREEN, GPIO.OUT)

    rpi = True

except ImportError:
    rpi = False
    print('RPi.GPIO import failed, no LED demo')


def clear() -> None:
    """Clears the LED color."""
    if not rpi:
        return
    GPIO.output(PIN_RED, GPIO.LOW)
    GPIO.output(PIN_YELLOW, GPIO.LOW)
    GPIO.output(PIN_GREEN, GPIO.LOW)


def set_led(i: int, color: int) -> None:
    """Sets the LED color."""
    if not rpi:
        return

    if i == COLOR_RED:
        GPIO.output(PIN_RED, GPIO.HIGH if color else GPIO.LOW)

    if i == COLOR_YELLOW:
        GPIO.output(PIN_YELLOW, GPIO.HIGH if color else GPIO.LOW)

    if i == COLOR_GREEN:
        GPIO.output(PIN_GREEN, GPIO.HIGH if color else GPIO.LOW)