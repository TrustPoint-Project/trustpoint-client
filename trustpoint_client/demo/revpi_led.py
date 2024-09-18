"""This module provides a simple interface to control the LEDs on a RevolutionPi Connect 4."""

try:
    import revpimodio2
except ImportError:
    rpi = None
    print('revpimodio2 import failed, no LED demo')

from enum import IntEnum

# ruff: noqa: PLR2004 (disable magic value check for LED numbers)

class RevPiLEDColor(IntEnum):
    """Enum for the possible color values of the RevolutionPi Connect 4 LEDs."""
    OFF     = 0
    RED     = 1
    GREEN   = 2
    YELLOW  = 3
    BLUE    = 4
    MAGENTA = 5
    CYAN    = 6
    WHITE   = 7


def set_led(i: int, color: RevPiLEDColor) -> None:
    """Turns the specified RevPi 4 LED to the specified color."""
    if not rpi:
        return

    if i < 1 or i > 5:
        return  # RevolutionPi Connect 4 has 5 RGB LEDs

    if i == 1:
        rpi.core.A1 = color

    if i == 2:
        rpi.core.A2 = color

    if i == 3:
        rpi.core.A3 = color

    if i == 4:
        rpi.core.A4 = color

    if i == 5:
        rpi.core.A5 = color


def clear(color: RevPiLEDColor = RevPiLEDColor.OFF) -> None:
    """Turns all RevPi LEDs to the specified color, off by default."""
    if not rpi:
        return

    rpi.core.A1 = color
    rpi.core.A2 = color
    rpi.core.A3 = color
    rpi.core.A4 = color
    rpi.core.A5 = color


rainbow_counter: int = 7


def rainbow_step() -> None:
    """Draws a rainbow to LEDs A3-A5. Each call advances it by one step."""
    if not rpi:
        return
    global rainbow_counter
    rainbow_counter -= 1
    if rainbow_counter == 0:
        rainbow_counter = 6
    smap = (5, 4, 6, 2, 3, 1)  # magenta, blue, cyan, green, yellow, red
    rpi.core.A3 = smap[(rainbow_counter + 2) % 6]
    rpi.core.A4 = smap[(rainbow_counter + 1) % 6]
    rpi.core.A5 = smap[(rainbow_counter + 0) % 6]

# noinspection PyBroadException
try:
    rpi = revpimodio2.RevPiModIO(autorefresh=True)
except Exception:   # noqa: BLE001
    rpi = None