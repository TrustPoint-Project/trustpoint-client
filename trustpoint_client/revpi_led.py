try:
    import revpimodio2
except ImportError:
    rpi = None
from enum import IntEnum


class RevPiLEDColor(IntEnum):
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
    if not rpi: return
    if i < 1 or i > 5: return  # RevolutionPi Connect 4 has 5 RGB LEDs
    if i == 1: rpi.core.A1 = color
    if i == 2: rpi.core.A2 = color
    if i == 3: rpi.core.A3 = color
    if i == 4: rpi.core.A4 = color
    if i == 5: rpi.core.A5 = color


def clear(color: RevPiLEDColor = RevPiLEDColor.OFF) -> None:
    """Turns all RevPi LEDs to the specified color, off by default."""
    if not rpi: return
    rpi.core.A1 = color
    rpi.core.A2 = color
    rpi.core.A3 = color
    rpi.core.A4 = color
    rpi.core.A5 = color


rainbowCounter: int = 7


def rainbow_step() -> None:
    """Draws a rainbow to LEDs A3-A5. Each call advances it by one step."""
    if not rpi: return
    global rainbowCounter
    rainbowCounter -= 1
    if rainbowCounter == 0: rainbowCounter = 6
    smap = (5, 4, 6, 2, 3, 1)  # magenta, blue, cyan, green, yellow, red
    rpi.core.A3 = smap[(rainbowCounter + 2) % 6]
    rpi.core.A4 = smap[(rainbowCounter + 1) % 6]
    rpi.core.A5 = smap[(rainbowCounter + 0) % 6]


try:
    rpi = revpimodio2.RevPiModIO(autorefresh=True)
except Exception:
    rpi = None
