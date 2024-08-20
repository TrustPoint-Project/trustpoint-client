
PIN_RED = 23
PIN_YELLOW = 24
PIN_GREEN = 25

try:
    import RPi.GPIO as GPIO

    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN_RED, GPIO.OUT)
    GPIO.setup(PIN_YELLOW, GPIO.OUT)
    GPIO.setup(PIN_GREEN, GPIO.OUT)

    rpi = True

except ImportError:
    rpi = False

def clear():
    if not rpi: return
    GPIO.output(PIN_RED, GPIO.LOW)
    GPIO.output(PIN_YELLOW, GPIO.LOW)
    GPIO.output(PIN_GREEN, GPIO.LOW)

def set_led(i, color):
    if not rpi: return
    if i == 1: GPIO.output(PIN_RED, GPIO.HIGH if color else GPIO.LOW)
    if i == 2: GPIO.output(PIN_YELLOW, GPIO.HIGH if color else GPIO.LOW)
    if i == 3: GPIO.output(PIN_GREEN, GPIO.HIGH if color else GPIO.LOW)