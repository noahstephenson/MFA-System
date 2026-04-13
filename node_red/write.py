#!/usr/bin/env python

import sys

import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522


def main():
    reader = SimpleMFRC522()

    try:
        text = sys.argv[1] if len(sys.argv) > 1 else input("New data:")
        print("Now place your tag to write")
        reader.write(text)
        print("Written")
    finally:
        GPIO.cleanup()


if __name__ == "__main__":
    main()
