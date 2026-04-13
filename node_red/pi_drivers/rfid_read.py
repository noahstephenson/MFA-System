#!/usr/bin/env python

import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522


def main():
    reader = SimpleMFRC522()

    try:
        tag_id, text = reader.read()
        print(tag_id)
        print(text)
    finally:
        GPIO.cleanup()


if __name__ == "__main__":
    main()
