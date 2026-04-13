import argparse

import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522


def read_tag():
    reader = SimpleMFRC522()
    try:
        tag_id, text = reader.read()
        print(tag_id)
        print(text)
        return tag_id, text
    finally:
        GPIO.cleanup()


def main():
    parser = argparse.ArgumentParser(description="Read an RFID tag with the MFRC522 sensor.")
    parser.parse_args()
    read_tag()


if __name__ == "__main__":
    main()
