import argparse

import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522


def write_tag(text):
    reader = SimpleMFRC522()
    try:
        print("Now place your tag to write")
        reader.write(text)
        print("Written")
    finally:
        GPIO.cleanup()


def main():
    parser = argparse.ArgumentParser(description="Write text to an RFID tag with the MFRC522 sensor.")
    parser.add_argument("text", nargs="?", help="Text to write to the RFID tag.")
    args = parser.parse_args()

    text = args.text if args.text is not None else input("New data: ")
    write_tag(text)


if __name__ == "__main__":
    main()
