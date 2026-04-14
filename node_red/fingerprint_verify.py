#!/usr/bin/env python3

import argparse
import json
import sys

if __package__:
    from .fingerprint_sensor import FingerprintSensor
else:
    from fingerprint_sensor import FingerprintSensor


def _emit(payload):
    print(json.dumps(payload, separators=(",", ":")))


def _parse_args():
    parser = argparse.ArgumentParser(description="Verify one fingerprint and emit JSON.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Seconds to wait for a fingerprint before returning a timeout error. Use 0 to wait forever.",
    )
    parser.add_argument("--port", default="/dev/serial0", help="Fingerprint UART device.")
    parser.add_argument("--baudrate", type=int, default=57600, help="Fingerprint UART baud rate.")
    return parser.parse_args()


def main():
    args = _parse_args()
    try:
        with FingerprintSensor(port=args.port, baudrate=args.baudrate) as sensor:
            payload = sensor.verify(timeout_seconds=args.timeout)
    except Exception as exc:
        payload = {
            "ok": False,
            "sensor": "fingerprint",
            "matched": False,
            "error": "hardware_error",
            "message": str(exc),
        }

    _emit(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
