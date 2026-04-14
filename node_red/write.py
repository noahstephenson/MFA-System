#!/usr/bin/env python3

import argparse
import json
import os
import signal
import sys


class _WriteTimeoutError(TimeoutError):
    pass


def _timeout_handler(_signum, _frame):
    raise _WriteTimeoutError()


def _emit(payload):
    print(json.dumps(payload, separators=(",", ":")))


def _error_payload(error, message, **extra):
    payload = {
        "ok": False,
        "sensor": "rfid",
        "error": error,
        "message": message,
    }
    payload.update(extra)
    return payload


def _parse_args():
    parser = argparse.ArgumentParser(description="Write one value to an RFID tag and emit JSON.")
    parser.add_argument("text", nargs="?", help="Value to write onto the RFID tag.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Seconds to wait for a tag before returning a timeout error. Use 0 to wait forever.",
    )
    return parser.parse_args()


def _write_once(text, timeout_seconds):
    if not text:
        return _error_payload("invalid_input", "A tag value is required.", written=False)

    try:
        import RPi.GPIO as GPIO
        from mfrc522 import SimpleMFRC522
    except Exception as exc:
        return _error_payload(
            "dependency_error",
            f"RFID dependencies are unavailable: {exc}",
            written=False,
        )

    reader = None
    previous_handler = None
    timer_enabled = bool(timeout_seconds and timeout_seconds > 0 and os.name != "nt")
    try:
        reader = SimpleMFRC522()
        if timer_enabled:
            previous_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.setitimer(signal.ITIMER_REAL, timeout_seconds)

        reader.write(text)
        return {
            "ok": True,
            "sensor": "rfid",
            "written": True,
            "data": text,
            "message": "",
        }
    except _WriteTimeoutError:
        return _error_payload("timeout", "RFID write timed out.", written=False, data=text)
    except Exception as exc:
        return _error_payload(
            "hardware_error",
            f"RFID write failed: {exc}",
            written=False,
            data=text,
        )
    finally:
        if timer_enabled:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if previous_handler is not None:
                restore_handler = previous_handler.value if hasattr(previous_handler, "value") else previous_handler
                signal.signal(signal.SIGALRM, restore_handler)
        if reader is not None:
            try:
                GPIO.cleanup()
            except Exception:
                pass


def main():
    args = _parse_args()
    payload = _write_once(args.text, args.timeout)
    _emit(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
