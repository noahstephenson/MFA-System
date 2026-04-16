#!/usr/bin/env python3

import argparse
import json
import sys
import time


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


def _success_payload(tag_id, text):
    uid = _normalize_uid(tag_id)
    return {
        "ok": True,
        "sensor": "rfid",
        "uid": uid,
        "message": "",
        "tag_text": text.strip(),
        "uid_decimal": str(tag_id),
    }


def _normalize_uid(tag_id):
    try:
        numeric_tag_id = int(tag_id)
    except (TypeError, ValueError):
        return str(tag_id).strip().upper()

    hex_uid = format(numeric_tag_id, "X")
    if len(hex_uid) % 2:
        hex_uid = f"0{hex_uid}"
    return hex_uid.upper()


def _parse_args():
    parser = argparse.ArgumentParser(description="Read one RFID tag and emit JSON.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Seconds to wait for a card before returning a timeout error. Use 0 to wait forever.",
    )
    return parser.parse_args()


def _read_once(timeout_seconds):
    try:
        import RPi.GPIO as GPIO
        from mfrc522 import SimpleMFRC522
    except Exception as exc:
        return _error_payload(
            "dependency_error",
            f"RFID dependencies are unavailable: {exc}",
        )

    reader = None
    deadline = time.monotonic() + timeout_seconds if timeout_seconds and timeout_seconds > 0 else None
    try:
        reader = SimpleMFRC522()
        while True:
            tag_id, text = reader.read_no_block()
            if tag_id:
                return _success_payload(tag_id, text or "")
            if deadline is not None and time.monotonic() >= deadline:
                return _error_payload("timeout", "RFID read timed out.")
            time.sleep(0.1)
    except Exception as exc:
        return _error_payload("hardware_error", f"RFID read failed: {exc}")
    finally:
        if reader is not None:
            try:
                GPIO.cleanup()
            except Exception:
                pass


def main():
    args = _parse_args()
    payload = _read_once(args.timeout)
    _emit(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
