#!/usr/bin/env python3

import time


def _error_payload(error, message, *, matched=False, **extra):
    payload = {
        "ok": False,
        "sensor": "fingerprint",
        "error": error,
        "message": message,
        "matched": matched,
    }
    payload.update(extra)
    return payload


def _status_payload(status, message, **extra):
    payload = {
        "status": status,
        "message": message,
    }
    payload.update(extra)
    return payload


class FingerprintSensor:
    def __init__(self, *, port="/dev/serial0", baudrate=57600, serial_timeout=1):
        self.port = port
        self.baudrate = baudrate
        self.serial_timeout = serial_timeout
        self._uart = None
        self._finger = None
        self._lib = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        self.close()

    def connect(self):
        if self._finger is not None:
            return self._finger

        try:
            import adafruit_fingerprint
            import serial
        except Exception as exc:
            raise RuntimeError(f"Fingerprint dependencies are unavailable: {exc}") from exc

        try:
            self._uart = serial.Serial(
                self.port,
                baudrate=self.baudrate,
                timeout=self.serial_timeout,
            )
            self._finger = adafruit_fingerprint.Adafruit_Fingerprint(self._uart)
            self._lib = adafruit_fingerprint
        except Exception as exc:
            self.close()
            raise RuntimeError(f"Fingerprint sensor initialization failed: {exc}") from exc

        return self._finger

    def close(self):
        if self._uart is not None:
            try:
                self._uart.close()
            except Exception:
                pass
        self._uart = None
        self._finger = None
        self._lib = None

    def verify(self, *, timeout_seconds=20.0, poll_interval=0.2):
        finger = self.connect()
        lib = self._lib
        deadline = time.monotonic() + timeout_seconds if timeout_seconds and timeout_seconds > 0 else None

        while True:
            if deadline is not None and time.monotonic() >= deadline:
                return _error_payload("timeout", "Fingerprint verification timed out.")

            result = finger.get_image()
            if result == lib.OK:
                break
            if result == lib.NOFINGER:
                time.sleep(poll_interval)
                continue
            return _error_payload(
                "sensor_error",
                f"Fingerprint image capture failed: {self._code_name(result)}.",
            )

        result = finger.image_2_tz(1)
        if result != lib.OK:
            return _error_payload(
                "template_failed",
                f"Fingerprint templating failed: {self._code_name(result)}.",
            )

        result = finger.finger_search()
        if result == lib.OK:
            return {
                "ok": True,
                "sensor": "fingerprint",
                "matched": True,
                "finger_id": finger.finger_id,
                "confidence": finger.confidence,
                "message": "",
            }
        if result == getattr(lib, "NOTFOUND", None):
            return _error_payload("not_matched", "Fingerprint not matched.")
        return _error_payload(
            "search_failed",
            f"Fingerprint search failed: {self._code_name(result)}.",
        )

    def enroll(self, location, *, timeout_seconds=30.0, poll_interval=0.2):
        finger = self.connect()
        lib = self._lib
        deadline = time.monotonic() + timeout_seconds if timeout_seconds and timeout_seconds > 0 else None

        for fingerimg in range(1, 3):
            result = self._capture_image(deadline=deadline, poll_interval=poll_interval)
            if result is not None:
                return result

            result = finger.image_2_tz(fingerimg)
            if result != lib.OK:
                return _error_payload(
                    "template_failed",
                    f"Fingerprint templating failed: {self._code_name(result)}.",
                )

            if fingerimg == 1:
                time.sleep(1)
                while finger.get_image() != lib.NOFINGER:
                    if deadline is not None and time.monotonic() >= deadline:
                        return _error_payload("timeout", "Fingerprint enroll timed out.")
                    time.sleep(poll_interval)

        result = finger.create_model()
        if result != lib.OK:
            return _error_payload(
                "model_failed",
                f"Fingerprint model creation failed: {self._code_name(result)}.",
            )

        result = finger.store_model(location)
        if result != lib.OK:
            return _error_payload(
                "store_failed",
                f"Fingerprint storage failed: {self._code_name(result)}.",
            )

        return {
            "ok": True,
            "sensor": "fingerprint",
            "finger_id": int(location),
            "message": "",
        }

    def delete(self, location):
        finger = self.connect()
        result = finger.delete_model(location)
        if result == self._lib.OK:
            return {
                "ok": True,
                "sensor": "fingerprint",
                "finger_id": int(location),
                "message": "",
            }
        return _error_payload(
            "delete_failed",
            f"Fingerprint deletion failed: {self._code_name(result)}.",
            finger_id=int(location),
        )

    def reset(self):
        finger = self.connect()
        result = finger.empty_library()
        if result == self._lib.OK:
            return {
                "ok": True,
                "sensor": "fingerprint",
                "message": "Fingerprint library cleared.",
            }
        return _error_payload(
            "reset_failed",
            f"Fingerprint reset failed: {self._code_name(result)}.",
        )

    def verify_status_payload(self, *, timeout_seconds=20.0):
        payload = self.verify(timeout_seconds=timeout_seconds)
        if payload.get("ok"):
            return _status_payload(
                "found",
                payload.get("message", ""),
                finger_id=payload["finger_id"],
                confidence=payload.get("confidence"),
                ok=True,
                sensor="fingerprint",
                matched=True,
            )
        if payload.get("error") == "not_matched":
            return _status_payload(
                "not_found",
                payload.get("message", ""),
                ok=False,
                sensor="fingerprint",
                matched=False,
                error="not_matched",
            )
        return payload

    def _capture_image(self, *, deadline, poll_interval):
        finger = self._finger
        lib = self._lib
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                return _error_payload("timeout", "Fingerprint enroll timed out.")

            result = finger.get_image()
            if result == lib.OK:
                return None
            if result == lib.NOFINGER:
                time.sleep(poll_interval)
                continue
            return _error_payload(
                "sensor_error",
                f"Fingerprint image capture failed: {self._code_name(result)}.",
            )

    def _code_name(self, code):
        if self._lib is None:
            return str(code)

        names = {
            "OK",
            "NOFINGER",
            "PACKETRECIEVEERR",
            "IMAGEFAIL",
            "IMAGEMESS",
            "FEATUREFAIL",
            "INVALIDIMAGE",
            "NOTFOUND",
            "ENROLLMISMATCH",
            "BADLOCATION",
            "FLASHERR",
        }
        for name in names:
            if getattr(self._lib, name, object()) == code:
                return name.lower()
        return str(code)
