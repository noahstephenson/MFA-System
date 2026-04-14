#!/usr/bin/env python3

import os

from flask import Flask, jsonify, request

if __package__:
    from .fingerprint_sensor import FingerprintSensor
else:
    from fingerprint_sensor import FingerprintSensor

app = Flask(__name__)


def _json_body():
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        return payload
    return {}


def _timeout_value(payload, *, default):
    value = payload.get("timeout_seconds", default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _sensor():
    return FingerprintSensor(
        port=os.environ.get("FINGERPRINT_SERIAL_PORT", "/dev/serial0"),
        baudrate=int(os.environ.get("FINGERPRINT_BAUDRATE", "57600")),
    )


def _http_status(payload):
    if payload.get("ok"):
        return 200
    if payload.get("error") == "not_matched":
        return 200
    if payload.get("error") == "timeout":
        return 504
    return 503


@app.route("/health", methods=["GET"])
def api_health():
    return jsonify({"ok": True, "service": "fingerprint_api", "message": ""})


@app.route("/verify", methods=["POST"])
def api_verify():
    payload = _json_body()
    timeout_seconds = _timeout_value(payload, default=20.0)
    try:
        with _sensor() as sensor:
            response = sensor.verify(timeout_seconds=timeout_seconds)
    except Exception as exc:
        response = {
            "ok": False,
            "sensor": "fingerprint",
            "matched": False,
            "error": "hardware_error",
            "message": str(exc),
        }
    return jsonify(response), _http_status(response)


@app.route("/scan", methods=["GET", "POST"])
def api_scan():
    payload = _json_body()
    timeout_seconds = _timeout_value(payload, default=20.0)
    try:
        with _sensor() as sensor:
            response = sensor.verify_status_payload(timeout_seconds=timeout_seconds)
    except Exception as exc:
        response = {
            "ok": False,
            "sensor": "fingerprint",
            "matched": False,
            "error": "hardware_error",
            "message": str(exc),
        }
    return jsonify(response), _http_status(response)


@app.route("/enroll", methods=["POST"])
def api_enroll():
    payload = _json_body()
    try:
        location = int(payload["id"])
    except Exception:
        return jsonify({"ok": False, "error": "missing_id", "message": "missing id"}), 400

    timeout_seconds = _timeout_value(payload, default=30.0)
    try:
        with _sensor() as sensor:
            response = sensor.enroll(location, timeout_seconds=timeout_seconds)
    except Exception as exc:
        response = {
            "ok": False,
            "sensor": "fingerprint",
            "error": "hardware_error",
            "message": str(exc),
        }
    return jsonify(response), _http_status(response)


@app.route("/delete", methods=["POST"])
def api_delete():
    payload = _json_body()
    try:
        location = int(payload["id"])
    except Exception:
        return jsonify({"ok": False, "error": "missing_id", "message": "missing id"}), 400

    try:
        with _sensor() as sensor:
            response = sensor.delete(location)
    except Exception as exc:
        response = {
            "ok": False,
            "sensor": "fingerprint",
            "error": "hardware_error",
            "message": str(exc),
        }
    return jsonify(response), _http_status(response)


@app.route("/reset", methods=["POST"])
def api_reset():
    try:
        with _sensor() as sensor:
            response = sensor.reset()
    except Exception as exc:
        response = {
            "ok": False,
            "sensor": "fingerprint",
            "error": "hardware_error",
            "message": str(exc),
        }
    return jsonify(response), _http_status(response)


def main():
    port = int(os.environ.get("FINGERPRINT_API_PORT", "5000"))
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
