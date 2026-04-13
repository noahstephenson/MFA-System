#!/usr/bin/env python

# SPDX-FileCopyrightText: 2021 ladyada for Adafruit Industries
# SPDX-License-Identifier: MIT

import time

import adafruit_fingerprint
import serial
from flask import Flask, jsonify, request

uart = serial.Serial("/dev/serial0", baudrate=57600, timeout=1)
finger = adafruit_fingerprint.Adafruit_Fingerprint(uart)

app = Flask(__name__)


def get_fingerprint():
    """Get a fingerprint image, template it, and search."""
    print("Waiting for image...")
    while finger.get_image() != adafruit_fingerprint.OK:
        pass

    print("Templating...")
    if finger.image_2_tz(1) != adafruit_fingerprint.OK:
        return False

    print("Searching...")
    if finger.finger_search() != adafruit_fingerprint.OK:
        return False

    return True


def enroll_finger(location):
    """Enroll a fingerprint at a given ID (location)."""
    for fingerimg in range(1, 3):
        prompt = (
            "Place finger on sensor..."
            if fingerimg == 1
            else "Place same finger again..."
        )
        print(prompt, end="")

        while True:
            result = finger.get_image()
            if result == adafruit_fingerprint.OK:
                print("Image taken")
                break
            if result == adafruit_fingerprint.NOFINGER:
                print(".", end="")
            else:
                print("Error:", result)
                return False

        print("Templating...", end="")
        result = finger.image_2_tz(fingerimg)
        if result != adafruit_fingerprint.OK:
            print("Templating failed:", result)
            return False

        if fingerimg == 1:
            print("Remove finger")
            time.sleep(1)
            while finger.get_image() != adafruit_fingerprint.NOFINGER:
                pass

    print("Creating model...", end="")
    if finger.create_model() != adafruit_fingerprint.OK:
        print("Model creation failed")
        return False

    print(f"Storing model #{location}...", end="")
    if finger.store_model(location) != adafruit_fingerprint.OK:
        print("Storing failed")
        return False

    return True


def reset_library():
    """Erase all fingerprints from the sensor."""
    if finger.empty_library() == adafruit_fingerprint.OK:
        return {"status": "success", "message": "Library cleared"}
    return {"status": "failed", "message": "Failed to reset library"}


@app.route("/scan", methods=["GET"])
def api_scan():
    if get_fingerprint():
        return jsonify(
            {
                "status": "found",
                "finger_id": finger.finger_id,
                "confidence": finger.confidence,
            }
        )
    return jsonify({"status": "not_found"})


@app.route("/enroll", methods=["POST"])
def api_enroll():
    try:
        location = int(request.json["id"])
    except Exception:
        return jsonify({"status": "error", "message": "missing id"}), 400

    if enroll_finger(location):
        return jsonify({"status": "enrolled", "id": location})
    return jsonify({"status": "failed", "id": location})


@app.route("/delete", methods=["POST"])
def api_delete():
    try:
        location = int(request.json["id"])
    except Exception:
        return jsonify({"status": "error", "message": "missing id"}), 400

    if finger.delete_model(location) == adafruit_fingerprint.OK:
        return jsonify({"status": "deleted", "id": location})
    return jsonify({"status": "failed", "id": location})


@app.route("/reset", methods=["POST"])
def api_reset():
    return jsonify(reset_library())


def main():
    app.run(host="0.0.0.0", port=5000)


if __name__ == "__main__":
    main()
