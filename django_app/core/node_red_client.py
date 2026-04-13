"""Centralized HTTP boundary for local Node-RED calls.

Accepted inbound variations:
- normalized Node-RED payloads that already use ok/error/message fields
- status-based fingerprint payloads such as fingerprint_api.py returns
- combined factor payloads with top-level rfid/fingerprint keys or nested factors

Everything is normalized into a small Django-side contract so the service layer
does not need to understand hardware-specific response quirks.
"""

from urllib.parse import urljoin

import requests
from django.conf import settings

_session = requests.Session()


def _headers():
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    shared_secret = getattr(settings, "NODE_RED_SHARED_SECRET", "").strip()
    if shared_secret:
        headers["X-API-Key"] = shared_secret
    return headers


def _base_error(sensor, error, message, *, raw=None, status_code=None, extra=None):
    payload = {
        "ok": False,
        "sensor": sensor,
        "error": error,
        "message": message,
        "status_code": status_code,
        "raw": raw,
    }
    if extra:
        payload.update(extra)
    return payload


def _request_json(method, path, *, payload=None):
    url = urljoin(f"{settings.NODE_RED_BASE_URL}/", path.lstrip("/"))
    try:
        response = _session.request(
            method,
            url,
            json=payload,
            headers=_headers(),
            timeout=getattr(settings, "NODE_RED_TIMEOUT", 5),
        )
    except requests.Timeout:
        return {
            "ok": False,
            "error": "timeout",
            "message": "Node-RED request timed out.",
            "status_code": None,
            "raw": None,
        }
    except requests.RequestException as exc:
        return {
            "ok": False,
            "error": "connection_error",
            "message": f"Node-RED request failed: {exc}",
            "status_code": None,
            "raw": None,
        }

    try:
        data = response.json()
    except ValueError:
        return {
            "ok": False,
            "error": "invalid_json",
            "message": "Node-RED returned invalid JSON.",
            "status_code": response.status_code,
            "raw": response.text,
        }

    if not isinstance(data, dict):
        return {
            "ok": False,
            "error": "invalid_json",
            "message": "Node-RED returned a JSON payload that was not an object.",
            "status_code": response.status_code,
            "raw": data,
        }

    if response.status_code >= 400:
        return {
            "ok": False,
            "error": str(data.get("error") or data.get("status") or "http_error"),
            "message": data.get("message") or f"Node-RED returned HTTP {response.status_code}.",
            "status_code": response.status_code,
            "raw": data,
        }

    return {
        "ok": True,
        "status_code": response.status_code,
        "data": data,
        "raw": data,
    }


def _status_value(payload):
    return str(payload.get("status") or "").strip().lower()


def _finger_id_value(payload):
    finger_id = payload.get("finger_id")
    if finger_id is None:
        finger_id = payload.get("id")
    if isinstance(finger_id, str):
        finger_id = finger_id.strip()
        if finger_id.isdigit():
            return int(finger_id)
    return finger_id


def _normalize_rfid_payload(payload):
    if not isinstance(payload, dict):
        return _base_error("rfid", "invalid_payload", "RFID payload was missing.", raw=payload)

    uid = payload.get("uid") or payload.get("identifier") or payload.get("card_id") or payload.get("id")
    status = _status_value(payload)
    ok_value = payload.get("ok")
    success = bool(ok_value) if ok_value is not None else status in {
        "ok",
        "success",
        "found",
        "read",
        "scanned",
    }

    if success and uid:
        return {
            "ok": True,
            "sensor": "rfid",
            "uid": str(uid),
            "message": str(payload.get("message") or ""),
            "raw": payload,
        }

    return _base_error(
        "rfid",
        str(payload.get("error") or status or "invalid_payload"),
        payload.get("message") or "RFID result did not include a usable UID.",
        raw=payload,
    )


def _normalize_fingerprint_payload(payload):
    if not isinstance(payload, dict):
        return _base_error(
            "fingerprint",
            "invalid_payload",
            "Fingerprint payload was missing.",
            raw=payload,
            extra={"matched": False},
        )

    status = _status_value(payload)
    matched = payload.get("matched")
    if matched is None and status in {"found", "matched", "verified", "success"}:
        matched = True
    if matched is None and status in {"not_found", "not_matched", "no_match", "failed"}:
        matched = False

    finger_id = _finger_id_value(payload)
    confidence = payload.get("confidence")

    if matched is True and finger_id is not None:
        return {
            "ok": True,
            "sensor": "fingerprint",
            "matched": True,
            "finger_id": finger_id,
            "confidence": confidence,
            "message": str(payload.get("message") or ""),
            "raw": payload,
        }

    if matched is False:
        return _base_error(
            "fingerprint",
            str(payload.get("error") or status or "not_matched"),
            payload.get("message") or "Fingerprint not matched.",
            raw=payload,
            extra={"matched": False},
        )

    return _base_error(
        "fingerprint",
        str(payload.get("error") or status or "invalid_payload"),
        payload.get("message") or "Fingerprint result did not include a usable finger ID.",
        raw=payload,
        extra={"matched": False},
    )


def _normalize_enroll_payload(payload):
    if not isinstance(payload, dict):
        return _base_error(
            "fingerprint",
            "invalid_payload",
            "Fingerprint enroll payload was missing.",
            raw=payload,
        )

    status = _status_value(payload)
    finger_id = _finger_id_value(payload)
    ok_value = payload.get("ok")
    success = bool(ok_value) if ok_value is not None else status in {"enrolled", "success", "stored"}

    if success and finger_id is not None:
        return {
            "ok": True,
            "sensor": "fingerprint",
            "finger_id": finger_id,
            "message": str(payload.get("message") or ""),
            "raw": payload,
        }

    return _base_error(
        "fingerprint",
        str(payload.get("error") or status or "invalid_payload"),
        payload.get("message") or "Fingerprint enroll response was invalid.",
        raw=payload,
    )


def read_rfid():
    response = _request_json("POST", "/api/rfid/read")
    if not response["ok"]:
        return _base_error(
            "rfid",
            response["error"],
            response["message"],
            raw=response["raw"],
            status_code=response["status_code"],
        )
    return _normalize_rfid_payload(response["data"])


def verify_fingerprint(payload):
    response = _request_json("POST", "/api/fingerprint/verify", payload=payload)
    if not response["ok"]:
        return _base_error(
            "fingerprint",
            response["error"],
            response["message"],
            raw=response["raw"],
            status_code=response["status_code"],
            extra={"matched": False},
        )
    return _normalize_fingerprint_payload(response["data"])


def enroll_fingerprint(payload):
    response = _request_json("POST", "/api/fingerprint/enroll", payload=payload)
    if not response["ok"]:
        return _base_error(
            "fingerprint",
            response["error"],
            response["message"],
            raw=response["raw"],
            status_code=response["status_code"],
        )
    return _normalize_enroll_payload(response["data"])


def collect_factors(payload):
    response = _request_json("POST", "/api/auth/collect-factors", payload=payload)
    if not response["ok"]:
        return {
            "ok": False,
            "error": response["error"],
            "message": response["message"],
            "rfid": _base_error("rfid", "missing", "RFID data was not collected."),
            "fingerprint": _base_error(
                "fingerprint",
                "missing",
                "Fingerprint data was not collected.",
                extra={"matched": False},
            ),
            "raw": response["raw"],
            "status_code": response["status_code"],
        }

    data = response["data"]
    factors = data.get("factors", {}) if isinstance(data.get("factors"), dict) else {}
    rfid_payload = data.get("rfid") or data.get("rfid_result") or factors.get("rfid") or {}
    fingerprint_payload = (
        data.get("fingerprint")
        or data.get("fingerprint_result")
        or factors.get("fingerprint")
        or {}
    )
    has_factor_sections = bool(rfid_payload or fingerprint_payload)
    explicit_ok = data.get("ok")
    overall_ok = bool(explicit_ok) if explicit_ok is not None else has_factor_sections

    return {
        "ok": overall_ok,
        "error": str(data.get("error") or ""),
        "message": str(data.get("message") or ""),
        "rfid": (
            _normalize_rfid_payload(rfid_payload)
            if rfid_payload
            else _base_error("rfid", "missing", "RFID data was not returned.")
        ),
        "fingerprint": (
            _normalize_fingerprint_payload(fingerprint_payload)
            if fingerprint_payload
            else _base_error(
                "fingerprint",
                "missing",
                "Fingerprint data was not returned.",
                extra={"matched": False},
            )
        ),
        "raw": data,
        "status_code": response["status_code"],
    }
