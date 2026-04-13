import json
from unittest.mock import patch

import requests
from django.test import SimpleTestCase, override_settings

from .. import node_red_client


class FakeResponse:
    def __init__(self, *, status_code=200, payload=None, text="", json_error=None):
        self.status_code = status_code
        self._payload = payload
        self._json_error = json_error
        self.text = text or (json.dumps(payload) if payload is not None else "")

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._payload


@override_settings(NODE_RED_BASE_URL="http://127.0.0.1:1880", NODE_RED_TIMEOUT=2)
class NodeRedClientTests(SimpleTestCase):
    @patch("core.node_red_client._session.request")
    def test_read_rfid_success_case(self, mock_request):
        mock_request.return_value = FakeResponse(
            payload={"ok": True, "sensor": "rfid", "uid": "04A1B2C3D4"}
        )

        result = node_red_client.read_rfid()

        self.assertTrue(result["ok"])
        self.assertEqual(result["uid"], "04A1B2C3D4")
        self.assertEqual(result["message"], "")

    @patch("core.node_red_client._session.request")
    def test_verify_fingerprint_accepts_status_based_pi_response(self, mock_request):
        mock_request.return_value = FakeResponse(
            payload={"status": "found", "finger_id": 4, "confidence": 87}
        )

        result = node_red_client.verify_fingerprint({})

        self.assertTrue(result["ok"])
        self.assertEqual(result["finger_id"], 4)
        self.assertEqual(result["confidence"], 87)

    @patch("core.node_red_client._session.request")
    def test_enroll_fingerprint_accepts_status_based_success_response(self, mock_request):
        mock_request.return_value = FakeResponse(
            payload={"status": "enrolled", "id": 7}
        )

        result = node_red_client.enroll_fingerprint({"id": 7})

        self.assertTrue(result["ok"])
        self.assertEqual(result["finger_id"], 7)

    @patch("core.node_red_client._session.request")
    def test_collect_factors_returns_timeout_error(self, mock_request):
        mock_request.side_effect = requests.Timeout()

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "timeout")

    @patch("core.node_red_client._session.request")
    def test_collect_factors_returns_connection_error(self, mock_request):
        mock_request.side_effect = requests.ConnectionError("sensor host down")

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "connection_error")

    @patch("core.node_red_client._session.request")
    def test_collect_factors_handles_bad_json(self, mock_request):
        mock_request.return_value = FakeResponse(text="not-json", json_error=ValueError("bad json"))

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "invalid_json")

    @patch("core.node_red_client._session.request")
    def test_collect_factors_handles_non_object_json(self, mock_request):
        mock_request.return_value = FakeResponse(payload=["not", "an", "object"])

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "invalid_json")

    @patch("core.node_red_client._session.request")
    def test_collect_factors_infers_success_from_partial_combined_payload(self, mock_request):
        mock_request.return_value = FakeResponse(
            payload={
                "rfid": {"ok": True, "uid": "CARD-1001"},
            }
        )

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertTrue(result["ok"])
        self.assertTrue(result["rfid"]["ok"])
        self.assertFalse(result["fingerprint"]["ok"])
        self.assertEqual(result["fingerprint"]["error"], "missing")

    @patch("core.node_red_client._session.request")
    def test_collect_factors_normalizes_negative_factor_result(self, mock_request):
        mock_request.return_value = FakeResponse(
            payload={
                "ok": True,
                "rfid": {"ok": True, "uid": "CARD-1001"},
                "fingerprint": {"status": "not_found"},
            }
        )

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertTrue(result["ok"])
        self.assertTrue(result["rfid"]["ok"])
        self.assertFalse(result["fingerprint"]["ok"])
        self.assertFalse(result["fingerprint"]["matched"])
        self.assertEqual(result["fingerprint"]["error"], "not_found")

    @patch("core.node_red_client._session.request")
    def test_collect_factors_normalizes_error_payload(self, mock_request):
        mock_request.return_value = FakeResponse(
            payload={"ok": False, "error": "timeout", "message": "sensor stalled"}
        )

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "timeout")
        self.assertEqual(result["message"], "sensor stalled")
