import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import requests
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from .. import node_red_client
from .base import CoreTestDataMixin


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


class RecordingNodeRedServer:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []
        self._httpd = None
        self._thread = None
        self.base_url = None

    def __enter__(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                parent._handle(self)

            def log_message(self, format, *args):
                return

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self._httpd.server_port}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _handle(self, handler):
        content_length = int(handler.headers.get("Content-Length", "0"))
        raw_body = handler.rfile.read(content_length) if content_length else b""
        body_text = raw_body.decode("utf-8", errors="replace")
        try:
            body_json = json.loads(body_text or "{}")
        except ValueError:
            body_json = None

        request_record = {
            "method": handler.command,
            "path": handler.path,
            "headers": dict(handler.headers.items()),
            "body_text": body_text,
            "body_json": body_json,
        }
        self.requests.append(request_record)

        route = self.routes.get((handler.command, handler.path))
        if route is None:
            response = {
                "status": 404,
                "headers": {"Content-Type": "application/json"},
                "body_text": json.dumps({"error": "not_found", "message": "Route not configured."}),
            }
        elif callable(route):
            response = route(request_record)
        else:
            response = route

        status = response.get("status", 200)
        headers = dict(response.get("headers", {}))
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
        body_text = response.get("body_text")
        if body_text is None:
            body = response.get("body", {})
            body_text = json.dumps(body)

        handler.send_response(status)
        for header_name, header_value in headers.items():
            handler.send_header(header_name, header_value)
        handler.end_headers()
        try:
            handler.wfile.write(body_text.encode("utf-8"))
        except OSError:
            pass


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
    def test_collect_factors_marks_missing_rfid_as_missing_not_success(self, mock_request):
        mock_request.return_value = FakeResponse(
            payload={
                "fingerprint": {"ok": True, "matched": True, "finger_id": 4},
            }
        )

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertTrue(result["ok"])
        self.assertFalse(result["rfid"]["ok"])
        self.assertEqual(result["rfid"]["error"], "missing")
        self.assertTrue(result["fingerprint"]["ok"])

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
    def test_collect_factors_rejects_wrong_data_types_as_invalid_payload(self, mock_request):
        mock_request.return_value = FakeResponse(
            payload={
                "ok": True,
                "rfid": ["CARD-1001"],
                "fingerprint": "bad",
            }
        )

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "invalid_payload")
        self.assertEqual(result["rfid"]["error"], "invalid_payload")
        self.assertEqual(result["fingerprint"]["error"], "invalid_payload")

    @patch("core.node_red_client._session.request")
    def test_collect_factors_rejects_empty_dict_payload(self, mock_request):
        mock_request.return_value = FakeResponse(payload={})

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "invalid_payload")
        self.assertEqual(result["rfid"]["error"], "missing")
        self.assertEqual(result["fingerprint"]["error"], "missing")

    @patch("core.node_red_client._session.request")
    def test_collect_factors_normalizes_error_payload(self, mock_request):
        mock_request.return_value = FakeResponse(
            payload={"ok": False, "error": "timeout", "message": "sensor stalled"}
        )

        result = node_red_client.collect_factors({"session_id": 1})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "timeout")
        self.assertEqual(result["message"], "sensor stalled")

    def test_collect_factors_real_http_request_uses_expected_path_headers_and_json(self):
        with RecordingNodeRedServer(
            {
                ("POST", "/api/auth/collect-factors"): {
                    "status": 200,
                    "body": {
                        "ok": True,
                        "message": "",
                        "rfid": {"ok": True, "sensor": "rfid", "uid": "CARD-1001", "message": ""},
                        "fingerprint": {
                            "ok": True,
                            "sensor": "fingerprint",
                            "matched": True,
                            "finger_id": 4,
                            "confidence": 87,
                            "message": "",
                        },
                    },
                }
            }
        ) as server:
            with self.settings(
                NODE_RED_BASE_URL=server.base_url,
                NODE_RED_TIMEOUT=2,
                NODE_RED_SHARED_SECRET="node-red-secret",
            ):
                outbound_payload = {
                    "session_id": 7,
                    "resource_id": 3,
                    "user_id": 4,
                    "policy_id": 9,
                    "required_factor_count": 2,
                }
                result = node_red_client.collect_factors(outbound_payload)

        self.assertTrue(result["ok"])
        self.assertTrue(result["rfid"]["ok"])
        self.assertTrue(result["fingerprint"]["ok"])
        self.assertEqual(len(server.requests), 1)
        request_record = server.requests[0]
        self.assertEqual(request_record["path"], "/api/auth/collect-factors")
        self.assertEqual(request_record["headers"]["X-API-Key"], "node-red-secret")
        self.assertEqual(request_record["headers"]["Content-Type"], "application/json")
        self.assertEqual(request_record["body_json"], outbound_payload)

    def test_collect_factors_real_http_request_omits_shared_secret_header_when_not_configured(self):
        with RecordingNodeRedServer(
            {
                ("POST", "/api/auth/collect-factors"): {
                    "status": 200,
                    "body": {
                        "ok": True,
                        "rfid": {"ok": True, "uid": "CARD-1001"},
                        "fingerprint": {"ok": True, "matched": True, "finger_id": 4},
                    },
                }
            }
        ) as server:
            with self.settings(
                NODE_RED_BASE_URL=server.base_url,
                NODE_RED_TIMEOUT=2,
                NODE_RED_SHARED_SECRET="",
            ):
                result = node_red_client.collect_factors({"session_id": 5})

        self.assertTrue(result["ok"])
        self.assertNotIn("X-API-Key", server.requests[0]["headers"])

    def test_collect_factors_real_http_invalid_json_response(self):
        with RecordingNodeRedServer(
            {
                ("POST", "/api/auth/collect-factors"): {
                    "status": 200,
                    "headers": {"Content-Type": "text/plain"},
                    "body_text": "not-json",
                }
            }
        ) as server:
            with self.settings(NODE_RED_BASE_URL=server.base_url, NODE_RED_TIMEOUT=2):
                result = node_red_client.collect_factors({"session_id": 11})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "invalid_json")

    def test_collect_factors_real_http_timeout(self):
        def slow_collect(_request_record):
            time.sleep(0.25)
            return {
                "status": 200,
                "body": {
                    "ok": True,
                    "rfid": {"ok": True, "uid": "CARD-1001"},
                    "fingerprint": {"ok": True, "matched": True, "finger_id": 4},
                },
            }

        with RecordingNodeRedServer(
            {
                ("POST", "/api/auth/collect-factors"): slow_collect,
            }
        ) as server:
            with self.settings(NODE_RED_BASE_URL=server.base_url, NODE_RED_TIMEOUT=0.05):
                result = node_red_client.collect_factors({"session_id": 22})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "timeout")

    def test_collect_factors_real_http_500_json_error(self):
        with RecordingNodeRedServer(
            {
                ("POST", "/api/auth/collect-factors"): {
                    "status": 500,
                    "body": {"error": "upstream_error", "message": "fingerprint worker crashed"},
                }
            }
        ) as server:
            with self.settings(NODE_RED_BASE_URL=server.base_url, NODE_RED_TIMEOUT=2):
                result = node_red_client.collect_factors({"session_id": 31})

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "upstream_error")
        self.assertEqual(result["message"], "fingerprint worker crashed")


class NodeRedDjangoBoundaryTests(CoreTestDataMixin, TestCase):
    def test_api_access_start_uses_real_http_call_to_fake_node_red(self):
        with RecordingNodeRedServer(
            {
                ("POST", "/api/auth/collect-factors"): {
                    "status": 200,
                    "body": {
                        "ok": True,
                        "message": "",
                        "rfid": {"ok": True, "sensor": "rfid", "uid": self.rfid.identifier, "message": ""},
                        "fingerprint": {
                            "ok": True,
                            "sensor": "fingerprint",
                            "matched": True,
                            "finger_id": 4,
                            "confidence": 87,
                            "message": "",
                        },
                    },
                }
            }
        ) as server:
            with self.settings(NODE_RED_BASE_URL=server.base_url, NODE_RED_TIMEOUT=2):
                response = self.client.post(
                    reverse("core:api-access-start"),
                    data=json.dumps(
                        {
                            "resource_id": self.resource.id,
                            "tier": self.tier1_policy.tier,
                            "user_id": self.user.id,
                        }
                    ),
                    content_type="application/json",
                )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["data"]["session"]["is_access_granted"])
        self.assertEqual(len(server.requests), 1)
        request_record = server.requests[0]
        self.assertEqual(request_record["path"], "/api/auth/collect-factors")
        self.assertEqual(
            request_record["body_json"],
            {
                "session_id": payload["data"]["session"]["id"],
                "resource_id": self.resource.id,
                "user_id": self.user.id,
                "policy_id": self.tier1_policy.id,
                "required_factor_count": 2,
                "allowed_factor_types": ["rfid", "biometric"],
            },
        )

    def test_api_access_start_real_http_tier2_request_tells_node_red_to_skip_fingerprint(self):
        with RecordingNodeRedServer(
            {
                ("POST", "/api/auth/collect-factors"): {
                    "status": 200,
                    "body": {
                        "ok": True,
                        "message": "",
                        "rfid": {"ok": True, "sensor": "rfid", "uid": self.rfid.identifier, "message": ""},
                    },
                }
            }
        ) as server:
            with self.settings(NODE_RED_BASE_URL=server.base_url, NODE_RED_TIMEOUT=2):
                response = self.client.post(
                    reverse("core:api-access-start"),
                    data=json.dumps(
                        {
                            "resource_id": self.resource.id,
                            "tier": self.tier2_policy.tier,
                            "user_id": self.user.id,
                            "knowledge_factor": self.pin.identifier,
                        }
                    ),
                    content_type="application/json",
                )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["data"]["session"]["is_access_granted"])
        self.assertEqual(len(server.requests), 1)
        self.assertEqual(
            server.requests[0]["body_json"],
            {
                "session_id": payload["data"]["session"]["id"],
                "resource_id": self.resource.id,
                "user_id": self.user.id,
                "policy_id": self.tier2_policy.id,
                "required_factor_count": 2,
                "allowed_factor_types": ["rfid", "pin"],
            },
        )

    def test_api_access_start_real_http_timeout_denies_access_cleanly(self):
        def slow_collect(_request_record):
            time.sleep(0.25)
            return {
                "status": 200,
                "body": {
                    "ok": True,
                    "rfid": {"ok": True, "uid": self.rfid.identifier},
                    "fingerprint": {"ok": True, "matched": True, "finger_id": 4},
                },
            }

        with RecordingNodeRedServer(
            {
                ("POST", "/api/auth/collect-factors"): slow_collect,
            }
        ) as server:
            with self.settings(NODE_RED_BASE_URL=server.base_url, NODE_RED_TIMEOUT=0.05):
                response = self.client.post(
                    reverse("core:api-access-start"),
                    data=json.dumps(
                        {
                            "resource_id": self.resource.id,
                            "tier": self.tier1_policy.tier,
                            "user_id": self.user.id,
                        }
                    ),
                    content_type="application/json",
                )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertFalse(payload["data"]["session"]["is_access_granted"])
        self.assertEqual(
            payload["data"]["session"]["factor_collection_result"]["error"],
            "timeout",
        )

    def test_api_access_start_real_http_malformed_payload_denies_cleanly(self):
        with RecordingNodeRedServer(
            {
                ("POST", "/api/auth/collect-factors"): {
                    "status": 200,
                    "body": {"ok": True, "rfid": [], "fingerprint": {}},
                }
            }
        ) as server:
            with self.settings(NODE_RED_BASE_URL=server.base_url, NODE_RED_TIMEOUT=2):
                response = self.client.post(
                    reverse("core:api-access-start"),
                    data=json.dumps(
                        {
                            "resource_id": self.resource.id,
                            "tier": self.tier1_policy.tier,
                            "user_id": self.user.id,
                        }
                    ),
                    content_type="application/json",
                )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertFalse(payload["data"]["session"]["is_access_granted"])
        self.assertEqual(
            payload["data"]["session"]["factor_collection_result"]["error"],
            "invalid_payload",
        )
