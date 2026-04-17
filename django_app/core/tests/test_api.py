import json
from unittest.mock import patch

from django.test import Client, TestCase, override_settings
from django.urls import reverse

from .base import CoreTestDataMixin


class AccessAPITests(CoreTestDataMixin, TestCase):
    _UNSET = object()

    def _node_red_result(
        self,
        *,
        ok=True,
        message="",
        error="",
        rfid=None,
        fingerprint=None,
        status_code=200,
        raw=_UNSET,
    ):
        if raw is self._UNSET:
            raw = {}
        return {
            "ok": ok,
            "error": error,
            "message": message,
            "rfid": rfid if rfid is not None else {"ok": False, "sensor": "rfid", "error": "missing", "message": "RFID data was not returned."},
            "fingerprint": fingerprint
            if fingerprint is not None
            else {
                "ok": False,
                "sensor": "fingerprint",
                "matched": False,
                "error": "missing",
                "message": "Fingerprint data was not returned.",
            },
            "raw": raw,
            "status_code": status_code,
        }

    def _rfid_ok(self, identifier=None):
        return {
            "ok": True,
            "sensor": "rfid",
            "uid": identifier or self.rfid.identifier,
            "message": "",
        }

    def _fingerprint_ok(self, finger_id=4):
        return {
            "ok": True,
            "sensor": "fingerprint",
            "matched": True,
            "finger_id": finger_id,
            "confidence": 87,
            "message": "",
        }

    def _fingerprint_fail(self, *, error="not_matched", message="Fingerprint not matched."):
        return {
            "ok": False,
            "sensor": "fingerprint",
            "matched": False,
            "error": error,
            "message": message,
        }

    def _assert_session_payload_shape(self, payload):
        self.assertEqual(
            set(payload["data"].keys()),
            {"session", "node_red"},
        )
        self.assertEqual(
            set(payload["data"]["session"].keys()),
            {
                "id",
                "user",
                "resource",
                "tier",
                "policy",
                "status",
                "decision",
                "required_factor_count",
                "required_factor_types",
                "accepted_factor_count",
                "remaining_factor_count",
                "submitted_factors",
                "is_complete",
                "is_access_granted",
                "factor_collection_result",
                "authentication",
                "authorization",
                "result_url",
            },
        )
        self.assertEqual(
            set(payload["data"]["node_red"].keys()),
            {"ok", "error", "message"},
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_tier1_success_shape(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_ok(),
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier1_policy.tier,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self.assertTrue(payload["ok"])
        self._assert_session_payload_shape(payload)
        self.assertTrue(payload["data"]["session"]["authentication"]["ok"])
        self.assertTrue(payload["data"]["session"]["authorization"]["ok"])

    def test_api_access_start_requires_resource_field(self):
        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps({"user_id": self.user.id}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIn("resource_id", payload["errors"])

    def test_api_access_start_requires_knowledge_factor_for_tier2_and_tier3(self):
        for tier in (self.tier2_policy.tier, self.tier3_policy.tier):
            response = self.client.post(
                reverse("core:api-access-start"),
                data=json.dumps(
                    {
                        "resource_id": self.resource.id,
                        "user_id": self.user.id,
                        "tier": tier,
                    }
                ),
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 400)
            payload = response.json()
            self.assertFalse(payload["ok"])
            self.assertIn("knowledge_factor", payload["errors"])

    def test_api_access_start_requires_exactly_eight_digit_pin(self):
        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier2_policy.tier,
                    "knowledge_factor": "1234567A",
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 400)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["errors"]["knowledge_factor"], ["PIN must be exactly 8 digits."])

    def test_api_access_start_rejects_invalid_json(self):
        response = self.client.post(
            reverse("core:api-access-start"),
            data="not-json",
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIn("body", payload["errors"])

    def test_api_access_start_rejects_non_object_json_body(self):
        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps([1, 2, 3]),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIn("body", payload["errors"])

    @override_settings(MFA_API_SHARED_SECRET="demo-secret")
    def test_api_access_start_requires_shared_secret_when_configured(self):
        machine_client = Client(enforce_csrf_checks=True)

        response = machine_client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier1_policy.tier,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "API authentication failed.")

    @override_settings(MFA_API_SHARED_SECRET="demo-secret")
    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_accepts_valid_shared_secret(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="timeout",
            message="Node-RED request timed out.",
            rfid={"ok": False, "sensor": "rfid", "error": "missing", "message": "RFID data was not collected."},
            fingerprint=self._fingerprint_fail(error="timeout", message="Fingerprint service timed out."),
            status_code=None,
            raw=None,
        )
        machine_client = Client(enforce_csrf_checks=True)

        response = machine_client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier1_policy.tier,
                }
            ),
            content_type="application/json",
            HTTP_X_API_KEY="demo-secret",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json()["data"]["session"]["factor_collection_result"]["error"],
            "timeout",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_negative_factor_result_shape(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=True,
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier1_policy.tier,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self._assert_session_payload_shape(payload)
        self.assertFalse(payload["data"]["session"]["authentication"]["ok"])
        self.assertFalse(payload["data"]["session"]["authorization"]["ok"])
        self.assertFalse(payload["data"]["session"]["is_access_granted"])
        self.assertEqual(
            payload["data"]["session"]["factor_collection_result"]["fingerprint"]["error"],
            "not_matched",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_tier1_does_not_accept_rfid_plus_knowledge(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=True,
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier1_policy.tier,
                    "knowledge_factor": self.pin.identifier,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self._assert_session_payload_shape(payload)
        self.assertFalse(payload["data"]["session"]["authentication"]["ok"])
        self.assertEqual(
            payload["data"]["session"]["authentication"]["verified_factor_types"],
            ["rfid"],
        )
        self.assertFalse(payload["data"]["session"]["is_access_granted"])

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_tier2_success_with_knowledge_factor(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier2_policy.tier,
                    "knowledge_factor": self.pin.identifier,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self._assert_session_payload_shape(payload)
        self.assertTrue(payload["data"]["session"]["authentication"]["ok"])
        self.assertTrue(payload["data"]["session"]["authorization"]["ok"])
        self.assertEqual(
            payload["data"]["session"]["authentication"]["verified_factor_types"],
            ["rfid", "pin"],
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_tier2_denial_wrong_knowledge_message(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=True,
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_ok(),
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier2_policy.tier,
                    "knowledge_factor": "99999999",
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self._assert_session_payload_shape(payload)
        self.assertFalse(payload["data"]["session"]["authentication"]["ok"])
        self.assertEqual(
            payload["data"]["session"]["authentication"]["message"],
            "Knowledge factor did not match the enrolled credential.",
        )
        self.assertFalse(payload["data"]["session"]["is_access_granted"])

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_tier2_does_not_require_fingerprint(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier2_policy.tier,
                    "knowledge_factor": self.pin.identifier,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertTrue(payload["data"]["session"]["is_access_granted"])
        self.assertNotIn(
            "biometric",
            payload["data"]["session"]["authentication"]["verified_factor_types"],
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_tier3_degraded_resource_denial_shape(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier3_policy.tier,
                    "knowledge_factor": self.pin.identifier,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self._assert_session_payload_shape(payload)
        self.assertTrue(payload["data"]["session"]["authentication"]["ok"])
        self.assertFalse(payload["data"]["session"]["authorization"]["ok"])
        self.assertFalse(payload["data"]["session"]["is_access_granted"])
        self.assertEqual(
            payload["data"]["session"]["authorization"]["message"],
            "Selected resource is not approved for Tier 3 degraded access.",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_tier3_success_shape(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.degraded_resource.id,
                    "user_id": self.user.id,
                    "tier": self.degraded_tier3_policy.tier,
                    "knowledge_factor": self.pin.identifier,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self._assert_session_payload_shape(payload)
        self.assertTrue(payload["data"]["session"]["authentication"]["ok"])
        self.assertTrue(payload["data"]["session"]["authorization"]["ok"])
        self.assertTrue(payload["data"]["session"]["is_access_granted"])

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_malformed_node_red_response_shape(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="invalid_payload",
            message="Node-RED returned an invalid factor payload.",
            rfid={},
            fingerprint={},
            raw={"ok": True},
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier1_policy.tier,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self._assert_session_payload_shape(payload)
        self.assertFalse(payload["data"]["session"]["authentication"]["ok"])
        self.assertEqual(
            payload["data"]["session"]["factor_collection_result"]["error"],
            "invalid_payload",
        )
        self.assertEqual(payload["data"]["node_red"]["error"], "invalid_payload")

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_empty_combined_payload_is_not_treated_as_success(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="invalid_payload",
            message="Node-RED did not return any factor data.",
            rfid={"ok": False, "sensor": "rfid", "error": "missing", "message": "RFID data was not returned."},
            fingerprint={
                "ok": False,
                "sensor": "fingerprint",
                "matched": False,
                "error": "missing",
                "message": "Fingerprint data was not returned.",
            },
            raw={},
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier1_policy.tier,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self._assert_session_payload_shape(payload)
        self.assertFalse(payload["data"]["session"]["authentication"]["ok"])
        self.assertEqual(payload["data"]["node_red"]["error"], "invalid_payload")
        self.assertEqual(
            payload["data"]["node_red"]["message"],
            "Node-RED did not return any factor data.",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_timeout_external_failure_shape(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="timeout",
            message="Fingerprint service timed out.",
            rfid={"ok": False, "sensor": "rfid", "error": "missing", "message": "RFID data was not collected."},
            fingerprint=self._fingerprint_fail(error="timeout", message="Fingerprint service timed out."),
            status_code=None,
            raw=None,
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier1_policy.tier,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self._assert_session_payload_shape(payload)
        self.assertFalse(payload["data"]["session"]["authentication"]["ok"])
        self.assertFalse(payload["data"]["session"]["authorization"]["ok"])
        self.assertEqual(payload["data"]["node_red"]["error"], "timeout")
        self.assertEqual(payload["data"]["node_red"]["message"], "Fingerprint service timed out.")
