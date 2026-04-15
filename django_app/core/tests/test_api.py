import json
from unittest.mock import patch

from django.test import Client, TestCase, override_settings
from django.urls import reverse

from .base import CoreTestDataMixin


class AccessAPITests(CoreTestDataMixin, TestCase):
    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_tier1_happy_path(self, mock_collect):
        mock_collect.return_value = {
            "ok": True,
            "error": "",
            "message": "",
            "rfid": {"ok": True, "uid": self.rfid.identifier, "message": ""},
            "fingerprint": {"ok": True, "matched": True, "finger_id": 4, "message": ""},
            "raw": {},
            "status_code": 200,
        }

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

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"]["session"]["resource"], self.resource.name)
        self.assertEqual(payload["data"]["session"]["tier"], self.tier1_policy.tier)
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
        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(
                {
                    "resource_id": self.resource.id,
                    "user_id": self.user.id,
                    "tier": self.tier2_policy.tier,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIn("knowledge_factor", payload["errors"])

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
        mock_collect.return_value = {
            "ok": False,
            "error": "timeout",
            "message": "Node-RED request timed out.",
            "rfid": {"ok": False, "sensor": "rfid", "error": "missing", "message": "RFID data was not collected."},
            "fingerprint": {
                "ok": False,
                "sensor": "fingerprint",
                "matched": False,
                "error": "timeout",
                "message": "Fingerprint service timed out.",
            },
            "raw": None,
            "status_code": None,
        }
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
    def test_api_access_start_tier2_uses_knowledge_factor(self, mock_collect):
        mock_collect.return_value = {
            "ok": False,
            "error": "not_matched",
            "message": "Fingerprint not matched.",
            "rfid": {"ok": True, "sensor": "rfid", "uid": self.rfid.identifier, "message": ""},
            "fingerprint": {
                "ok": False,
                "sensor": "fingerprint",
                "matched": False,
                "error": "not_matched",
                "message": "Fingerprint not matched.",
            },
            "raw": {},
            "status_code": 200,
        }

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
        self.assertTrue(payload["data"]["session"]["authentication"]["ok"])
        self.assertTrue(payload["data"]["session"]["authorization"]["ok"])
        self.assertTrue(payload["data"]["session"]["is_access_granted"])

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_tier3_denies_non_degraded_resource(self, mock_collect):
        mock_collect.return_value = {
            "ok": False,
            "error": "not_matched",
            "message": "Fingerprint not matched.",
            "rfid": {"ok": True, "sensor": "rfid", "uid": self.rfid.identifier, "message": ""},
            "fingerprint": {
                "ok": False,
                "sensor": "fingerprint",
                "matched": False,
                "error": "not_matched",
                "message": "Fingerprint not matched.",
            },
            "raw": {},
            "status_code": 200,
        }

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
        self.assertTrue(payload["data"]["session"]["authentication"]["ok"])
        self.assertFalse(payload["data"]["session"]["authorization"]["ok"])
        self.assertFalse(payload["data"]["session"]["is_access_granted"])

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_negative_path_still_returns_result_shape(self, mock_collect):
        mock_collect.return_value = {
            "ok": False,
            "error": "timeout",
            "message": "Node-RED request timed out.",
            "rfid": {"ok": False, "sensor": "rfid", "error": "missing", "message": "RFID data was not collected."},
            "fingerprint": {
                "ok": False,
                "sensor": "fingerprint",
                "matched": False,
                "error": "timeout",
                "message": "Fingerprint service timed out.",
            },
            "raw": None,
            "status_code": None,
        }

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
        self.assertFalse(payload["data"]["session"]["authentication"]["ok"])
        self.assertFalse(payload["data"]["session"]["authorization"]["ok"])
        self.assertFalse(payload["data"]["session"]["is_access_granted"])
