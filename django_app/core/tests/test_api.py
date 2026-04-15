import json
from unittest.mock import patch

from django.test import Client, TestCase, override_settings
from django.urls import reverse

from ..models import AccessPolicy, ProtectedResource
from .base import CoreTestDataMixin


class AccessAPITests(CoreTestDataMixin, TestCase):
    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_happy_path(self, mock_collect):
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
            data=json.dumps({"tier": self.policy.tier, "user_id": self.user.id}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"]["session"]["tier"], self.policy.tier)
        self.assertNotIn("resource", payload["data"]["session"])
        self.assertEqual(payload["data"]["session"]["status"], "approved")
        self.assertTrue(payload["data"]["session"]["is_access_granted"])

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

    def test_api_access_start_requires_fields(self):
        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps({"user_id": self.user.id}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIn("tier", payload["errors"])

    @override_settings(MFA_API_SHARED_SECRET="demo-secret")
    def test_api_access_start_requires_shared_secret_when_configured(self):
        machine_client = Client(enforce_csrf_checks=True)

        response = machine_client.post(
            reverse("core:api-access-start"),
            data=json.dumps({"tier": self.policy.tier, "user_id": self.user.id}),
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
            "message": "Fingerprint service timed out.",
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
            data=json.dumps({"tier": self.policy.tier, "user_id": self.user.id}),
            content_type="application/json",
            HTTP_X_API_KEY="demo-secret",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json()["data"]["session"]["factor_collection_result"]["error"],
            "timeout",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_returns_negative_factor_shape(self, mock_collect):
        mock_collect.return_value = {
            "ok": True,
            "error": "",
            "message": "",
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
            data=json.dumps({"tier": self.policy.tier, "user_id": self.user.id}),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self.assertFalse(payload["data"]["session"]["is_access_granted"])
        self.assertEqual(
            payload["data"]["session"]["factor_collection_result"]["fingerprint"]["error"],
            "not_matched",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_returns_timeout_failure_shape(self, mock_collect):
        mock_collect.return_value = {
            "ok": False,
            "error": "timeout",
            "message": "Fingerprint service timed out.",
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
            data=json.dumps({"tier": self.policy.tier, "user_id": self.user.id}),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 201)
        self.assertFalse(payload["data"]["session"]["is_access_granted"])
        self.assertEqual(
            payload["data"]["session"]["factor_collection_result"]["error"],
            "timeout",
        )

    def test_api_access_start_rejects_ambiguous_tier(self):
        other_resource = ProtectedResource.objects.create(name="Lobby Door", description="Second demo target.")
        AccessPolicy.objects.create(
            resource=other_resource,
            name="Second Elevated Policy",
            description="Competing elevated policy.",
            tier=self.policy.tier,
            required_factor_count=1,
        )

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps({"tier": self.policy.tier, "user_id": self.user.id}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("tier", response.json()["errors"])
