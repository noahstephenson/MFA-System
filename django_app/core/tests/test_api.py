import json
from unittest.mock import patch

from django.test import Client, TestCase, override_settings
from django.urls import reverse

from ..models import Credential
from .base import CoreTestDataMixin


class AccessAPITests(CoreTestDataMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.policy.allowed_factor_types = [
            Credential.CredentialType.RFID,
            Credential.CredentialType.BIOMETRIC,
        ]
        self.policy.minimum_distinct_factor_types = 2
        self.policy.save(
            update_fields=["allowed_factor_types", "minimum_distinct_factor_types", "updated_at"]
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_returns_granted_session(self, mock_collect):
        mock_collect.return_value = {
            "ok": True,
            "error": "",
            "message": "",
            "rfid": {"ok": True, "uid": self.rfid.identifier},
            "fingerprint": {"ok": True, "matched": True, "finger_id": 4},
            "raw": {},
            "status_code": 200,
        }

        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps({"resource_id": self.resource.id, "user_id": self.user.id}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"]["session"]["status"], "approved")
        self.assertTrue(payload["data"]["session"]["is_access_granted"])
        self.assertEqual(payload["data"]["node_red"]["ok"], True)

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_start_is_callable_without_csrf_token_for_machine_clients(self, mock_collect):
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
            data=json.dumps({"resource_id": self.resource.id, "user_id": self.user.id}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertFalse(response.json()["data"]["session"]["is_access_granted"])

    @override_settings(MFA_API_SHARED_SECRET="demo-secret")
    def test_api_access_start_requires_shared_secret_when_configured(self):
        machine_client = Client(enforce_csrf_checks=True)

        response = machine_client.post(
            reverse("core:api-access-start"),
            data=json.dumps({"resource_id": self.resource.id, "user_id": self.user.id}),
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
            data=json.dumps({"resource_id": self.resource.id, "user_id": self.user.id}),
            content_type="application/json",
            HTTP_X_API_KEY="demo-secret",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json()["data"]["session"]["factor_collection_result"]["error"],
            "timeout",
        )

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

    def test_api_access_start_rejects_non_object_json(self):
        response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps(["not", "an", "object"]),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("body", response.json()["errors"])

    @patch("core.services.node_red_client.collect_factors")
    def test_api_access_session_detail_returns_current_state(self, mock_collect):
        mock_collect.return_value = {
            "ok": True,
            "error": "",
            "message": "",
            "rfid": {"ok": True, "uid": self.rfid.identifier},
            "fingerprint": {"ok": True, "matched": True, "finger_id": 4},
            "raw": {},
            "status_code": 200,
        }

        start_response = self.client.post(
            reverse("core:api-access-start"),
            data=json.dumps({"resource_id": self.resource.id, "user_id": self.user.id}),
            content_type="application/json",
        )

        session_id = start_response.json()["data"]["session"]["id"]
        response = self.client.get(reverse("core:api-access-session-detail", args=[session_id]))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"]["session"]["id"], session_id)
        self.assertEqual(payload["data"]["session"]["accepted_factor_count"], 2)


class IncrementalAuthAPITests(CoreTestDataMixin, TestCase):
    def test_auth_start_endpoint_creates_session(self):
        response = self.client.post(
            reverse("core:auth-start"),
            data=json.dumps({"resource_id": self.resource.id, "user_id": self.user.id}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"]["session"]["status"], "in_progress")
        self.assertEqual(payload["data"]["session"]["accepted_factor_count"], 0)

    def test_auth_factor_endpoint_advances_and_completes_session(self):
        start_response = self.client.post(
            reverse("core:auth-start"),
            data=json.dumps({"resource_id": self.resource.id, "user_id": self.user.id}),
            content_type="application/json",
        )
        session_id = start_response.json()["data"]["session"]["id"]

        first_factor_response = self.client.post(
            reverse("core:auth-factor"),
            data=json.dumps(
                {
                    "session_id": session_id,
                    "credential_type": Credential.CredentialType.RFID,
                    "identifier": self.rfid.identifier,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(first_factor_response.status_code, 200)
        self.assertTrue(first_factor_response.json()["data"]["accepted"])
        self.assertEqual(first_factor_response.json()["data"]["session"]["status"], "in_progress")

        second_factor_response = self.client.post(
            reverse("core:auth-factor"),
            data=json.dumps(
                {
                    "session_id": session_id,
                    "credential_type": Credential.CredentialType.PIN,
                    "identifier": self.pin.identifier,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(second_factor_response.status_code, 200)
        self.assertTrue(second_factor_response.json()["data"]["accepted"])
        self.assertEqual(second_factor_response.json()["data"]["session"]["status"], "approved")
        self.assertEqual(second_factor_response.json()["data"]["session"]["decision"], "granted")

    def test_auth_factor_endpoint_returns_duplicate_result_for_same_factor(self):
        start_response = self.client.post(
            reverse("core:auth-start"),
            data=json.dumps({"resource_id": self.resource.id, "user_id": self.user.id}),
            content_type="application/json",
        )
        session_id = start_response.json()["data"]["session"]["id"]

        self.client.post(
            reverse("core:auth-factor"),
            data=json.dumps(
                {
                    "session_id": session_id,
                    "credential_type": Credential.CredentialType.RFID,
                    "identifier": self.rfid.identifier,
                }
            ),
            content_type="application/json",
        )
        response = self.client.post(
            reverse("core:auth-factor"),
            data=json.dumps(
                {
                    "session_id": session_id,
                    "credential_type": Credential.CredentialType.RFID,
                    "identifier": self.rfid.identifier,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["data"]["accepted"])
        self.assertEqual(payload["data"]["reason_code"], "duplicate")

    def test_auth_session_detail_returns_current_state(self):
        start_response = self.client.post(
            reverse("core:auth-start"),
            data=json.dumps({"resource_id": self.resource.id, "user_id": self.user.id}),
            content_type="application/json",
        )
        session_id = start_response.json()["data"]["session"]["id"]

        response = self.client.get(reverse("core:auth-session-detail", args=[session_id]))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])

    def test_auth_start_endpoint_returns_consistent_405_shape(self):
        response = self.client.get(reverse("core:auth-start"))

        self.assertEqual(response.status_code, 405)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "Request method not allowed.")

    def test_auth_start_endpoint_returns_consistent_validation_error_shape(self):
        response = self.client.post(
            reverse("core:auth-start"),
            data=json.dumps({"user_id": self.user.id}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "Request validation failed.")
        self.assertIn("resource_id", payload["errors"])
