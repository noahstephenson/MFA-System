from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from ..models import AuthenticationSession, Credential
from .base import CoreTestDataMixin


class OperatorPageTests(CoreTestDataMixin, TestCase):
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

    def test_home_page_loads(self):
        response = self.client.get(reverse("core:home"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Node-RED driven MFA MVP")
        self.assertContains(response, "Start Access Attempt")

    def test_access_start_page_loads(self):
        response = self.client.get(reverse("core:access-start"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Start access attempt")
        self.assertContains(response, self.user.username)
        self.assertContains(response, "Node-RED will collect RFID and fingerprint factors")

    @patch("core.services.node_red_client.collect_factors")
    def test_access_start_submit_redirects_to_result_page(self, mock_collect):
        mock_collect.return_value = {
            "ok": True,
            "error": "",
            "message": "",
            "rfid": {"ok": True, "uid": self.rfid.identifier},
            "fingerprint": {"ok": True, "matched": True, "finger_id": self.biometric.identifier},
            "raw": {},
            "status_code": 200,
        }

        response = self.client.post(
            reverse("core:access-start-submit"),
            {"user": self.user.id, "resource": self.resource.id},
        )

        session = AuthenticationSession.objects.get()
        self.assertRedirects(response, reverse("core:access-result", args=[session.id]))

    @patch("core.services.node_red_client.collect_factors")
    def test_access_result_page_shows_denial_after_node_red_failure(self, mock_collect):
        mock_collect.return_value = {
            "ok": False,
            "error": "timeout",
            "message": "Node-RED request timed out.",
            "rfid": {"ok": False, "sensor": "rfid", "error": "missing", "message": "RFID data was not collected."},
            "fingerprint": {
                "ok": False,
                "sensor": "fingerprint",
                "error": "missing",
                "message": "Fingerprint data was not collected.",
            },
            "raw": None,
            "status_code": None,
        }

        start_response = self.client.post(
            reverse("core:access-start-submit"),
            {"user": self.user.id, "resource": self.resource.id},
        )
        session = AuthenticationSession.objects.get()

        self.assertRedirects(start_response, reverse("core:access-result", args=[session.id]))

        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertContains(result_response, "Access denied")
        self.assertContains(result_response, "Node-RED request timed out.")
        self.assertContains(result_response, "Factor Collection")
