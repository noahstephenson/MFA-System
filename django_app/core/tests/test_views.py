from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from ..models import AuthenticationSession
from .base import CoreTestDataMixin


class OperatorPageTests(CoreTestDataMixin, TestCase):
    def test_access_start_page_loads_with_tier_selector(self):
        response = self.client.get(reverse("core:access-start"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Start access attempt")
        self.assertContains(response, self.user.username)
        self.assertContains(response, "Access tier")
        self.assertNotContains(response, "Protected resource")

    @patch("core.services.node_red_client.collect_factors")
    def test_access_start_post_redirects_to_result_page(self, mock_collect):
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
            reverse("core:access-start"),
            {"user": self.user.id, "tier": self.policy.tier},
        )

        session = AuthenticationSession.objects.get()
        self.assertRedirects(response, reverse("core:access-result", args=[session.id]))

    @patch("core.services.node_red_client.collect_factors")
    def test_access_result_page_renders_granted_state(self, mock_collect):
        mock_collect.return_value = {
            "ok": True,
            "error": "",
            "message": "",
            "rfid": {"ok": True, "uid": self.rfid.identifier, "message": ""},
            "fingerprint": {"ok": True, "matched": True, "finger_id": 4, "message": ""},
            "raw": {},
            "status_code": 200,
        }

        start_response = self.client.post(
            reverse("core:access-start"),
            {"user": self.user.id, "tier": self.policy.tier},
        )
        session = AuthenticationSession.objects.get()

        self.assertRedirects(start_response, reverse("core:access-result", args=[session.id]))
        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertContains(result_response, "Access granted")
        self.assertContains(result_response, self.rfid.identifier)
        self.assertContains(result_response, "Tier")

    @patch("core.services.node_red_client.collect_factors")
    def test_access_result_page_renders_denied_state(self, mock_collect):
        mock_collect.return_value = {
            "ok": True,
            "error": "",
            "message": "",
            "rfid": {"ok": True, "uid": self.rfid.identifier, "message": ""},
            "fingerprint": {
                "ok": False,
                "matched": False,
                "error": "not_matched",
                "message": "Fingerprint not matched.",
            },
            "raw": {},
            "status_code": 200,
        }

        self.client.post(
            reverse("core:access-start"),
            {"user": self.user.id, "tier": self.policy.tier},
        )
        session = AuthenticationSession.objects.get()

        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertContains(result_response, "Access denied")
        self.assertContains(result_response, "Fingerprint not matched.")
