from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from ..models import AuthenticationSession
from .base import CoreTestDataMixin


class OperatorPageTests(CoreTestDataMixin, TestCase):
    def _node_red_result(
        self,
        *,
        ok=True,
        message="",
        error="",
        rfid=None,
        fingerprint=None,
        status_code=200,
        raw=None,
    ):
        if raw is None:
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

    def _rfid_ok(self):
        return {"ok": True, "uid": self.rfid.identifier, "message": ""}

    def _fingerprint_ok(self):
        return {"ok": True, "matched": True, "finger_id": 4, "message": ""}

    def _fingerprint_fail(self, *, error="not_matched", message="Fingerprint not matched."):
        return {"ok": False, "matched": False, "error": error, "message": message}

    def test_access_start_page_loads_with_required_fields(self):
        response = self.client.get(reverse("core:access-start"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Start access attempt")
        self.assertContains(response, self.user.username)
        self.assertContains(response, "Protected resource")
        self.assertContains(response, "Access tier")
        self.assertContains(response, "Knowledge factor")

    def test_access_start_page_validates_knowledge_input_for_tier2(self):
        response = self.client.post(
            reverse("core:access-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
                "tier": self.tier2_policy.tier,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Provide the knowledge factor for Tier 2 and Tier 3 access attempts.")

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_post_redirects_to_result_page(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_ok(),
        )

        response = self.client.post(
            reverse("core:access-start"),
            {"user": self.user.id, "resource": self.resource.id, "tier": self.tier1_policy.tier},
        )

        session = AuthenticationSession.objects.get()
        self.assertRedirects(response, reverse("core:access-result", args=[session.id]))

    @patch("core.services.node_red_client.collect_factors")
    def test_tier2_post_redirects_to_granted_result_page(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        start_response = self.client.post(
            reverse("core:access-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
                "tier": self.tier2_policy.tier,
                "knowledge_factor": self.pin.identifier,
            },
        )
        session = AuthenticationSession.objects.get()

        self.assertRedirects(start_response, reverse("core:access-result", args=[session.id]))
        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertContains(result_response, "Access granted")
        self.assertContains(result_response, "Authentication")
        self.assertContains(result_response, "Authorization")

    @patch("core.services.node_red_client.collect_factors")
    def test_tier3_post_redirects_to_granted_result_page_for_degraded_resource(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        start_response = self.client.post(
            reverse("core:access-start"),
            {
                "user": self.user.id,
                "resource": self.degraded_resource.id,
                "tier": self.degraded_tier3_policy.tier,
                "knowledge_factor": self.pin.identifier,
            },
        )
        session = AuthenticationSession.objects.get()

        self.assertRedirects(start_response, reverse("core:access-result", args=[session.id]))
        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertContains(result_response, "Access granted")
        self.assertContains(result_response, self.degraded_resource.name)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier3_non_degraded_resource_renders_denied_state(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        self.client.post(
            reverse("core:access-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
                "tier": self.tier3_policy.tier,
                "knowledge_factor": self.pin.identifier,
            },
        )
        session = AuthenticationSession.objects.get()

        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertContains(result_response, "Access denied")
        self.assertContains(result_response, "Selected resource is not approved for Tier 3 degraded access.")
