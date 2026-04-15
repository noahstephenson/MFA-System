from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from ..models import AuthenticationSession, Credential
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
            "rfid": rfid
            if rfid is not None
            else {
                "ok": False,
                "sensor": "rfid",
                "error": "missing",
                "message": "RFID data was not returned.",
            },
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

    def test_home_page_renders_primary_actions(self):
        response = self.client.get(reverse("core:home"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Operator console")
        self.assertContains(response, "Demo ATAK")
        self.assertContains(response, "Start Access Request")
        self.assertContains(response, "Enroll Credentials")

    def test_enrollment_page_renders_required_fields(self):
        response = self.client.get(reverse("core:enroll"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Enroll credentials")
        self.assertContains(response, "Credential type")
        self.assertContains(response, "Identifier / value")
        self.assertContains(response, "Save Credential")
        self.assertContains(response, "Use the UID returned by the Node-RED RFID flow.")

    def test_enrollment_submission_creates_credential_and_redirects_to_selected_user(self):
        response = self.client.post(
            reverse("core:enroll"),
            {
                "user": self.user.id,
                "credential_type": Credential.CredentialType.BIOMETRIC,
                "identifier": "7",
                "label": "Backup fingerprint",
            },
        )

        self.assertRedirects(response, f"{reverse('core:enroll')}?user={self.user.id}")
        self.assertTrue(
            Credential.objects.filter(
                user=self.user,
                credential_type=Credential.CredentialType.BIOMETRIC,
                identifier="7",
                active=True,
            ).exists()
        )

        follow_response = self.client.get(f"{reverse('core:enroll')}?user={self.user.id}")
        self.assertContains(follow_response, self.user.username)
        self.assertContains(follow_response, "Backup fingerprint")
        self.assertContains(follow_response, "Alice badge")
        self.assertContains(follow_response, "Stored PIN")

    def test_access_start_page_loads_with_required_fields_and_factor_cards(self):
        response = self.client.get(reverse("core:access-start"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Start access request")
        self.assertContains(response, "Run Access Attempt")
        self.assertContains(response, "User")
        self.assertContains(response, "Resource")
        self.assertContains(response, "Tier")
        self.assertContains(response, "Knowledge factor")
        self.assertContains(response, "What this tier needs")
        self.assertContains(response, "RFID")
        self.assertContains(response, "Fingerprint")
        self.assertContains(response, "Tier 1 uses RFID plus fingerprint.")

    def test_access_start_page_shows_tier2_requirements_cleanly(self):
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
        self.assertContains(response, "Tier 2 uses RFID plus PIN/passcode.")
        self.assertContains(response, "Ignored for Tier 2 and Tier 3.")
        self.assertContains(response, "Checked in Django after RFID.")
        self.assertEqual(AuthenticationSession.objects.count(), 0)

    def test_access_start_page_shows_tier3_requirements_cleanly(self):
        response = self.client.post(
            reverse("core:access-start"),
            {
                "user": self.user.id,
                "resource": self.degraded_resource.id,
                "tier": self.degraded_tier3_policy.tier,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Tier 3 uses RFID plus PIN/passcode and a degraded-approved resource.")
        self.assertContains(response, "Provide the knowledge factor for Tier 2 and Tier 3 access attempts.")
        self.assertEqual(AuthenticationSession.objects.count(), 0)

    def test_invalid_form_submission_rerenders_cleanly_with_useful_errors(self):
        response = self.client.post(
            reverse("core:access-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
                "tier": "tier-99",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Select a valid choice")
        self.assertContains(response, "Start access request")
        self.assertEqual(AuthenticationSession.objects.count(), 0)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_result_page_shows_green_factor_states(self, mock_collect):
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
        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertContains(result_response, "Access granted")
        self.assertContains(result_response, "Accepted")
        self.assertContains(result_response, "Fingerprint ID 4 matched the enrolled credential.")
        self.assertContains(result_response, "Knowledge factor")
        self.assertContains(result_response, "Not used")

    @patch("core.services.node_red_client.collect_factors")
    def test_tier3_denial_result_page_is_understandable(self, mock_collect):
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
        self.assertContains(result_response, "Authorization result")
        self.assertContains(result_response, "Selected resource is not approved for Tier 3 degraded access.")
        self.assertContains(result_response, "Fingerprint")
        self.assertContains(result_response, "Not used")

    @patch("core.services.node_red_client.collect_factors")
    def test_result_page_makes_external_node_red_failure_understandable(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="timeout",
            message="Node-RED request timed out.",
            rfid={
                "ok": False,
                "sensor": "rfid",
                "error": "missing",
                "message": "RFID data was not collected.",
            },
            fingerprint={
                "ok": False,
                "sensor": "fingerprint",
                "matched": False,
                "error": "timeout",
                "message": "Fingerprint service timed out.",
            },
            status_code=None,
            raw=None,
        )

        self.client.post(
            reverse("core:access-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
                "tier": self.tier1_policy.tier,
            },
        )
        session = AuthenticationSession.objects.get()

        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertContains(result_response, "Collection message")
        self.assertContains(result_response, "Node-RED request timed out.")
        self.assertContains(result_response, "RFID data was not collected.")
        self.assertContains(result_response, "Fingerprint service timed out.")

    def test_access_result_unknown_session_returns_404(self):
        response = self.client.get(reverse("core:access-result", args=[9999]))

        self.assertEqual(response.status_code, 404)
