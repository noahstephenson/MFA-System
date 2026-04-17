from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from ..models import AuthenticationSession, Credential
from .base import CoreTestDataMixin

User = get_user_model()


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

    def test_home_page_renders_primary_actions_in_operator_order(self):
        response = self.client.get(reverse("core:home"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "MFA Demo")
        self.assertContains(response, "Enroll")
        self.assertContains(response, "Access")

        content = response.content.decode("utf-8")
        self.assertLess(content.index("Enroll"), content.index("Access"))

    def test_enrollment_page_renders_operator_actions_without_manual_hardware_fields(self):
        response = self.client.get(
            f"{reverse('core:enroll')}?username=alice&credential_type={Credential.CredentialType.RFID}"
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Enroll Credentials")
        self.assertContains(response, "Credential")
        self.assertContains(response, "Scan Badge")
        self.assertNotContains(response, "Capture Fingerprint")
        self.assertNotContains(response, "Save PIN")
        self.assertNotContains(response, 'name="pin"', html=False)
        self.assertNotContains(response, "Identifier / value")
        self.assertNotContains(response, 'name="identifier"', html=False)
        self.assertNotContains(response, "Stored credentials")
        self.assertNotContains(response, "Admin")

    @patch("core.views.capture_enrollment_identifier")
    def test_badge_capture_flow_uses_hardware_result_before_save(self, mock_capture):
        mock_capture.return_value = {
            "ok": True,
            "identifier": "CARD-2002",
            "message": "Badge ready to save.",
            "capture_result": {},
        }

        capture_response = self.client.post(
            reverse("core:enroll"),
            {
                "action": "capture-rfid",
                "username": "alice",
                "credential_type": Credential.CredentialType.RFID,
            },
        )

        self.assertEqual(capture_response.status_code, 200)
        self.assertContains(capture_response, "Ready to save")
        self.assertContains(capture_response, "UID CARD-2002")
        self.assertContains(capture_response, "Save Badge")
        self.assertNotContains(capture_response, "Save Credential")

        save_response = self.client.post(
            reverse("core:enroll"),
            {
                "action": "save-rfid",
                "username": "alice",
                "credential_type": Credential.CredentialType.RFID,
                "captured_identifier": "CARD-2002",
            },
        )

        self.assertRedirects(
            save_response,
            f"{reverse('core:enroll')}?username=alice&credential_type={Credential.CredentialType.RFID}",
        )
        self.assertTrue(
            Credential.objects.filter(
                user=self.user,
                credential_type=Credential.CredentialType.RFID,
                identifier="CARD-2002",
                active=True,
            ).exists()
        )

    @patch("core.views.capture_enrollment_identifier")
    def test_fingerprint_capture_flow_uses_hardware_result_before_save(self, mock_capture):
        mock_capture.return_value = {
            "ok": True,
            "identifier": "7",
            "message": "Fingerprint ready to save.",
            "capture_result": {},
        }

        capture_response = self.client.post(
            reverse("core:enroll"),
            {
                "action": "capture-fingerprint",
                "username": "alice",
                "credential_type": Credential.CredentialType.BIOMETRIC,
            },
        )

        self.assertEqual(capture_response.status_code, 200)
        self.assertContains(capture_response, "Ready to save")
        self.assertContains(capture_response, "ID 7")
        self.assertContains(capture_response, "Save Fingerprint")
        self.assertNotContains(capture_response, "Save Credential")

        save_response = self.client.post(
            reverse("core:enroll"),
            {
                "action": "save-fingerprint",
                "username": "alice",
                "credential_type": Credential.CredentialType.BIOMETRIC,
                "captured_identifier": "7",
            },
        )

        self.assertRedirects(
            save_response,
            f"{reverse('core:enroll')}?username=alice&credential_type={Credential.CredentialType.BIOMETRIC}",
        )
        self.assertTrue(
            Credential.objects.filter(
                user=self.user,
                credential_type=Credential.CredentialType.BIOMETRIC,
                identifier="7",
                active=True,
            ).exists()
        )

    def test_pin_enrollment_is_manual(self):
        response = self.client.post(
            reverse("core:enroll"),
            {
                "action": "save-pin",
                "username": "alice",
                "credential_type": Credential.CredentialType.PIN,
                "pin": "87654321",
                "label": "Shift PIN",
            },
        )

        self.assertRedirects(
            response,
            f"{reverse('core:enroll')}?username=alice&credential_type={Credential.CredentialType.PIN}",
        )
        self.assertTrue(
            Credential.objects.filter(
                user=self.user,
                credential_type=Credential.CredentialType.PIN,
                identifier="87654321",
                label="Shift PIN",
                active=True,
            ).exists()
        )

    def test_pin_enrollment_creates_typed_subject(self):
        response = self.client.post(
            reverse("core:enroll"),
            {
                "action": "save-pin",
                "username": "Noah",
                "credential_type": Credential.CredentialType.PIN,
                "pin": "12345678",
            },
        )

        user = User.objects.get(username="noah")
        self.assertRedirects(
            response,
            f"{reverse('core:enroll')}?username=noah&credential_type={Credential.CredentialType.PIN}",
        )
        self.assertTrue(
            Credential.objects.filter(
                user=user,
                credential_type=Credential.CredentialType.PIN,
                identifier="12345678",
                active=True,
            ).exists()
        )

    def test_pin_enrollment_requires_exactly_eight_digits(self):
        response = self.client.post(
            reverse("core:enroll"),
            {
                "action": "save-pin",
                "username": "alice",
                "credential_type": Credential.CredentialType.PIN,
                "pin": "1234",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "PIN must be exactly 8 digits.")
        self.assertFalse(
            Credential.objects.filter(
                user=self.user,
                credential_type=Credential.CredentialType.PIN,
                identifier="1234",
            ).exists()
        )

    def test_enrollment_page_changes_by_credential_type(self):
        rfid_response = self.client.get(
            f"{reverse('core:enroll')}?username=alice&credential_type={Credential.CredentialType.RFID}"
        )
        pin_response = self.client.get(
            f"{reverse('core:enroll')}?username=alice&credential_type={Credential.CredentialType.PIN}"
        )

        self.assertContains(rfid_response, "Scan badge")
        self.assertNotContains(rfid_response, "Enter PIN")
        self.assertNotContains(rfid_response, 'name="pin"', html=False)
        self.assertNotContains(rfid_response, "Stored credentials")
        self.assertContains(pin_response, "Enter PIN")
        self.assertContains(pin_response, 'name="pin"', html=False)
        self.assertNotContains(pin_response, "Scan Badge")

    @patch("core.views.capture_enrollment_identifier")
    def test_enrollment_capture_failure_is_shown_cleanly(self, mock_capture):
        mock_capture.return_value = {
            "ok": False,
            "identifier": "",
            "message": "Node-RED request timed out.",
            "capture_result": {"error": "timeout"},
        }

        response = self.client.post(
            reverse("core:enroll"),
            {
                "action": "capture-rfid",
                "username": "alice",
                "credential_type": Credential.CredentialType.RFID,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Capture failed")
        self.assertContains(response, "Factor service timed out.")
        self.assertNotContains(response, "Save Badge")

    def test_access_start_page_loads_with_operator_sections_and_factor_cards(self):
        response = self.client.get(reverse("core:access-start"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Start access request")
        self.assertContains(response, "Request setup")
        self.assertContains(response, "Required factors")
        self.assertContains(response, "Run Access Check")
        self.assertContains(response, "Badge")
        self.assertContains(response, "Fingerprint")
        self.assertContains(response, "PIN")

    def test_access_start_page_shows_tier2_factor_states(self):
        response = self.client.post(
            reverse("core:access-start"),
            {
                "username": "alice",
                "resource": self.resource.id,
                "tier": self.tier2_policy.tier,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Tier 2: Badge + PIN")
        self.assertContains(response, "Not Required")
        self.assertContains(response, "Enter a PIN.")
        self.assertEqual(AuthenticationSession.objects.count(), 0)

    def test_access_start_requires_exactly_eight_digit_pin_for_tier2(self):
        response = self.client.post(
            reverse("core:access-start"),
            {
                "username": "alice",
                "resource": self.resource.id,
                "tier": self.tier2_policy.tier,
                "knowledge_factor": "1234567A",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "PIN must be exactly 8 digits.")
        self.assertEqual(AuthenticationSession.objects.count(), 0)

    def test_access_start_page_shows_tier3_factor_states(self):
        response = self.client.post(
            reverse("core:access-start"),
            {
                "username": "alice",
                "resource": self.degraded_resource.id,
                "tier": self.degraded_tier3_policy.tier,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Tier 3: Badge + PIN (degraded access to approved functions only)")
        self.assertContains(response, "PIN")
        self.assertContains(response, "Not Required")
        self.assertEqual(AuthenticationSession.objects.count(), 0)

    def test_invalid_form_submission_rerenders_cleanly_with_useful_errors(self):
        response = self.client.post(
            reverse("core:access-start"),
            {
                "username": "alice",
                "resource": self.resource.id,
                "tier": "tier-99",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Select a valid choice")
        self.assertContains(response, "Start access request")
        self.assertEqual(AuthenticationSession.objects.count(), 0)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_result_page_shows_factor_states(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_ok(),
        )

        response = self.client.post(
            reverse("core:access-start"),
            {"username": "alice", "resource": self.resource.id, "tier": self.tier1_policy.tier},
        )
        session = AuthenticationSession.objects.get()

        self.assertRedirects(response, reverse("core:access-result", args=[session.id]))
        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertContains(result_response, "Access granted")
        self.assertContains(result_response, "Factor results")
        self.assertContains(result_response, "Accepted")
        self.assertContains(result_response, "ID 4")
        self.assertContains(result_response, "Not Required")

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
                "username": "alice",
                "resource": self.resource.id,
                "tier": self.tier3_policy.tier,
                "knowledge_factor": self.pin.identifier,
            },
        )
        session = AuthenticationSession.objects.get()

        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertContains(result_response, "Access denied")
        self.assertContains(result_response, "Resource check")
        self.assertContains(result_response, "Resource is not approved for Tier 3 access.")
        self.assertContains(result_response, "Fingerprint")
        self.assertContains(result_response, "Not Required")

    @patch("core.services.node_red_client.collect_factors")
    def test_result_page_hides_node_red_language(self, mock_collect):
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
                "username": "alice",
                "resource": self.resource.id,
                "tier": self.tier1_policy.tier,
            },
        )
        session = AuthenticationSession.objects.get()

        result_response = self.client.get(reverse("core:access-result", args=[session.id]))
        self.assertNotContains(result_response, "Node-RED")
        self.assertContains(result_response, "Factors received with errors.")
        self.assertContains(result_response, "Badge scan unavailable.")
        self.assertContains(result_response, "Fingerprint service timed out.")

    def test_access_result_unknown_session_returns_404(self):
        response = self.client.get(reverse("core:access-result", args=[99999999]))

        self.assertEqual(response.status_code, 404)
