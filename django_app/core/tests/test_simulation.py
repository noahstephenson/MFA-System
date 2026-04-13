from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from ..models import AuthenticationSession, AuditEvent, Credential
from .base import CoreTestDataMixin


class MVPAccessFlowTests(CoreTestDataMixin, TestCase):
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
    def test_html_access_flow_grants_access(self, mock_collect):
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
            follow=True,
        )

        session = AuthenticationSession.objects.get()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Access granted")
        self.assertEqual(session.status, AuthenticationSession.Status.APPROVED)
        self.assertEqual(AuditEvent.objects.filter(event_type="access_granted", session=session).count(), 1)

    @patch("core.services.node_red_client.collect_factors")
    def test_html_access_flow_denies_access_when_node_red_returns_invalid_result(self, mock_collect):
        mock_collect.return_value = {
            "ok": False,
            "error": "invalid_json",
            "message": "Node-RED returned invalid JSON.",
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

        response = self.client.post(
            reverse("core:access-start-submit"),
            {"user": self.user.id, "resource": self.resource.id},
            follow=True,
        )

        session = AuthenticationSession.objects.get()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Access denied")
        self.assertEqual(session.status, AuthenticationSession.Status.DENIED)
        self.assertEqual(AuditEvent.objects.filter(event_type="session_denied", session=session).count(), 1)

    @patch("core.services.node_red_client.collect_factors")
    def test_html_access_flow_denies_access_when_combined_result_is_partial(self, mock_collect):
        mock_collect.return_value = {
            "ok": True,
            "error": "",
            "message": "",
            "rfid": {"ok": True, "uid": self.rfid.identifier},
            "fingerprint": {
                "ok": False,
                "sensor": "fingerprint",
                "matched": False,
                "error": "missing",
                "message": "Fingerprint data was not returned.",
            },
            "raw": {},
            "status_code": 200,
        }

        response = self.client.post(
            reverse("core:access-start-submit"),
            {"user": self.user.id, "resource": self.resource.id},
            follow=True,
        )

        session = AuthenticationSession.objects.get()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Fingerprint data was not returned.")
        self.assertEqual(session.status, AuthenticationSession.Status.DENIED)
