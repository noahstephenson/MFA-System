from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase

from ..models import AccessPolicy, AuditEvent, AuthenticationSession, ProtectedResource
from ..services import run_node_red_access_attempt, start_authentication_session
from .base import CoreTestDataMixin


class MVPServiceTests(CoreTestDataMixin, TestCase):
    def test_start_authentication_session_creates_session_and_audit_event(self):
        session = start_authentication_session(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )

        self.assertEqual(session.resource, self.resource)
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.policy, self.policy)
        self.assertEqual(session.status, AuthenticationSession.Status.IN_PROGRESS)
        self.assertEqual(session.decision, AuthenticationSession.Decision.PENDING)
        self.assertEqual(AuditEvent.objects.filter(event_type="session_started").count(), 1)

    @patch("core.services.node_red_client.collect_factors")
    def test_run_node_red_access_attempt_grants_on_matching_rfid_and_fingerprint(self, mock_collect):
        mock_collect.return_value = {
            "ok": True,
            "error": "",
            "message": "",
            "rfid": {"ok": True, "sensor": "rfid", "uid": self.rfid.identifier, "message": ""},
            "fingerprint": {
                "ok": True,
                "sensor": "fingerprint",
                "matched": True,
                "finger_id": 4,
                "confidence": 87,
                "message": "",
            },
            "raw": {},
            "status_code": 200,
        }

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )

        session = result["session"]
        self.assertEqual(session.status, AuthenticationSession.Status.APPROVED)
        self.assertEqual(session.decision, AuthenticationSession.Decision.GRANTED)
        self.assertTrue(session.is_access_granted)
        self.assertEqual(session.accepted_factor_count, 2)
        self.assertEqual(AuditEvent.objects.filter(event_type="access_granted", session=session).count(), 1)

    @patch("core.services.node_red_client.collect_factors")
    def test_run_node_red_access_attempt_denies_on_negative_fingerprint_result(self, mock_collect):
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

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )

        session = result["session"]
        self.assertEqual(session.status, AuthenticationSession.Status.DENIED)
        self.assertEqual(session.decision, AuthenticationSession.Decision.REJECTED)
        self.assertFalse(session.is_access_granted)
        self.assertEqual((session.details or {})["result_message"], "Fingerprint not matched.")

    @patch("core.services.node_red_client.collect_factors")
    def test_run_node_red_access_attempt_denies_on_timeout_and_stores_message(self, mock_collect):
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

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )

        session = result["session"]
        self.assertEqual(session.status, AuthenticationSession.Status.DENIED)
        self.assertEqual((session.details or {})["result_message"], "Fingerprint service timed out.")
        self.assertEqual(AuditEvent.objects.filter(event_type="access_denied", session=session).count(), 1)

    def test_start_authentication_session_rejects_invalid_user_resource_and_policy(self):
        with self.assertRaises(ValidationError):
            start_authentication_session(resource_id=9999, user_id=self.user.id)

        with self.assertRaises(ValidationError):
            start_authentication_session(resource_id=self.resource.id, user_id=9999)

        other_resource = ProtectedResource.objects.create(name="Vault", description="Separate area")
        other_policy = AccessPolicy.objects.create(
            resource=other_resource,
            name="Vault Policy",
            description="Not for the server room.",
            required_factor_count=1,
        )

        with self.assertRaises(ValidationError):
            start_authentication_session(
                resource_id=self.resource.id,
                user_id=self.user.id,
                policy_id=other_policy.id,
            )
