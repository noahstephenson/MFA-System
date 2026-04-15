from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase

from ..models import AuditEvent, AuthenticationSession
from ..services import run_node_red_access_attempt, start_authentication_session
from .base import CoreTestDataMixin


class MVPServiceTests(CoreTestDataMixin, TestCase):
    def test_start_authentication_session_uses_selected_resource_and_tier(self):
        session = start_authentication_session(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier1_policy.tier,
        )

        self.assertEqual(session.resource, self.resource)
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.policy, self.tier1_policy)
        self.assertEqual(session.status, AuthenticationSession.Status.IN_PROGRESS)
        self.assertEqual(session.decision, AuthenticationSession.Decision.PENDING)
        self.assertEqual((session.details or {})["selected_tier"], self.tier1_policy.tier)
        self.assertEqual(
            (session.details or {})["required_factor_types"],
            ["rfid", "biometric"],
        )
        self.assertEqual(AuditEvent.objects.filter(event_type="session_started").count(), 1)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_requires_rfid_and_fingerprint(self, mock_collect):
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
            tier=self.tier1_policy.tier,
        )

        session = result["session"]
        self.assertTrue((session.details or {})["authentication_result"]["ok"])
        self.assertTrue((session.details or {})["authorization_result"]["ok"])
        self.assertEqual(session.status, AuthenticationSession.Status.APPROVED)
        self.assertTrue(session.is_access_granted)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier2_requires_rfid_and_knowledge_not_fingerprint(self, mock_collect):
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

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier2_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        authentication_result = (session.details or {})["authentication_result"]
        self.assertTrue(authentication_result["ok"])
        self.assertEqual(authentication_result["verified_factor_types"], ["rfid", "pin"])
        self.assertEqual(session.status, AuthenticationSession.Status.APPROVED)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier2_denies_with_wrong_knowledge_factor(self, mock_collect):
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
                "message": "",
            },
            "raw": {},
            "status_code": 200,
        }

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier2_policy.tier,
            knowledge_factor="9999",
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertEqual(
            (session.details or {})["authentication_result"]["message"],
            "Knowledge factor did not match the enrolled credential.",
        )
        self.assertEqual(session.status, AuthenticationSession.Status.DENIED)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier3_requires_degraded_approved_resource_after_authentication(self, mock_collect):
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
            tier=self.tier3_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        self.assertTrue((session.details or {})["authentication_result"]["ok"])
        self.assertFalse((session.details or {})["authorization_result"]["ok"])
        self.assertEqual(
            (session.details or {})["authorization_result"]["message"],
            "Selected resource is not approved for Tier 3 degraded access.",
        )
        self.assertFalse(session.is_access_granted)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier3_grants_when_resource_is_degraded_approved(self, mock_collect):
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
            resource_id=self.degraded_resource.id,
            user_id=self.user.id,
            tier=self.degraded_tier3_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        self.assertTrue((session.details or {})["authentication_result"]["ok"])
        self.assertTrue((session.details or {})["authorization_result"]["ok"])
        self.assertTrue(session.is_access_granted)

    @patch("core.services.node_red_client.collect_factors")
    def test_timeout_denies_authentication(self, mock_collect):
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
            tier=self.tier1_policy.tier,
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertEqual(session.status, AuthenticationSession.Status.DENIED)
        self.assertEqual(AuditEvent.objects.filter(event_type="authentication_failed", session=session).count(), 1)

    def test_start_authentication_session_rejects_invalid_user_resource_and_tier(self):
        with self.assertRaises(ValidationError):
            start_authentication_session(resource_id=9999, user_id=self.user.id, tier=self.tier1_policy.tier)

        with self.assertRaises(ValidationError):
            start_authentication_session(resource_id=self.resource.id, user_id=9999, tier=self.tier1_policy.tier)

        with self.assertRaises(ValidationError):
            start_authentication_session(resource_id=self.resource.id, user_id=self.user.id, tier="tier9")
