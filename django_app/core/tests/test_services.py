from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase

from ..models import AuditEvent, AuthenticationSession, Credential, ProtectedResource
from ..services import run_node_red_access_attempt, start_authentication_session
from .base import CoreTestDataMixin


class MVPServiceTests(CoreTestDataMixin, TestCase):
    _UNSET = object()

    def _node_red_result(
        self,
        *,
        ok=True,
        message="",
        error="",
        rfid=None,
        fingerprint=None,
        status_code=200,
        raw=_UNSET,
    ):
        if raw is self._UNSET:
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

    def _rfid_ok(self, identifier=None):
        return {
            "ok": True,
            "sensor": "rfid",
            "uid": identifier or self.rfid.identifier,
            "message": "",
        }

    def _rfid_fail(self, *, error="not_found", message="RFID factor was not accepted."):
        return {
            "ok": False,
            "sensor": "rfid",
            "error": error,
            "message": message,
        }

    def _fingerprint_ok(self, finger_id=4):
        return {
            "ok": True,
            "sensor": "fingerprint",
            "matched": True,
            "finger_id": finger_id,
            "confidence": 87,
            "message": "",
        }

    def _fingerprint_fail(self, *, error="not_matched", message="Fingerprint not matched."):
        return {
            "ok": False,
            "sensor": "fingerprint",
            "matched": False,
            "error": error,
            "message": message,
        }

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
            [Credential.CredentialType.RFID, Credential.CredentialType.BIOMETRIC],
        )
        self.assertEqual(AuditEvent.objects.filter(event_type="session_started").count(), 1)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_success_requires_rfid_and_fingerprint(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_ok(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier1_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        self.assertTrue(session.is_access_granted)
        self.assertEqual(
            (session.details or {})["authentication_result"]["verified_factor_types"],
            [Credential.CredentialType.RFID, Credential.CredentialType.BIOMETRIC],
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_denies_when_only_rfid_succeeds(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier1_policy.tier,
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertFalse((session.details or {})["authorization_result"]["ok"])
        self.assertFalse(session.is_access_granted)
        self.assertEqual((session.details or {})["result_message"], "Fingerprint not matched.")

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_denies_when_only_fingerprint_succeeds(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_fail(message="RFID read failed."),
            fingerprint=self._fingerprint_ok(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier1_policy.tier,
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertEqual((session.details or {})["authentication_result"]["message"], "RFID read failed.")
        self.assertFalse(session.is_access_granted)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_denies_on_wrong_fingerprint(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_ok(finger_id=99),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier1_policy.tier,
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertEqual(
            (session.details or {})["authentication_result"]["message"],
            "Fingerprint credential is not enrolled for this user.",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_denies_on_wrong_rfid(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(identifier="CARD-9999"),
            fingerprint=self._fingerprint_ok(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier1_policy.tier,
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertEqual(
            (session.details or {})["authentication_result"]["message"],
            "RFID credential is not enrolled for this user.",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_does_not_accept_rfid_plus_knowledge_in_place_of_fingerprint(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier1_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        authentication_result = (session.details or {})["authentication_result"]
        self.assertFalse(authentication_result["ok"])
        self.assertEqual(
            authentication_result["verified_factor_types"],
            [Credential.CredentialType.RFID],
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_denies_on_partial_node_red_payload(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="invalid_payload",
            message="Node-RED returned an invalid factor payload.",
            rfid=self._rfid_ok(),
            fingerprint={},
            raw={"ok": True, "rfid": {"ok": True, "uid": self.rfid.identifier}, "fingerprint": {}},
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier1_policy.tier,
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertEqual(
            (session.details or {})["authentication_result"]["message"],
            "Fingerprint factor was not returned by Node-RED.",
        )
        self.assertEqual(
            AuditEvent.objects.filter(event_type="factor_collection_completed", session=session).count(),
            1,
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_tier1_denies_on_wrong_data_types_from_node_red(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="invalid_payload",
            message="Node-RED returned an invalid factor payload.",
            rfid={"ok": False, "sensor": "rfid", "error": "invalid_payload", "message": "RFID payload was missing."},
            fingerprint={
                "ok": False,
                "sensor": "fingerprint",
                "matched": False,
                "error": "invalid_payload",
                "message": "Fingerprint payload was missing.",
            },
            raw={"ok": True, "rfid": [], "fingerprint": "bad"},
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier1_policy.tier,
        )

        session = result["session"]
        self.assertFalse(session.is_access_granted)
        self.assertEqual(
            (session.details or {})["factor_collection_result"]["error"],
            "invalid_payload",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_tier2_success_requires_rfid_and_knowledge(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier2_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        authentication_result = (session.details or {})["authentication_result"]
        self.assertTrue(authentication_result["ok"])
        self.assertEqual(
            authentication_result["verified_factor_types"],
            [Credential.CredentialType.RFID, Credential.CredentialType.PIN],
        )
        self.assertTrue(session.is_access_granted)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier2_denies_with_correct_rfid_and_wrong_knowledge_factor(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_ok(),
        )

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

    @patch("core.services.node_red_client.collect_factors")
    def test_tier2_denies_when_rfid_fails_even_if_knowledge_is_correct(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_fail(message="RFID read failed."),
            fingerprint=self._fingerprint_ok(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier2_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertEqual((session.details or {})["authentication_result"]["message"], "RFID read failed.")
        self.assertFalse((session.details or {})["authorization_result"]["ok"])

    @patch("core.services.node_red_client.collect_factors")
    def test_tier2_ignores_fingerprint_when_it_is_present_but_not_required(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier2_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        self.assertTrue((session.details or {})["authentication_result"]["ok"])
        self.assertNotIn(
            Credential.CredentialType.BIOMETRIC,
            (session.details or {})["authentication_result"]["verified_factor_types"],
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_tier2_denies_when_node_red_times_out(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="timeout",
            message="Fingerprint service timed out.",
            rfid={"ok": False, "sensor": "rfid", "error": "missing", "message": "RFID data was not collected."},
            fingerprint=self._fingerprint_fail(error="timeout", message="Fingerprint service timed out."),
            status_code=None,
            raw=None,
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier2_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertEqual(
            AuditEvent.objects.filter(event_type="factor_collection_failed", session=session).count(),
            1,
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_tier2_denies_when_node_red_returns_malformed_payload(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="invalid_payload",
            message="Node-RED returned an invalid factor payload.",
            rfid={},
            fingerprint={},
            raw={"ok": True},
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier2_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertEqual(
            (session.details or {})["factor_collection_result"]["error"],
            "invalid_payload",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_tier3_success_requires_rfid_knowledge_and_degraded_approved_resource(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

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
    def test_tier3_denies_when_resource_is_not_approved_for_degraded_access(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier3_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        self.assertTrue((session.details or {})["authentication_result"]["ok"])
        self.assertFalse((session.details or {})["authorization_result"]["ok"])
        self.assertFalse(session.is_access_granted)

    @patch("core.services.node_red_client.collect_factors")
    def test_tier3_denies_with_wrong_knowledge_factor(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.degraded_resource.id,
            user_id=self.user.id,
            tier=self.degraded_tier3_policy.tier,
            knowledge_factor="9999",
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertFalse((session.details or {})["authorization_result"]["ok"])
        self.assertEqual(
            (session.details or {})["authorization_result"]["message"],
            "Authorization denied because authentication failed.",
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_tier3_denies_when_rfid_fails(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_fail(message="RFID read failed."),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.degraded_resource.id,
            user_id=self.user.id,
            tier=self.degraded_tier3_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        self.assertFalse((session.details or {})["authentication_result"]["ok"])
        self.assertFalse((session.details or {})["authorization_result"]["ok"])

    @patch("core.services.node_red_client.collect_factors")
    def test_tier3_ignores_fingerprint_when_present_but_not_required(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=True,
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_ok(finger_id=99),
        )

        result = run_node_red_access_attempt(
            resource_id=self.degraded_resource.id,
            user_id=self.user.id,
            tier=self.degraded_tier3_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        self.assertTrue((session.details or {})["authentication_result"]["ok"])
        self.assertNotIn(
            Credential.CredentialType.BIOMETRIC,
            (session.details or {})["authentication_result"]["verified_factor_types"],
        )

    @patch("core.services.node_red_client.collect_factors")
    def test_authentication_and_authorization_results_are_stored_separately(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier3_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        details = session.details or {}
        self.assertTrue(details["authentication_result"]["ok"])
        self.assertFalse(details["authorization_result"]["ok"])
        self.assertIn("result_message", details)
        self.assertIn("factor_collection_result", details)

    @patch("core.services.node_red_client.collect_factors")
    def test_audit_events_capture_auth_and_authorization_outcomes(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            ok=False,
            error="not_matched",
            message="Fingerprint not matched.",
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier3_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        session = result["session"]
        event_types = list(
            AuditEvent.objects.filter(session=session).order_by("id").values_list("event_type", flat=True)
        )
        self.assertEqual(
            event_types,
            [
                "session_started",
                "factor_collection_completed",
                "authentication_succeeded",
                "authorization_denied",
                "access_denied",
            ],
        )

    def test_start_authentication_session_rejects_invalid_user_resource_and_tier(self):
        with self.assertRaises(ValidationError):
            start_authentication_session(
                resource_id=9999,
                user_id=self.user.id,
                tier=self.tier1_policy.tier,
            )

        with self.assertRaises(ValidationError):
            start_authentication_session(
                resource_id=self.resource.id,
                user_id=9999,
                tier=self.tier1_policy.tier,
            )

        with self.assertRaises(ValidationError):
            start_authentication_session(
                resource_id=self.resource.id,
                user_id=self.user.id,
                tier="tier9",
            )

        other_resource = ProtectedResource.objects.create(name="Lobby Door", description="Secondary door")
        with self.assertRaises(ValidationError):
            start_authentication_session(
                resource_id=other_resource.id,
                user_id=self.user.id,
                tier=self.tier1_policy.tier,
            )
