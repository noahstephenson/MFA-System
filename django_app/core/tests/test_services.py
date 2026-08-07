from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from ..models import AccessPolicy, AuditEvent, AuthenticationSession, Credential, ProtectedResource
from ..services import (
    capture_enrollment_identifier,
    create_audit_event,
    enroll_credential,
    run_node_red_access_attempt,
    start_authentication_session,
)
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
            rfid=self._rfid_ok(identifier="CARD-99999999"),
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
            knowledge_factor="99999999",
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
    def test_tier3_grants_degraded_access_when_rfid_and_knowledge_succeed_and_resource_is_approved(self, mock_collect):
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
            knowledge_factor="99999999",
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
    def test_access_mode_is_standard_for_tier2(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.resource.id,
            user_id=self.user.id,
            tier=self.tier2_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        self.assertEqual(result["session"].details["access_mode"], "standard")

    @patch("core.services.node_red_client.collect_factors")
    def test_access_mode_is_degraded_for_tier3(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        result = run_node_red_access_attempt(
            resource_id=self.degraded_resource.id,
            user_id=self.user.id,
            tier=self.degraded_tier3_policy.tier,
            knowledge_factor=self.pin.identifier,
        )

        self.assertEqual(result["session"].details["access_mode"], "degraded")

    @patch("core.services.node_red_client.collect_factors")
    def test_tier3_audit_failure_does_not_block_access(self, mock_collect):
        mock_collect.return_value = self._node_red_result(
            rfid=self._rfid_ok(),
            fingerprint=self._fingerprint_fail(),
        )

        with patch("core.services.create_audit_event") as mock_audit:
            mock_audit.side_effect = [
                None,                            # session_started succeeds
                Exception("audit unavailable"),  # factor_collection_completed
                Exception("audit unavailable"),  # authentication_succeeded
                Exception("audit unavailable"),  # authorization_granted
                Exception("audit unavailable"),  # access_granted
            ]
            result = run_node_red_access_attempt(
                resource_id=self.degraded_resource.id,
                user_id=self.user.id,
                tier=self.degraded_tier3_policy.tier,
                knowledge_factor=self.pin.identifier,
            )

        session = result["session"]
        self.assertTrue(session.is_access_granted)
        self.assertEqual(session.status, AuthenticationSession.Status.APPROVED)

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
                resource_id=99999999,
                user_id=self.user.id,
                tier=self.tier1_policy.tier,
            )

        with self.assertRaises(ValidationError):
            start_authentication_session(
                resource_id=self.resource.id,
                user_id=99999999,
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

    def test_enroll_credential_creates_new_entry(self):
        result = enroll_credential(
            user_id=self.user.id,
            credential_type=Credential.CredentialType.RFID,
            identifier="CARD-2002",
            label="Spare ATAK badge",
        )

        credential = result["credential"]
        self.assertTrue(result["created"])
        self.assertEqual(credential.identifier, "CARD-2002")
        self.assertEqual(credential.label, "Spare ATAK badge")
        self.assertTrue(credential.active)
        self.assertEqual(
            AuditEvent.objects.filter(event_type="credential_enrolled", user=self.user).count(),
            1,
        )

    def test_enroll_credential_reactivates_existing_entry(self):
        self.rfid.active = False
        self.rfid.save(update_fields=["active", "updated_at"])

        result = enroll_credential(
            user_id=self.user.id,
            credential_type=Credential.CredentialType.RFID,
            identifier=self.rfid.identifier,
            label="Primary ATAK badge",
        )

        self.rfid.refresh_from_db()
        self.assertFalse(result["created"])
        self.assertTrue(self.rfid.active)
        self.assertEqual(self.rfid.label, "Primary ATAK badge")

    @patch("core.services.node_red_client.read_rfid")
    def test_capture_enrollment_identifier_reads_badge_from_node_red(self, mock_read_rfid):
        mock_read_rfid.return_value = {
            "ok": True,
            "sensor": "rfid",
            "uid": "CARD-4004",
            "message": "",
        }

        result = capture_enrollment_identifier(
            user_id=self.user.id,
            credential_type=Credential.CredentialType.RFID,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["identifier"], "CARD-4004")
        self.assertEqual(
            AuditEvent.objects.filter(event_type="credential_capture_succeeded", user=self.user).count(),
            1,
        )
        mock_read_rfid.assert_called_once_with()

    @patch("core.services.node_red_client.enroll_fingerprint")
    def test_capture_enrollment_identifier_reads_fingerprint_from_node_red(self, mock_enroll_fingerprint):
        mock_enroll_fingerprint.return_value = {
            "ok": True,
            "sensor": "fingerprint",
            "finger_id": 9,
            "message": "",
        }

        result = capture_enrollment_identifier(
            user_id=self.user.id,
            credential_type=Credential.CredentialType.BIOMETRIC,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["identifier"], "9")
        self.assertEqual(
            AuditEvent.objects.filter(event_type="credential_capture_succeeded", user=self.user).count(),
            1,
        )
        mock_enroll_fingerprint.assert_called_once_with(
            {
                "user_id": self.user.id,
                "username": self.user.username,
            }
        )

    @patch("core.services.node_red_client.read_rfid")
    def test_capture_enrollment_identifier_handles_badge_capture_failure(self, mock_read_rfid):
        mock_read_rfid.return_value = {
            "ok": False,
            "sensor": "rfid",
            "error": "timeout",
            "message": "Node-RED request timed out.",
        }

        result = capture_enrollment_identifier(
            user_id=self.user.id,
            credential_type=Credential.CredentialType.RFID,
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["identifier"], "")
        self.assertEqual(result["message"], "Node-RED request timed out.")
        self.assertEqual(
            AuditEvent.objects.filter(event_type="credential_capture_failed", user=self.user).count(),
            1,
        )

    def test_enroll_credential_rejects_invalid_type(self):
        with self.assertRaises(ValidationError):
            enroll_credential(
                user_id=self.user.id,
                credential_type="mystery",
                identifier="1234",
            )

    def test_capture_enrollment_identifier_rejects_pin_capture(self):
        with self.assertRaises(ValidationError):
            capture_enrollment_identifier(
                user_id=self.user.id,
                credential_type=Credential.CredentialType.PIN,
            )


class ScopeMonotonicityAndAuditSinkTests(CoreTestDataMixin, TestCase):
    """Covers ProtectedResource.minimum_tier / SCOPE_MONOTONICITY_ENABLED and
    the AUDIT_SINK_AVAILABLE test hook used for the paper's before/after
    measurements. See CLAUDE.md for the corrected tier-assurance ordering."""

    def _factor_result(self, *, rfid_ok=True, fingerprint_ok=False):
        return {
            "ok": True,
            "error": "",
            "message": "",
            "rfid": (
                {"ok": True, "sensor": "rfid", "uid": self.rfid.identifier, "message": ""}
                if rfid_ok
                else {
                    "ok": False,
                    "sensor": "rfid",
                    "error": "not_found",
                    "message": "RFID factor was not accepted.",
                }
            ),
            "fingerprint": (
                {
                    "ok": True,
                    "sensor": "fingerprint",
                    "matched": True,
                    "finger_id": self.biometric.identifier,
                    "confidence": 87,
                    "message": "",
                }
                if fingerprint_ok
                else {
                    "ok": False,
                    "sensor": "fingerprint",
                    "matched": False,
                    "error": "not_matched",
                    "message": "Fingerprint not matched.",
                }
            ),
            "raw": {},
            "status_code": 200,
        }

    @patch("core.services.node_red_client.collect_factors")
    def test_monotonicity_denies_weaker_tier_when_enabled(self, mock_collect):
        resource = ProtectedResource.objects.create(
            name="High Assurance Resource",
            minimum_tier=AccessPolicy.Tier.BASIC,
        )
        AccessPolicy.objects.create(
            resource=resource,
            name="Tier 2 Policy",
            tier=AccessPolicy.Tier.ELEVATED,
            required_factor_count=2,
        )
        mock_collect.return_value = self._factor_result(rfid_ok=True, fingerprint_ok=False)

        with override_settings(SCOPE_MONOTONICITY_ENABLED=True):
            result = run_node_red_access_attempt(
                resource_id=resource.id,
                user_id=self.user.id,
                tier=AccessPolicy.Tier.ELEVATED,
                knowledge_factor=self.pin.identifier,
            )

        session = result["session"]
        details = session.details or {}
        self.assertTrue(details["authentication_result"]["ok"])
        self.assertFalse(details["authorization_result"]["ok"])
        self.assertEqual(details["authorization_result"]["reason_code"], "insufficient_tier_assurance")
        self.assertFalse(session.is_access_granted)

    @patch("core.services.node_red_client.collect_factors")
    def test_monotonicity_disabled_matches_pre_existing_behavior(self, mock_collect):
        resource = ProtectedResource.objects.create(
            name="High Assurance Resource",
            minimum_tier=AccessPolicy.Tier.BASIC,
        )
        AccessPolicy.objects.create(
            resource=resource,
            name="Tier 2 Policy",
            tier=AccessPolicy.Tier.ELEVATED,
            required_factor_count=2,
        )
        mock_collect.return_value = self._factor_result(rfid_ok=True, fingerprint_ok=False)

        with override_settings(SCOPE_MONOTONICITY_ENABLED=False):
            result = run_node_red_access_attempt(
                resource_id=resource.id,
                user_id=self.user.id,
                tier=AccessPolicy.Tier.ELEVATED,
                knowledge_factor=self.pin.identifier,
            )

        session = result["session"]
        authorization_result = (session.details or {})["authorization_result"]
        self.assertTrue(authorization_result["ok"])
        self.assertNotIn("reason_code", authorization_result)
        self.assertTrue(session.is_access_granted)

    @patch("core.services.node_red_client.collect_factors")
    def test_monotonicity_allows_matching_or_stronger_tier(self, mock_collect):
        resource = ProtectedResource.objects.create(
            name="High Assurance Resource",
            minimum_tier=AccessPolicy.Tier.BASIC,
        )
        AccessPolicy.objects.create(
            resource=resource,
            name="Tier 1 Policy",
            tier=AccessPolicy.Tier.BASIC,
            required_factor_count=2,
        )
        mock_collect.return_value = self._factor_result(rfid_ok=True, fingerprint_ok=True)

        with override_settings(SCOPE_MONOTONICITY_ENABLED=True):
            result = run_node_red_access_attempt(
                resource_id=resource.id,
                user_id=self.user.id,
                tier=AccessPolicy.Tier.BASIC,
            )

        session = result["session"]
        self.assertTrue(session.is_access_granted)

    @patch("core.services.node_red_client.collect_factors")
    def test_monotonicity_does_not_affect_tier3_degraded_access_checks(self, mock_collect):
        mock_collect.return_value = self._factor_result(rfid_ok=True, fingerprint_ok=False)

        for monotonicity_enabled in (True, False):
            with self.subTest(monotonicity_enabled=monotonicity_enabled), override_settings(
                SCOPE_MONOTONICITY_ENABLED=monotonicity_enabled
            ):
                granted_result = run_node_red_access_attempt(
                    resource_id=self.degraded_resource.id,
                    user_id=self.user.id,
                    tier=self.degraded_tier3_policy.tier,
                    knowledge_factor=self.pin.identifier,
                )
                self.assertTrue(granted_result["session"].is_access_granted)

                denied_result = run_node_red_access_attempt(
                    resource_id=self.resource.id,
                    user_id=self.user.id,
                    tier=self.tier3_policy.tier,
                    knowledge_factor=self.pin.identifier,
                )
                denied_session = denied_result["session"]
                self.assertFalse(denied_session.is_access_granted)
                self.assertEqual(
                    (denied_session.details or {})["authorization_result"]["message"],
                    "Selected resource is not approved for Tier 3 degraded access.",
                )

    def test_audit_sink_unavailable_raises(self):
        with override_settings(AUDIT_SINK_AVAILABLE=False):
            with self.assertRaises(RuntimeError):
                create_audit_event("test_event", "test message")

        # Sanity check: the sink works normally once available again (default).
        create_audit_event("test_event", "test message")
        self.assertEqual(AuditEvent.objects.filter(event_type="test_event").count(), 1)
