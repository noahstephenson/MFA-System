from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from ..models import AuditEvent, AuthenticationSession
from .base import CoreTestDataMixin


class CoreModelTests(CoreTestDataMixin, TestCase):
    def test_model_string_representations_are_readable(self):
        session = AuthenticationSession.objects.create(
            user=self.user,
            resource=self.resource,
            policy=self.policy,
        )
        audit_event = AuditEvent.objects.create(
            event_type="session_started",
            message="Authentication session started.",
            session=session,
            user=self.user,
        )

        self.assertEqual(str(self.resource), "Server Room")
        self.assertEqual(str(self.policy), "Server Room - Default Policy")
        self.assertEqual(str(self.rfid), "alice - RFID - Alice badge")
        self.assertEqual(str(session), f"Session {session.pk} - Server Room - Pending")
        self.assertEqual(str(audit_event), "Info - session_started")

    def test_credential_belongs_to_user_and_resource_policy_relationship_is_available(self):
        self.assertEqual(self.rfid.user, self.user)
        self.assertEqual(self.policy.resource, self.resource)
        self.assertEqual(self.resource.policies.count(), 1)

    def test_session_progress_properties_read_from_details(self):
        session = AuthenticationSession.objects.create(
            user=self.user,
            resource=self.resource,
            policy=self.policy,
            details={
                "accepted_factor_keys": ["rfid:CARD-1001"],
                "submitted_factors": [
                    {
                        "credential_type": "rfid",
                        "identifier": "CARD-1001",
                        "matched": True,
                    }
                ],
            },
        )

        self.assertEqual(session.required_factor_count, 2)
        self.assertEqual(session.accepted_factor_count, 1)
        self.assertEqual(len(session.submitted_factors), 1)

    def test_access_policy_rejects_zero_required_factors(self):
        self.policy.required_factor_count = 0

        with self.assertRaises(ValidationError):
            self.policy.full_clean()

    def test_session_defaults_to_single_factor_when_no_policy_is_attached(self):
        session = AuthenticationSession.objects.create(
            user=self.user,
            resource=self.resource,
        )

        self.assertEqual(session.required_factor_count, 1)
        self.assertEqual(session.remaining_factor_count, 1)
        self.assertFalse(session.is_complete)
        self.assertFalse(session.is_access_granted)

    def test_session_clean_rejects_inconsistent_completion_state(self):
        session = AuthenticationSession(
            user=self.user,
            resource=self.resource,
            policy=self.policy,
            status=AuthenticationSession.Status.APPROVED,
            decision=AuthenticationSession.Decision.PENDING,
            current_step=2,
            completed_at=None,
            details={
                "accepted_factor_keys": [
                    "rfid:CARD-1001",
                    "pin:2468",
                ],
                "submitted_factors": [
                    {"credential_type": "rfid", "identifier": "CARD-1001", "matched": True},
                    {"credential_type": "pin", "identifier": "2468", "matched": True},
                ],
            },
        )

        with self.assertRaises(ValidationError) as context:
            session.full_clean()

        self.assertIn("decision", context.exception.message_dict)
        self.assertIn("completed_at", context.exception.message_dict)

    def test_session_clean_allows_coherent_approved_state(self):
        session = AuthenticationSession(
            user=self.user,
            resource=self.resource,
            policy=self.policy,
            status=AuthenticationSession.Status.APPROVED,
            decision=AuthenticationSession.Decision.GRANTED,
            current_step=2,
            completed_at=timezone.now(),
            details={
                "accepted_factor_keys": [
                    "rfid:CARD-1001",
                    "pin:2468",
                ],
                "submitted_factors": [
                    {"credential_type": "rfid", "identifier": "CARD-1001", "matched": True},
                    {"credential_type": "pin", "identifier": "2468", "matched": True},
                ],
            },
        )

        session.full_clean()
