from django.core.exceptions import ValidationError
from django.test import TestCase

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
        self.assertEqual(str(self.rfid), "Alice badge")
        self.assertEqual(str(session), f"Session {session.pk} for Server Room")
        self.assertEqual(str(audit_event), "session_started (info)")

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
