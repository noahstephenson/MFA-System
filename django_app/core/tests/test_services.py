from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from ..models import AccessPolicy, AuditEvent, AuthenticationSession, Credential, ProtectedResource
from ..services import (
    deny_authentication_session,
    start_authentication_session,
    submit_authentication_factor,
)
from .base import CoreTestDataMixin

User = get_user_model()


class AuthenticationServiceTests(CoreTestDataMixin, TestCase):
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

    def test_submit_authentication_factor_flow_approves_session_after_required_factors(self):
        session = start_authentication_session(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )

        first_result = submit_authentication_factor(
            session_id=session.id,
            credential_type=Credential.CredentialType.RFID,
            identifier=self.rfid.identifier,
        )
        session.refresh_from_db()

        self.assertTrue(first_result["accepted"])
        self.assertEqual(session.status, AuthenticationSession.Status.IN_PROGRESS)
        self.assertEqual(session.accepted_factor_count, 1)

        second_result = submit_authentication_factor(
            session_id=session.id,
            credential_type=Credential.CredentialType.PIN,
            identifier=self.pin.identifier,
        )
        session.refresh_from_db()

        self.assertTrue(second_result["accepted"])
        self.assertEqual(session.status, AuthenticationSession.Status.APPROVED)
        self.assertEqual(session.decision, AuthenticationSession.Decision.GRANTED)
        self.assertIsNotNone(session.completed_at)
        self.assertEqual(
            AuditEvent.objects.filter(event_type="session_approved", session=session).count(),
            1,
        )

    def test_submit_authentication_factor_rejects_unknown_factor(self):
        session = start_authentication_session(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )

        result = submit_authentication_factor(
            session_id=session.id,
            credential_type=Credential.CredentialType.BIOMETRIC,
            identifier="missing-scan",
        )
        session.refresh_from_db()

        self.assertFalse(result["accepted"])
        self.assertEqual(session.status, AuthenticationSession.Status.IN_PROGRESS)
        self.assertEqual(
            AuditEvent.objects.filter(event_type="factor_rejected", session=session).count(),
            1,
        )

    def test_start_authentication_session_requires_valid_resource(self):
        with self.assertRaises(ValidationError):
            start_authentication_session(resource_id=9999, user_id=self.user.id)

    def test_start_authentication_session_rejects_inactive_user(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        with self.assertRaises(ValidationError) as context:
            start_authentication_session(resource_id=self.resource.id, user_id=self.user.id)

        self.assertIn("user_id", context.exception.message_dict)

    def test_completed_session_rejects_additional_factor_submission(self):
        session = start_authentication_session(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )
        submit_authentication_factor(
            session_id=session.id,
            credential_type=Credential.CredentialType.RFID,
            identifier=self.rfid.identifier,
        )
        submit_authentication_factor(
            session_id=session.id,
            credential_type=Credential.CredentialType.PIN,
            identifier=self.pin.identifier,
        )

        with self.assertRaises(ValidationError):
            submit_authentication_factor(
                session_id=session.id,
                credential_type=Credential.CredentialType.PIN,
                identifier=self.pin.identifier,
            )

    def test_deny_authentication_session_marks_session_denied_and_logs_event(self):
        session = start_authentication_session(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )

        denied_session = deny_authentication_session(session_id=session.id, reason="Demo ended.")
        denied_session.refresh_from_db()

        self.assertEqual(denied_session.status, AuthenticationSession.Status.DENIED)
        self.assertEqual(denied_session.decision, AuthenticationSession.Decision.REJECTED)
        self.assertIsNotNone(denied_session.completed_at)
        self.assertEqual(
            AuditEvent.objects.filter(event_type="session_denied", session=denied_session).count(),
            1,
        )

    def test_start_authentication_session_rejects_policy_for_other_resource(self):
        other_resource = ProtectedResource.objects.create(name="Vault", description="Separate area")
        other_policy = AccessPolicy.objects.create(
            resource=other_resource,
            name="Vault Policy",
            required_factor_count=1,
        )

        with self.assertRaises(ValidationError) as context:
            start_authentication_session(
                resource_id=self.resource.id,
                user_id=self.user.id,
                policy_id=other_policy.id,
            )

        self.assertIn("policy_id", context.exception.message_dict)

    def test_submit_authentication_factor_persists_user_for_anonymous_single_factor_session(self):
        quick_policy = AccessPolicy.objects.create(
            resource=self.resource,
            name="Single Factor Policy",
            required_factor_count=1,
        )
        session = start_authentication_session(
            resource_id=self.resource.id,
            policy_id=quick_policy.id,
        )

        result = submit_authentication_factor(
            session_id=session.id,
            credential_type=Credential.CredentialType.RFID,
            identifier=self.rfid.identifier,
        )
        session.refresh_from_db()

        self.assertTrue(result["accepted"])
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.status, AuthenticationSession.Status.APPROVED)
        self.assertEqual(
            AuditEvent.objects.filter(event_type="session_approved", session=session).count(),
            1,
        )

    def test_submit_authentication_factor_rejects_duplicate_factor(self):
        session = start_authentication_session(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )
        submit_authentication_factor(
            session_id=session.id,
            credential_type=Credential.CredentialType.RFID,
            identifier=self.rfid.identifier,
        )

        result = submit_authentication_factor(
            session_id=session.id,
            credential_type=Credential.CredentialType.RFID,
            identifier=self.rfid.identifier,
        )
        session.refresh_from_db()

        self.assertFalse(result["accepted"])
        self.assertEqual(session.accepted_factor_count, 1)
        self.assertEqual(
            AuditEvent.objects.filter(event_type="factor_duplicate", session=session).count(),
            1,
        )

    def test_submit_authentication_factor_rejects_ambiguous_match_without_user(self):
        other_user = User.objects.create_user(username="bob", password="password123")
        Credential.objects.create(
            user=other_user,
            credential_type=Credential.CredentialType.RFID,
            identifier=self.rfid.identifier,
            label="Bob badge",
        )
        quick_policy = AccessPolicy.objects.create(
            resource=self.resource,
            name="Anonymous Policy",
            required_factor_count=1,
        )
        session = start_authentication_session(
            resource_id=self.resource.id,
            policy_id=quick_policy.id,
        )

        with self.assertRaises(ValidationError) as context:
            submit_authentication_factor(
                session_id=session.id,
                credential_type=Credential.CredentialType.RFID,
                identifier=self.rfid.identifier,
            )

        self.assertIn("identifier", context.exception.message_dict)
