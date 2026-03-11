from django.core.exceptions import ValidationError
from django.test import TestCase

from ..models import AuditEvent, AuthenticationSession, Credential
from ..services import start_authentication_session, submit_authentication_factor
from .base import CoreTestDataMixin


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
