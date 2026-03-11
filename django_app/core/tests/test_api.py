from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from ..models import AuditEvent, Credential
from .base import CoreTestDataMixin


class AuthenticationAPITests(CoreTestDataMixin, APITestCase):
    def test_start_session_endpoint_creates_session(self):
        response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "user_id": self.user.id},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["session"]["status"], "in_progress")
        self.assertEqual(response.data["session"]["policy"]["id"], self.policy.id)
        self.assertEqual(AuditEvent.objects.filter(event_type="session_started").count(), 1)

    def test_factor_endpoint_advances_and_completes_session(self):
        start_response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "user_id": self.user.id},
            format="json",
        )
        session_id = start_response.data["session"]["id"]

        first_factor_response = self.client.post(
            reverse("core:auth-factor"),
            {
                "session_id": session_id,
                "credential_type": Credential.CredentialType.RFID,
                "identifier": self.rfid.identifier,
            },
            format="json",
        )

        self.assertEqual(first_factor_response.status_code, status.HTTP_200_OK)
        self.assertTrue(first_factor_response.data["accepted"])
        self.assertEqual(first_factor_response.data["session"]["status"], "in_progress")
        self.assertEqual(first_factor_response.data["session"]["accepted_factor_count"], 1)

        second_factor_response = self.client.post(
            reverse("core:auth-factor"),
            {
                "session_id": session_id,
                "credential_type": Credential.CredentialType.PIN,
                "identifier": self.pin.identifier,
            },
            format="json",
        )

        self.assertEqual(second_factor_response.status_code, status.HTTP_200_OK)
        self.assertTrue(second_factor_response.data["accepted"])
        self.assertEqual(second_factor_response.data["session"]["status"], "approved")
        self.assertEqual(second_factor_response.data["session"]["decision"], "granted")

    def test_session_status_endpoint_returns_current_state(self):
        start_response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "user_id": self.user.id},
            format="json",
        )
        session_id = start_response.data["session"]["id"]

        self.client.post(
            reverse("core:auth-factor"),
            {
                "session_id": session_id,
                "credential_type": Credential.CredentialType.RFID,
                "identifier": self.rfid.identifier,
            },
            format="json",
        )

        response = self.client.get(reverse("core:auth-session-detail", args=[session_id]))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["id"], session_id)
        self.assertEqual(response.data["accepted_factor_count"], 1)
        self.assertEqual(len(response.data["submitted_factors"]), 1)

    def test_start_session_endpoint_returns_error_for_unknown_resource(self):
        response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": 9999, "user_id": self.user.id},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("resource_id", response.data)

    def test_session_status_endpoint_returns_404_for_missing_session(self):
        response = self.client.get(reverse("core:auth-session-detail", args=[9999]))

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn("session_id", response.data)
