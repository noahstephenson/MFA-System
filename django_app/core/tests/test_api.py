from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from ..models import AccessPolicy, AuditEvent, Credential
from .base import CoreTestDataMixin

User = get_user_model()


class AuthenticationAPITests(CoreTestDataMixin, APITestCase):
    def test_start_session_endpoint_creates_session(self):
        response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "user_id": self.user.id},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data["ok"])
        self.assertEqual(response.data["data"]["session"]["status"], "in_progress")
        self.assertEqual(response.data["data"]["session"]["policy"]["id"], self.policy.id)
        self.assertEqual(AuditEvent.objects.filter(event_type="session_started").count(), 1)

    def test_factor_endpoint_advances_and_completes_session(self):
        start_response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "user_id": self.user.id},
            format="json",
        )
        session_id = start_response.data["data"]["session"]["id"]

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
        self.assertTrue(first_factor_response.data["ok"])
        self.assertTrue(first_factor_response.data["data"]["accepted"])
        self.assertEqual(first_factor_response.data["data"]["session"]["status"], "in_progress")
        self.assertEqual(first_factor_response.data["data"]["session"]["accepted_factor_count"], 1)

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
        self.assertTrue(second_factor_response.data["ok"])
        self.assertTrue(second_factor_response.data["data"]["accepted"])
        self.assertEqual(second_factor_response.data["data"]["session"]["status"], "approved")
        self.assertEqual(second_factor_response.data["data"]["session"]["decision"], "granted")

    def test_session_status_endpoint_returns_current_state(self):
        start_response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "user_id": self.user.id},
            format="json",
        )
        session_id = start_response.data["data"]["session"]["id"]

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
        self.assertTrue(response.data["ok"])
        self.assertEqual(response.data["data"]["session"]["id"], session_id)
        self.assertEqual(response.data["data"]["session"]["accepted_factor_count"], 1)
        self.assertEqual(response.data["data"]["session"]["remaining_factor_count"], 1)
        self.assertEqual(len(response.data["data"]["session"]["submitted_factors"]), 1)

    def test_start_session_endpoint_returns_error_for_unknown_resource(self):
        response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": 9999, "user_id": self.user.id},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["ok"])
        self.assertIn("resource_id", response.data["errors"])

    def test_start_session_endpoint_rejects_inactive_user(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "user_id": self.user.id},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["ok"])
        self.assertIn("user_id", response.data["errors"])

    def test_session_status_endpoint_returns_404_for_missing_session(self):
        response = self.client.get(reverse("core:auth-session-detail", args=[9999]))

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.data["ok"])
        self.assertIn("session_id", response.data["errors"])

    def test_start_and_factor_endpoints_can_bind_user_for_anonymous_session(self):
        quick_policy = AccessPolicy.objects.create(
            resource=self.resource,
            name="API Quick Policy",
            required_factor_count=1,
        )
        start_response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "policy_id": quick_policy.id},
            format="json",
        )
        session_id = start_response.data["data"]["session"]["id"]

        self.assertIsNone(start_response.data["data"]["session"]["user"])

        factor_response = self.client.post(
            reverse("core:auth-factor"),
            {
                "session_id": session_id,
                "credential_type": Credential.CredentialType.RFID,
                "identifier": f" {self.rfid.identifier} ",
            },
            format="json",
        )

        self.assertEqual(factor_response.status_code, status.HTTP_200_OK)
        self.assertTrue(factor_response.data["data"]["accepted"])
        self.assertEqual(factor_response.data["data"]["session"]["status"], "approved")
        self.assertEqual(factor_response.data["data"]["session"]["user"]["id"], self.user.id)

        detail_response = self.client.get(reverse("core:auth-session-detail", args=[session_id]))
        self.assertEqual(detail_response.status_code, status.HTTP_200_OK)
        self.assertEqual(detail_response.data["data"]["session"]["user"]["id"], self.user.id)

    def test_factor_endpoint_returns_duplicate_result_for_same_factor(self):
        start_response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "user_id": self.user.id},
            format="json",
        )
        session_id = start_response.data["data"]["session"]["id"]

        self.client.post(
            reverse("core:auth-factor"),
            {
                "session_id": session_id,
                "credential_type": Credential.CredentialType.RFID,
                "identifier": self.rfid.identifier,
            },
            format="json",
        )
        response = self.client.post(
            reverse("core:auth-factor"),
            {
                "session_id": session_id,
                "credential_type": Credential.CredentialType.RFID,
                "identifier": self.rfid.identifier,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["data"]["accepted"])
        self.assertEqual(response.data["data"]["session"]["accepted_factor_count"], 1)

    def test_factor_endpoint_returns_400_for_completed_session(self):
        start_response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "user_id": self.user.id},
            format="json",
        )
        session_id = start_response.data["data"]["session"]["id"]

        self.client.post(
            reverse("core:auth-factor"),
            {
                "session_id": session_id,
                "credential_type": Credential.CredentialType.RFID,
                "identifier": self.rfid.identifier,
            },
            format="json",
        )
        self.client.post(
            reverse("core:auth-factor"),
            {
                "session_id": session_id,
                "credential_type": Credential.CredentialType.PIN,
                "identifier": self.pin.identifier,
            },
            format="json",
        )
        response = self.client.post(
            reverse("core:auth-factor"),
            {
                "session_id": session_id,
                "credential_type": Credential.CredentialType.PIN,
                "identifier": self.pin.identifier,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["ok"])
        self.assertIn("session_id", response.data["errors"])

    def test_factor_endpoint_returns_400_for_ambiguous_factor_match(self):
        other_user = User.objects.create_user(username="bob", password="password123")
        Credential.objects.create(
            user=other_user,
            credential_type=Credential.CredentialType.RFID,
            identifier=self.rfid.identifier,
            label="Bob badge",
        )
        quick_policy = AccessPolicy.objects.create(
            resource=self.resource,
            name="Anonymous API Policy",
            required_factor_count=1,
        )
        start_response = self.client.post(
            reverse("core:auth-start"),
            {"resource_id": self.resource.id, "policy_id": quick_policy.id},
            format="json",
        )
        session_id = start_response.data["data"]["session"]["id"]

        response = self.client.post(
            reverse("core:auth-factor"),
            {
                "session_id": session_id,
                "credential_type": Credential.CredentialType.RFID,
                "identifier": self.rfid.identifier,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["ok"])
        self.assertIn("identifier", response.data["errors"])

    def test_start_session_endpoint_returns_consistent_serializer_error_shape(self):
        response = self.client.post(reverse("core:auth-start"), {"user_id": self.user.id}, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["ok"])
        self.assertEqual(response.data["message"], "Request validation failed.")
        self.assertIn("resource_id", response.data["errors"])

    def test_start_session_endpoint_returns_consistent_405_shape(self):
        response = self.client.get(reverse("core:auth-start"))

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertFalse(response.data["ok"])
        self.assertEqual(response.data["message"], "Request method not allowed.")
        self.assertIn("detail", response.data["errors"])

    def test_start_session_endpoint_returns_consistent_parse_error_shape(self):
        response = self.client.post(
            reverse("core:auth-start"),
            data="{invalid-json",
            content_type="application/json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["ok"])
        self.assertEqual(response.data["message"], "Request validation failed.")
        self.assertIn("detail", response.data["errors"])
