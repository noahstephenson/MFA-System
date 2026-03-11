from django.test import TestCase
from django.urls import reverse

from ..models import AccessPolicy, AuthenticationSession, ProtectedResource
from .base import CoreTestDataMixin


class SimulationWorkflowTests(CoreTestDataMixin, TestCase):
    def test_simulation_start_page_loads(self):
        response = self.client.get(reverse("core:simulation-start"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/simulation_start.html")
        self.assertContains(response, "Start an Access Attempt")
        self.assertContains(response, "Default Policy")
        self.assertNotContains(response, "Demo policy override")

    def test_simulation_start_creates_session_and_redirects(self):
        response = self.client.post(
            reverse("core:simulation-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
            },
        )

        session = AuthenticationSession.objects.get()
        self.assertRedirects(response, reverse("core:simulation-session", args=[session.id]))
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.resource, self.resource)
        self.assertEqual(session.policy, self.policy)

    def test_simulation_session_can_approve_access(self):
        start_response = self.client.post(
            reverse("core:simulation-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
            },
        )
        session = AuthenticationSession.objects.get()

        self.assertRedirects(start_response, reverse("core:simulation-session", args=[session.id]))

        first_factor = self.client.post(
            reverse("core:simulation-session", args=[session.id]),
            {
                "credential_type": "rfid",
                "identifier": self.rfid.identifier,
            },
        )
        self.assertRedirects(first_factor, reverse("core:simulation-session", args=[session.id]))

        second_factor = self.client.post(
            reverse("core:simulation-session", args=[session.id]),
            {
                "credential_type": "pin",
                "identifier": self.pin.identifier,
            },
        )
        self.assertRedirects(second_factor, reverse("core:simulation-result", args=[session.id]))

        session.refresh_from_db()
        self.assertEqual(session.status, AuthenticationSession.Status.APPROVED)

        result_response = self.client.get(reverse("core:simulation-result", args=[session.id]))
        self.assertContains(result_response, "Access granted")
        self.assertContains(result_response, "Default Policy")

    def test_simulation_session_can_end_as_denied(self):
        self.client.post(
            reverse("core:simulation-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
            },
        )
        session = AuthenticationSession.objects.get()

        response = self.client.post(
            reverse("core:simulation-session", args=[session.id]),
            {"deny_session": "1"},
        )

        self.assertRedirects(response, reverse("core:simulation-result", args=[session.id]))

        session.refresh_from_db()
        self.assertEqual(session.status, AuthenticationSession.Status.DENIED)

        result_response = self.client.get(reverse("core:simulation-result", args=[session.id]))
        self.assertContains(result_response, "Access denied")

    def test_simulation_result_redirects_back_to_session_until_complete(self):
        self.client.post(
            reverse("core:simulation-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
            },
        )
        session = AuthenticationSession.objects.get()

        response = self.client.get(reverse("core:simulation-result", args=[session.id]))

        self.assertRedirects(response, reverse("core:simulation-session", args=[session.id]))

    def test_simulation_session_shows_rejected_factor_after_invalid_submission(self):
        self.client.post(
            reverse("core:simulation-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
            },
        )
        session = AuthenticationSession.objects.get()

        response = self.client.post(
            reverse("core:simulation-session", args=[session.id]),
            {
                "credential_type": "biometric",
                "identifier": "missing-scan",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Factor was not accepted.")
        self.assertContains(response, "biometric / missing-scan -")
        self.assertContains(response, "rejected")

    def test_simulation_start_uses_the_selected_resource_policy(self):
        other_resource = ProtectedResource.objects.create(name="Research Lab")
        other_policy = AccessPolicy.objects.create(
            resource=other_resource,
            name="Research Policy",
            required_factor_count=1,
        )

        response = self.client.post(
            reverse("core:simulation-start"),
            {
                "user": self.user.id,
                "resource": other_resource.id,
            },
        )

        session = AuthenticationSession.objects.get()
        self.assertRedirects(response, reverse("core:simulation-session", args=[session.id]))
        self.assertEqual(session.resource, other_resource)
        self.assertEqual(session.policy, other_policy)

    def test_simulation_start_form_hides_inactive_users(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.client.get(reverse("core:simulation-start"))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.user.username)

    def test_completed_simulation_session_redirects_to_result_page(self):
        quick_resource = ProtectedResource.objects.create(name="Front Entrance")
        AccessPolicy.objects.create(
            resource=quick_resource,
            name="Simulation Quick Policy",
            required_factor_count=1,
        )
        self.client.post(
            reverse("core:simulation-start"),
            {
                "user": self.user.id,
                "resource": quick_resource.id,
            },
        )
        session = AuthenticationSession.objects.get()

        self.client.post(
            reverse("core:simulation-session", args=[session.id]),
            {
                "credential_type": "rfid",
                "identifier": self.rfid.identifier,
            },
        )
        response = self.client.get(reverse("core:simulation-session", args=[session.id]))

        self.assertRedirects(response, reverse("core:simulation-result", args=[session.id]))

    def test_simulation_session_shows_realistic_access_state_copy(self):
        self.client.post(
            reverse("core:simulation-start"),
            {
                "user": self.user.id,
                "resource": self.resource.id,
            },
        )
        session = AuthenticationSession.objects.get()

        response = self.client.get(reverse("core:simulation-session", args=[session.id]))

        self.assertContains(response, "Access attempt started")
        self.assertContains(response, "Present factor 1")
