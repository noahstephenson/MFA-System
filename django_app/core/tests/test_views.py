from django.test import TestCase
from django.urls import reverse

from ..models import AuditEvent
from ..services import start_authentication_session
from .base import CoreTestDataMixin


class PageLoadTests(CoreTestDataMixin, TestCase):
    def test_home_page_loads(self):
        response = self.client.get(reverse("core:home"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/home.html")
        self.assertContains(response, "MFA Prototype Dashboard")

    def test_protected_resources_page_loads(self):
        response = self.client.get(reverse("core:resource-list"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/protected_resource_list.html")
        self.assertContains(response, "Server Room")

    def test_protected_resource_detail_page_loads(self):
        response = self.client.get(reverse("core:resource-detail", args=[self.resource.id]))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/protected_resource_detail.html")
        self.assertContains(response, "Protected Resource")

    def test_access_policy_list_page_loads(self):
        response = self.client.get(reverse("core:policy-list"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/access_policy_list.html")
        self.assertContains(response, "Default Policy")

    def test_access_policy_detail_page_loads(self):
        response = self.client.get(reverse("core:policy-detail", args=[self.policy.id]))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/access_policy_detail.html")
        self.assertContains(response, "Access Policy")

    def test_credential_list_page_loads(self):
        response = self.client.get(reverse("core:credential-list"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/credential_list.html")
        self.assertContains(response, self.rfid.identifier)

    def test_credential_detail_page_loads(self):
        response = self.client.get(reverse("core:credential-detail", args=[self.rfid.id]))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/credential_detail.html")
        self.assertContains(response, "Credential")

    def test_authentication_session_detail_page_loads(self):
        session = start_authentication_session(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )

        response = self.client.get(reverse("core:session-detail", args=[session.id]))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/authentication_session_detail.html")
        self.assertContains(response, "Authentication Session")
        self.assertContains(response, "View Resource")

    def test_audit_log_page_loads(self):
        session = start_authentication_session(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )
        AuditEvent.objects.create(
            event_type="manual_check",
            message="Manual review performed.",
            session=session,
            user=self.user,
        )

        response = self.client.get(reverse("core:audit-log"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/audit_log.html")
        self.assertContains(response, "manual_check")

    def test_missing_session_page_returns_404(self):
        response = self.client.get(reverse("core:session-detail", args=[9999]))

        self.assertEqual(response.status_code, 404)

    def test_missing_resource_detail_page_returns_404(self):
        response = self.client.get(reverse("core:resource-detail", args=[9999]))

        self.assertEqual(response.status_code, 404)

    def test_missing_policy_detail_page_returns_404(self):
        response = self.client.get(reverse("core:policy-detail", args=[9999]))

        self.assertEqual(response.status_code, 404)

    def test_missing_credential_detail_page_returns_404(self):
        response = self.client.get(reverse("core:credential-detail", args=[9999]))

        self.assertEqual(response.status_code, 404)
