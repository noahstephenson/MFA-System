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
        self.assertContains(response, "System Status")

    def test_protected_resources_page_loads(self):
        response = self.client.get(reverse("core:resource-list"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/protected_resource_list.html")
        self.assertContains(response, "Server Room")

    def test_authentication_session_detail_page_loads(self):
        session = start_authentication_session(
            resource_id=self.resource.id,
            user_id=self.user.id,
        )

        response = self.client.get(reverse("core:session-detail", args=[session.id]))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/authentication_session_detail.html")
        self.assertContains(response, "Authentication Session")

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
