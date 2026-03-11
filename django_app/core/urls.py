from django.urls import path

from .api_views import (
    AuthenticationSessionDetailAPIView,
    StartAuthenticationSessionAPIView,
    SubmitAuthenticationFactorAPIView,
)
from .views import audit_log, authentication_session_detail, home, protected_resource_list

app_name = "core"

urlpatterns = [
    path("", home, name="home"),
    path("resources/", protected_resource_list, name="resource-list"),
    path("sessions/<int:session_id>/", authentication_session_detail, name="session-detail"),
    path("audit/", audit_log, name="audit-log"),
    path("api/auth/start/", StartAuthenticationSessionAPIView.as_view(), name="auth-start"),
    path("api/auth/factor/", SubmitAuthenticationFactorAPIView.as_view(), name="auth-factor"),
    path(
        "api/auth/session/<int:session_id>/",
        AuthenticationSessionDetailAPIView.as_view(),
        name="auth-session-detail",
    ),
]
