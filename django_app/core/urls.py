from django.urls import path

from .api_views import (
    AuthenticationSessionDetailAPIView,
    StartAuthenticationSessionAPIView,
    SubmitAuthenticationFactorAPIView,
)
from .views import (
    access_policy_detail,
    access_policy_list,
    audit_log,
    authentication_session_detail,
    credential_detail,
    credential_list,
    home,
    protected_resource_detail,
    protected_resource_list,
    simulation_result,
    simulation_session,
    simulation_start,
)

app_name = "core"

urlpatterns = [
    # Server-rendered pages for demos, inspection, and admin-adjacent use.
    path("", home, name="home"),
    path("simulate/", simulation_start, name="simulation-start"),
    path(
        "simulate/session/<int:session_id>/",
        simulation_session,
        name="simulation-session",
    ),
    path(
        "simulate/session/<int:session_id>/result/",
        simulation_result,
        name="simulation-result",
    ),
    path("resources/", protected_resource_list, name="resource-list"),
    path("resources/<int:resource_id>/", protected_resource_detail, name="resource-detail"),
    path("policies/", access_policy_list, name="policy-list"),
    path("policies/<int:policy_id>/", access_policy_detail, name="policy-detail"),
    path("credentials/", credential_list, name="credential-list"),
    path("credentials/<int:credential_id>/", credential_detail, name="credential-detail"),
    path("sessions/<int:session_id>/", authentication_session_detail, name="session-detail"),
    path("audit/", audit_log, name="audit-log"),
    # JSON API intended for future external clients.
    path("api/auth/start/", StartAuthenticationSessionAPIView.as_view(), name="auth-start"),
    path("api/auth/factor/", SubmitAuthenticationFactorAPIView.as_view(), name="auth-factor"),
    path(
        "api/auth/session/<int:session_id>/",
        AuthenticationSessionDetailAPIView.as_view(),
        name="auth-session-detail",
    ),
]
