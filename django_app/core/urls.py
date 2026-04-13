from django.urls import path

from .api_views import (
    api_access_session_detail,
    api_access_start,
    api_auth_factor,
    api_auth_session_detail,
    api_auth_start,
)
from .views import (
    access_result,
    access_start,
    access_start_submit,
    home,
    legacy_access_start_redirect,
    legacy_session_result_redirect,
)

app_name = "core"

urlpatterns = [
    path("", home, name="home"),
    path("app/access/", access_start, name="access-start"),
    path("app/access/start/", access_start_submit, name="access-start-submit"),
    path("app/access/result/<int:session_id>/", access_result, name="access-result"),
    path("api/access/start/", api_access_start, name="api-access-start"),
    path(
        "api/access/session/<int:session_id>/",
        api_access_session_detail,
        name="api-access-session-detail",
    ),
    path("api/auth/start/", api_auth_start, name="auth-start"),
    path("api/auth/factor/", api_auth_factor, name="auth-factor"),
    path(
        "api/auth/session/<int:session_id>/",
        api_auth_session_detail,
        name="auth-session-detail",
    ),
    # Compatibility aliases for older templates and clients that still point at
    # removed UI routes. They all forward to the current MVP flow.
    path("simulate/", legacy_access_start_redirect, name="simulation-start"),
    path(
        "simulate/session/<int:session_id>/",
        legacy_session_result_redirect,
        name="simulation-session",
    ),
    path(
        "simulate/session/<int:session_id>/result/",
        legacy_session_result_redirect,
        name="simulation-result",
    ),
    path(
        "simulate/session/<int:session_id>/reauth/",
        legacy_access_start_redirect,
        name="simulation-reauth",
    ),
    path("resources/", legacy_access_start_redirect, name="resource-list"),
    path("resources/<int:resource_id>/", legacy_access_start_redirect, name="resource-detail"),
    path("policies/", legacy_access_start_redirect, name="policy-list"),
    path("policies/<int:policy_id>/", legacy_access_start_redirect, name="policy-detail"),
    path("credentials/", legacy_access_start_redirect, name="credential-list"),
    path(
        "credentials/<int:credential_id>/",
        legacy_access_start_redirect,
        name="credential-detail",
    ),
    path("sessions/<int:session_id>/", legacy_session_result_redirect, name="session-detail"),
    path("audit/", legacy_access_start_redirect, name="audit-log"),
]
