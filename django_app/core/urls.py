from django.urls import path

from .api_views import api_access_start
from .views import access_result, access_start, enroll, home

app_name = "core"

urlpatterns = [
    path("", home, name="home"),
    path("app/", home, name="app-home"),
    path("app/access/", access_start, name="access-start"),
    path("app/access/result/<int:session_id>/", access_result, name="access-result"),
    path("app/enroll/", enroll, name="enroll"),
    path("api/access/start/", api_access_start, name="api-access-start"),
]
