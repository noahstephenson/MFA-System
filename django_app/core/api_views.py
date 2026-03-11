"""External JSON API for authentication workflows.

These endpoints are intended to stay simple and stable for future clients such as
Node-RED. Django remains the system of record, and the simulation UI reuses the
same service layer instead of implementing separate session rules.
"""

from django.core.exceptions import ValidationError
from rest_framework.exceptions import APIException
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import (
    AuthenticationSessionSerializer,
    StartAuthenticationSessionSerializer,
    SubmitAuthenticationFactorSerializer,
)
from .services import (
    get_authentication_session,
    start_authentication_session,
    submit_authentication_factor,
)


def api_success_response(*, data, message=None, http_status=status.HTTP_200_OK):
    payload = {
        "ok": True,
        "data": data,
    }
    if message:
        payload["message"] = message
    return Response(payload, status=http_status)


def api_error_response(*, errors, message, http_status):
    return Response(
        {
            "ok": False,
            "message": message,
            "errors": errors,
        },
        status=http_status,
    )


def _normalize_api_exception_details(detail):
    if isinstance(detail, dict):
        return {
            key: [str(item) for item in value] if isinstance(value, list) else [str(value)]
            for key, value in detail.items()
        }
    if isinstance(detail, list):
        return {"detail": [str(item) for item in detail]}
    return {"detail": [str(detail)]}


def _api_exception_message(status_code):
    if status_code == status.HTTP_400_BAD_REQUEST:
        return "Request validation failed."
    if status_code == status.HTTP_404_NOT_FOUND:
        return "Resource not found."
    if status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
        return "Request method not allowed."
    if status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE:
        return "Unsupported media type."
    return "Request failed."


def django_validation_error_response(exc, *, fallback_status=status.HTTP_400_BAD_REQUEST):
    if hasattr(exc, "message_dict"):
        errors = exc.message_dict
    else:
        errors = {"detail": exc.messages}
    return api_error_response(
        errors=errors,
        message="Request validation failed.",
        http_status=fallback_status,
    )


class CoreAPIView(APIView):
    """Base API view that keeps error responses consistent for external clients."""

    def handle_exception(self, exc):
        if isinstance(exc, APIException):
            return api_error_response(
                errors=_normalize_api_exception_details(exc.detail),
                message=_api_exception_message(exc.status_code),
                http_status=exc.status_code,
            )
        return super().handle_exception(exc)


class StartAuthenticationSessionAPIView(CoreAPIView):
    """Start an authentication session for a resource and optional user/policy."""

    def post(self, request):
        serializer = StartAuthenticationSessionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            session = start_authentication_session(**serializer.validated_data)
        except ValidationError as exc:
            return django_validation_error_response(exc)

        return api_success_response(
            data={"session": AuthenticationSessionSerializer(session).data},
            message="Authentication session started.",
            http_status=status.HTTP_201_CREATED,
        )


class SubmitAuthenticationFactorAPIView(CoreAPIView):
    """Submit one abstract authentication factor to an existing session."""

    def post(self, request):
        serializer = SubmitAuthenticationFactorSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            result = submit_authentication_factor(**serializer.validated_data)
        except ValidationError as exc:
            return django_validation_error_response(exc)

        return api_success_response(
            data={
                "accepted": result["accepted"],
                "session": AuthenticationSessionSerializer(result["session"]).data,
            },
            message=result["message"],
            http_status=status.HTTP_200_OK,
        )


class AuthenticationSessionDetailAPIView(CoreAPIView):
    """Return the current session state for polling-style external clients."""

    def get(self, request, session_id):
        try:
            session = get_authentication_session(session_id)
        except ValidationError as exc:
            return django_validation_error_response(exc, fallback_status=status.HTTP_404_NOT_FOUND)

        return api_success_response(
            data={"session": AuthenticationSessionSerializer(session).data},
            http_status=status.HTTP_200_OK,
        )
