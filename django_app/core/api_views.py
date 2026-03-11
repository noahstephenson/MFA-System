from django.core.exceptions import ValidationError
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


def validation_error_response(exc, *, fallback_status=status.HTTP_400_BAD_REQUEST):
    if hasattr(exc, "message_dict"):
        return Response(exc.message_dict, status=fallback_status)
    return Response({"detail": exc.messages[0]}, status=fallback_status)


class StartAuthenticationSessionAPIView(APIView):
    def post(self, request):
        serializer = StartAuthenticationSessionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            session = start_authentication_session(**serializer.validated_data)
        except ValidationError as exc:
            return validation_error_response(exc)

        return Response(
            {
                "message": "Authentication session started.",
                "session": AuthenticationSessionSerializer(session).data,
            },
            status=status.HTTP_201_CREATED,
        )


class SubmitAuthenticationFactorAPIView(APIView):
    def post(self, request):
        serializer = SubmitAuthenticationFactorSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            result = submit_authentication_factor(**serializer.validated_data)
        except ValidationError as exc:
            return validation_error_response(exc)

        return Response(
            {
                "accepted": result["accepted"],
                "message": result["message"],
                "session": AuthenticationSessionSerializer(result["session"]).data,
            },
            status=status.HTTP_200_OK,
        )


class AuthenticationSessionDetailAPIView(APIView):
    def get(self, request, session_id):
        try:
            session = get_authentication_session(session_id)
        except ValidationError as exc:
            return validation_error_response(exc, fallback_status=status.HTTP_404_NOT_FOUND)

        return Response(AuthenticationSessionSerializer(session).data, status=status.HTTP_200_OK)
