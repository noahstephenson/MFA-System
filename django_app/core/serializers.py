"""Serializers for the JSON API used by future external clients.

The simulation pages use the same service layer, but these serializers define the
client-facing contract for HTTP/JSON callers.
"""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import (
    AccessPolicy,
    AuthenticationSession,
    Credential,
    ProtectedResource,
)

User = get_user_model()


class UserSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username"]


class ProtectedResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProtectedResource
        fields = ["id", "name", "active"]


class AccessPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessPolicy
        fields = [
            "id",
            "resource",
            "name",
            "tier",
            "required_factor_count",
            "active",
        ]


class AuthenticationSessionSerializer(serializers.ModelSerializer):
    resource = ProtectedResourceSerializer(read_only=True)
    policy = AccessPolicySerializer(read_only=True)
    user = UserSummarySerializer(read_only=True)
    required_factor_count = serializers.ReadOnlyField()
    accepted_factor_count = serializers.ReadOnlyField()
    remaining_factor_count = serializers.ReadOnlyField()
    submitted_factors = serializers.ReadOnlyField()
    is_complete = serializers.ReadOnlyField()
    is_access_granted = serializers.ReadOnlyField()

    class Meta:
        model = AuthenticationSession
        fields = [
            "id",
            "user",
            "resource",
            "policy",
            "status",
            "decision",
            "current_step",
            "required_factor_count",
            "accepted_factor_count",
            "remaining_factor_count",
            "is_complete",
            "is_access_granted",
            "submitted_factors",
            "started_at",
            "completed_at",
        ]


class StartAuthenticationSessionSerializer(serializers.Serializer):
    resource_id = serializers.IntegerField(min_value=1)
    user_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)
    policy_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)


class SubmitAuthenticationFactorSerializer(serializers.Serializer):
    session_id = serializers.IntegerField(min_value=1)
    credential_type = serializers.ChoiceField(choices=Credential.CredentialType.choices)
    identifier = serializers.CharField(max_length=255, trim_whitespace=True)
