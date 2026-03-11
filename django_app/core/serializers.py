from rest_framework import serializers

from .models import (
    AccessPolicy,
    AuthenticationSession,
    Credential,
    ProtectedResource,
)


class ProtectedResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProtectedResource
        fields = ["id", "name", "description", "active"]


class AccessPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessPolicy
        fields = [
            "id",
            "resource",
            "name",
            "description",
            "tier",
            "required_factor_count",
            "active",
        ]

class AuthenticationSessionSerializer(serializers.ModelSerializer):
    resource = ProtectedResourceSerializer(read_only=True)
    policy = AccessPolicySerializer(read_only=True)
    user = serializers.SerializerMethodField()
    required_factor_count = serializers.ReadOnlyField()
    accepted_factor_count = serializers.ReadOnlyField()
    submitted_factors = serializers.ReadOnlyField()

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
            "submitted_factors",
            "started_at",
            "completed_at",
        ]

    def get_user(self, obj):
        if obj.user is None:
            return None
        return {"id": obj.user.id, "username": obj.user.username}


class StartAuthenticationSessionSerializer(serializers.Serializer):
    resource_id = serializers.IntegerField(min_value=1)
    user_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)
    policy_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)


class SubmitAuthenticationFactorSerializer(serializers.Serializer):
    session_id = serializers.IntegerField(min_value=1)
    credential_type = serializers.ChoiceField(choices=Credential.CredentialType.choices)
    identifier = serializers.CharField(max_length=255, trim_whitespace=True)
