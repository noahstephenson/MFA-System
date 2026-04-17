from django.contrib.auth import get_user_model

from ..models import AccessPolicy, Credential, ProtectedResource

User = get_user_model()


class CoreTestDataMixin:
    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="alice", password="password123")

        self.resource = ProtectedResource.objects.create(
            name="Demo ATAK Console",
            description="Primary demo ATAK resource.",
            allow_degraded_access=False,
        )
        self.degraded_resource = ProtectedResource.objects.create(
            name="Mission Continuity Console",
            description="Approved degraded-mode console.",
            allow_degraded_access=True,
        )

        self.tier1_policy = AccessPolicy.objects.create(
            resource=self.resource,
            name="Tier 1 Policy",
            description="RFID plus fingerprint.",
            tier=AccessPolicy.Tier.BASIC,
            required_factor_count=2,
        )
        self.tier2_policy = AccessPolicy.objects.create(
            resource=self.resource,
            name="Tier 2 Policy",
            description="RFID plus knowledge factor.",
            tier=AccessPolicy.Tier.ELEVATED,
            required_factor_count=2,
        )
        self.tier3_policy = AccessPolicy.objects.create(
            resource=self.resource,
            name="Tier 3 Policy",
            description="Degraded access request for a non-approved resource.",
            tier=AccessPolicy.Tier.HIGH,
            required_factor_count=2,
        )
        self.degraded_tier3_policy = AccessPolicy.objects.create(
            resource=self.degraded_resource,
            name="Tier 3 Degraded Policy",
            description="Degraded access request for an approved resource.",
            tier=AccessPolicy.Tier.HIGH,
            required_factor_count=2,
        )

        self.policy = self.tier1_policy

        self.rfid = Credential.objects.create(
            user=self.user,
            credential_type=Credential.CredentialType.RFID,
            identifier="CARD-1001",
            label="Alice badge",
        )
        self.pin = Credential.objects.create(
            user=self.user,
            credential_type=Credential.CredentialType.PIN,
            identifier="12345678",
            label="Alice PIN",
        )
        self.biometric = Credential.objects.create(
            user=self.user,
            credential_type=Credential.CredentialType.BIOMETRIC,
            identifier="4",
            label="Alice fingerprint",
        )
