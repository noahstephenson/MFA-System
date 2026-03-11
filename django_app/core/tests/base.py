from django.contrib.auth import get_user_model

from ..models import AccessPolicy, Credential, ProtectedResource

User = get_user_model()


class CoreTestDataMixin:
    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="alice", password="password123")
        self.resource = ProtectedResource.objects.create(
            name="Server Room",
            description="Restricted access room.",
        )
        self.policy = AccessPolicy.objects.create(
            resource=self.resource,
            name="Default Policy",
            description="Two-factor access for the room.",
            required_factor_count=2,
        )
        self.rfid = Credential.objects.create(
            user=self.user,
            credential_type=Credential.CredentialType.RFID,
            identifier="CARD-1001",
            label="Alice badge",
        )
        self.pin = Credential.objects.create(
            user=self.user,
            credential_type=Credential.CredentialType.PIN,
            identifier="2468",
            label="Alice PIN",
        )
