from django import forms
from django.contrib.auth import get_user_model

from .models import Credential, ProtectedResource

User = get_user_model()


class SimulationStartForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label="Person requesting access",
        help_text="Choose the user whose credentials will be presented during the demo.",
    )
    resource = forms.ModelChoiceField(
        queryset=ProtectedResource.objects.none(),
        label="Requested resource",
        help_text="Select the protected resource. The backend will apply that resource's active access policy automatically.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["user"].queryset = User.objects.filter(is_active=True).order_by("username")
        self.fields["resource"].queryset = ProtectedResource.objects.filter(active=True).order_by("name")
        self.fields["user"].empty_label = None
        self.fields["resource"].empty_label = None


class SimulationFactorForm(forms.Form):
    credential_type = forms.ChoiceField(
        choices=Credential.CredentialType.choices,
        label="Presented factor type",
    )
    identifier = forms.CharField(
        max_length=255,
        label="Presented credential value",
        help_text="Enter the credential value being presented for this step.",
    )

    def clean_identifier(self):
        return self.cleaned_data["identifier"].strip()
