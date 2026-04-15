from django import forms
from django.contrib.auth import get_user_model

from .models import (
    AccessPolicy,
    Credential,
    ProtectedResource,
    normalize_access_tier,
    tier_requirement_definition,
)

User = get_user_model()


class AccessStartForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label="User",
        help_text="Who is requesting access.",
    )
    resource = forms.ModelChoiceField(
        queryset=ProtectedResource.objects.none(),
        label="Resource",
        help_text="Where access is being requested.",
    )
    tier = forms.ChoiceField(
        choices=AccessPolicy.Tier.choices,
        label="Tier",
        help_text="Tier 1 uses RFID + fingerprint. Tier 2 and Tier 3 use RFID + PIN.",
    )
    knowledge_factor = forms.CharField(
        required=False,
        label="PIN",
        help_text="Required for Tier 2 and Tier 3.",
        widget=forms.PasswordInput(render_value=True),
        strip=True,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["user"].queryset = User.objects.filter(is_active=True).order_by("username")
        self.fields["resource"].queryset = ProtectedResource.objects.filter(active=True).order_by("name")
        self.fields["user"].empty_label = None
        self.fields["resource"].empty_label = None

    def clean_tier(self):
        tier = normalize_access_tier(self.cleaned_data.get("tier"))
        if not tier:
            raise forms.ValidationError("Select a valid tier.")
        return tier

    def clean(self):
        cleaned_data = super().clean()
        tier = cleaned_data.get("tier")
        knowledge_factor = str(cleaned_data.get("knowledge_factor") or "").strip()
        if tier_requirement_definition(tier)["requires_knowledge_factor"] and not knowledge_factor:
            self.add_error(
                "knowledge_factor",
                "Provide the knowledge factor for Tier 2 and Tier 3 access attempts.",
            )
        return cleaned_data


class EnrollmentForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label="User",
        help_text="Choose the user who owns this credential.",
    )
    credential_type = forms.ChoiceField(
        choices=Credential.CredentialType.choices,
        label="Credential type",
        help_text="Badge uses a UID, biometric uses a fingerprint ID, and PIN stores the knowledge factor.",
    )
    identifier = forms.CharField(
        label="Identifier / value",
        help_text="Enter the exact UID, fingerprint ID, or PIN value you want to store.",
        strip=True,
    )
    label = forms.CharField(
        required=False,
        label="Label",
        help_text="Optional friendly name, such as Alice badge or Ops fingerprint.",
        strip=True,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["user"].queryset = User.objects.filter(is_active=True).order_by("username")
        self.fields["user"].empty_label = None

    def clean_credential_type(self):
        credential_type = str(self.cleaned_data.get("credential_type") or "").strip()
        valid_types = {value for value, _label in Credential.CredentialType.choices}
        if credential_type not in valid_types:
            raise forms.ValidationError("Select a valid credential type.")
        return credential_type

    def clean_identifier(self):
        identifier = str(self.cleaned_data.get("identifier") or "").strip()
        if not identifier:
            raise forms.ValidationError("Enter the credential identifier or value.")
        return identifier
