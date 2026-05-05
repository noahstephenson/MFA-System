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
PIN_LENGTH = 8


def validate_exact_pin(pin):
    normalized_pin = str(pin or "").strip()
    if not normalized_pin:
        raise forms.ValidationError("Enter a PIN.")
    if not normalized_pin.isdigit() or len(normalized_pin) != PIN_LENGTH:
        raise forms.ValidationError("PIN must be exactly 8 digits.")
    return normalized_pin


class AccessStartForm(forms.Form):
    username = forms.CharField(
        label="Subject",
        strip=True,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "username",
                "placeholder": "Enter username",
            },
        ),
    )
    resource = forms.ModelChoiceField(
        queryset=ProtectedResource.objects.none(),
        label="Resource",
    )
    tier = forms.ChoiceField(
        choices=[
            (AccessPolicy.Tier.BASIC, "Tier 1 — Highest-Complexity Normal (Badge + Fingerprint)"),
            (AccessPolicy.Tier.ELEVATED, "Tier 2 — Standard Protected Access (Badge + PIN)"),
            (AccessPolicy.Tier.HIGH, "Tier 3 — Degraded / Mission Continuity Access (Badge + PIN)"),
        ],
        label="Tier",
    )
    knowledge_factor = forms.CharField(
        required=False,
        label="PIN",
        widget=forms.PasswordInput(
            render_value=True,
            attrs={
                "autocomplete": "off",
                "inputmode": "numeric",
            },
        ),
        strip=True,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["resource"].queryset = ProtectedResource.objects.filter(active=True).order_by("name")
        self.fields["resource"].empty_label = None

    def clean_username(self):
        username = str(self.cleaned_data.get("username") or "").strip()
        if not username:
            raise forms.ValidationError("Enter a username.")
        user = User.objects.filter(username__iexact=username, is_active=True).first()
        if user is None:
            raise forms.ValidationError("Enter a known active username.")
        self.cleaned_data["user"] = user
        return username

    def clean_tier(self):
        tier = normalize_access_tier(self.cleaned_data.get("tier"))
        if not tier:
            raise forms.ValidationError("Select a valid tier.")
        return tier

    def clean(self):
        cleaned_data = super().clean()
        tier = cleaned_data.get("tier")
        knowledge_factor = str(cleaned_data.get("knowledge_factor") or "").strip()
        if tier_requirement_definition(tier)["requires_knowledge_factor"]:
            try:
                cleaned_data["knowledge_factor"] = validate_exact_pin(knowledge_factor)
            except forms.ValidationError as exc:
                self.add_error("knowledge_factor", exc)
        return cleaned_data


class UserSelectionForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label="Subject",
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["user"].queryset = User.objects.filter(is_active=True).order_by("username")
        self.fields["user"].empty_label = "Select a subject"


class EnrollmentChooserForm(forms.Form):
    username = forms.CharField(
        label="Subject",
        strip=True,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "username",
                "placeholder": "Enter username",
            },
        ),
    )
    credential_type = forms.ChoiceField(
        choices=(
            (Credential.CredentialType.RFID, "Badge"),
            (Credential.CredentialType.BIOMETRIC, "Fingerprint"),
            (Credential.CredentialType.PIN, "PIN"),
        ),
        label="Credential",
    )

    def clean_username(self):
        username = str(self.cleaned_data.get("username") or "").strip()
        if not username:
            raise forms.ValidationError("Enter a username.")
        return username

    def clean_credential_type(self):
        credential_type = str(self.cleaned_data.get("credential_type") or "").strip()
        valid_types = {
            Credential.CredentialType.RFID,
            Credential.CredentialType.BIOMETRIC,
            Credential.CredentialType.PIN,
        }
        if credential_type not in valid_types:
            raise forms.ValidationError("Select a valid credential.")
        return credential_type


class CapturedCredentialForm(forms.Form):
    username = forms.CharField(
        widget=forms.HiddenInput(),
    )
    captured_identifier = forms.CharField(widget=forms.HiddenInput())

    def clean_username(self):
        username = str(self.cleaned_data.get("username") or "").strip()
        if not username:
            raise forms.ValidationError("Enter a username.")
        return username

    def clean_captured_identifier(self):
        identifier = str(self.cleaned_data.get("captured_identifier") or "").strip()
        if not identifier:
            raise forms.ValidationError("Capture a hardware credential before saving.")
        return identifier


class PinEnrollmentForm(forms.Form):
    username = forms.CharField(
        widget=forms.HiddenInput(),
    )
    pin = forms.CharField(
        label="PIN",
        strip=True,
        widget=forms.PasswordInput(
            render_value=True,
            attrs={
                "autocomplete": "off",
                "inputmode": "numeric",
                "placeholder": "Enter PIN",
            },
        ),
    )
    label = forms.CharField(
        required=False,
        label="Label",
        strip=True,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["label"].widget.attrs.update({"placeholder": "Optional label"})

    def clean_username(self):
        username = str(self.cleaned_data.get("username") or "").strip()
        if not username:
            raise forms.ValidationError("Enter a username.")
        return username

    def clean_pin(self):
        return validate_exact_pin(self.cleaned_data.get("pin"))


class ResourceEnrollmentForm(forms.Form):
    resource_name = forms.CharField(
        label="Resource Name",
        strip=True,
        widget=forms.TextInput(attrs={"placeholder": "Enter resource name"}),
    )
    description = forms.CharField(
        label="Description",
        required=False,
        strip=True,
        widget=forms.TextInput(attrs={"placeholder": "Optional description"}),
    )
    allow_degraded_access = forms.BooleanField(
        label="Allow Tier 3 (Degraded) Access",
        required=False,
    )
    tier = forms.ChoiceField(
        label="Authentication Tier",
        choices=[
            (AccessPolicy.Tier.BASIC, "Tier 1 — Badge + Fingerprint"),
            (AccessPolicy.Tier.ELEVATED, "Tier 2 — Badge + PIN"),
            (AccessPolicy.Tier.HIGH, "Tier 3 — Badge + PIN (degraded, resource must allow it)"),
        ],
    )

    def clean_resource_name(self):
        name = str(self.cleaned_data.get("resource_name") or "").strip()
        if not name:
            raise forms.ValidationError("Enter a resource name.")
        return name

    def clean_tier(self):
        tier = normalize_access_tier(self.cleaned_data.get("tier"))
        if not tier:
            raise forms.ValidationError("Select a valid tier.")
        return tier
