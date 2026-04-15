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
        label="Person",
    )
    resource = forms.ModelChoiceField(
        queryset=ProtectedResource.objects.none(),
        label="Resource",
    )
    tier = forms.ChoiceField(
        choices=AccessPolicy.Tier.choices,
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
                "Enter the PIN for Tier 2 and Tier 3.",
            )
        return cleaned_data


class UserSelectionForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label="Person",
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["user"].queryset = User.objects.filter(is_active=True).order_by("username")
        self.fields["user"].empty_label = "Select a person"


class EnrollmentChooserForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label="Person",
    )
    credential_type = forms.ChoiceField(
        choices=(
            (Credential.CredentialType.RFID, "Badge"),
            (Credential.CredentialType.BIOMETRIC, "Fingerprint"),
            (Credential.CredentialType.PIN, "PIN"),
        ),
        label="Credential",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["user"].queryset = User.objects.filter(is_active=True).order_by("username")
        self.fields["user"].empty_label = "Select a person"

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
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        widget=forms.HiddenInput(),
    )
    captured_identifier = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["user"].queryset = User.objects.filter(is_active=True).order_by("username")

    def clean_captured_identifier(self):
        identifier = str(self.cleaned_data.get("captured_identifier") or "").strip()
        if not identifier:
            raise forms.ValidationError("Capture a hardware credential before saving.")
        return identifier


class PinEnrollmentForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
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
        self.fields["user"].queryset = User.objects.filter(is_active=True).order_by("username")
        self.fields["label"].widget.attrs.update({"placeholder": "Optional label"})

    def clean_pin(self):
        pin = str(self.cleaned_data.get("pin") or "").strip()
        if not pin:
            raise forms.ValidationError("Enter a PIN.")
        return pin
