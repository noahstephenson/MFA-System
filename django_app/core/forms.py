from django import forms
from django.contrib.auth import get_user_model

from .models import AccessPolicy, ProtectedResource, normalize_access_tier, tier_requirement_definition

User = get_user_model()


class AccessStartForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label="Subject",
        help_text="Choose the enrolled subject for this access attempt.",
    )
    resource = forms.ModelChoiceField(
        queryset=ProtectedResource.objects.none(),
        label="Protected resource",
        help_text="Choose the resource the operator is requesting access to.",
    )
    tier = forms.ChoiceField(
        choices=AccessPolicy.Tier.choices,
        label="Access tier",
        help_text="Tier 1 requires RFID + fingerprint. Tier 2 and Tier 3 require RFID + knowledge factor.",
    )
    knowledge_factor = forms.CharField(
        required=False,
        label="Knowledge factor",
        help_text="Required for Tier 2 and Tier 3. For this MVP Django checks the value against the user's enrolled PIN/passcode credential.",
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
