from django import forms
from django.contrib.auth import get_user_model

from .models import AccessPolicy

User = get_user_model()


class AccessStartForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        label="Subject",
        help_text="Choose the enrolled subject for this access attempt.",
    )
    tier = forms.ChoiceField(
        choices=(),
        label="Access tier",
        help_text="Choose the demo tier. Django will resolve the one active policy configured for that tier, then call Node-RED to collect RFID and fingerprint factors.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["user"].queryset = User.objects.filter(is_active=True).order_by("username")
        self.fields["user"].empty_label = None
        active_tiers = list(
            AccessPolicy.objects.filter(active=True, resource__active=True)
            .order_by("tier")
            .values_list("tier", flat=True)
            .distinct()
        )
        tier_labels = dict(AccessPolicy.Tier.choices)
        self.fields["tier"].choices = [
            (tier, tier_labels.get(tier, tier.replace("_", " ").title()))
            for tier in active_tiers
        ]
