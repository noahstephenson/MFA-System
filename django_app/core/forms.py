from django import forms
from django.contrib.auth import get_user_model

from .models import ProtectedResource

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
        help_text="Django will start the session, then Node-RED will collect RFID and fingerprint factors for the selected resource.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["user"].queryset = User.objects.filter(is_active=True).order_by("username")
        self.fields["resource"].queryset = ProtectedResource.objects.filter(active=True).order_by("name")
        self.fields["user"].empty_label = None
        self.fields["resource"].empty_label = None
