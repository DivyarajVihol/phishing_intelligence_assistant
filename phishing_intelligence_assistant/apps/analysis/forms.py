"""Forms for URL submission (Phase 10)."""
from django import forms


class URLSubmissionForm(forms.Form):
    """Single URL input form for initiating an investigation."""
    url = forms.CharField(
        label="Suspicious URL",
        max_length=2048,
        required=True,
        widget=forms.TextInput(
            attrs={
                "id": "url-input",
                "class": "input-url",
                "placeholder": "example.com/login or https://...",
                "autocomplete": "off",
                "autofocus": "autofocus",
            }
        ),
    )
