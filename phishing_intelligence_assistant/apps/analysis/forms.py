"""Forms for URL submission and history filtering (Phases 10 & 11)."""
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


class HistoryFilterForm(forms.Form):
    """Filter form for investigation history search and facet controls."""

    q = forms.CharField(
        required=False,
        label="Search",
        widget=forms.TextInput(
            attrs={
                "placeholder": "Search URL or domain...",
                "class": "input-text input-search",
            }
        ),
    )
    date_from = forms.DateField(
        required=False,
        label="From",
        widget=forms.DateInput(attrs={"type": "date", "class": "input-date"}),
    )
    date_to = forms.DateField(
        required=False,
        label="To",
        widget=forms.DateInput(attrs={"type": "date", "class": "input-date"}),
    )
    risk_level = forms.ChoiceField(
        required=False,
        label="Risk Level",
        choices=[
            ("", "All risk levels"),
            ("high", "High risk"),
            ("medium", "Medium risk"),
            ("low_observed", "Low observed risk"),
            ("inconclusive", "Inconclusive"),
        ],
        widget=forms.Select(attrs={"class": "select-filter"}),
    )
    phishtank = forms.ChoiceField(
        required=False,
        label="PhishTank",
        choices=[
            ("", "All"),
            ("match", "Match found"),
            ("no_match", "No match found"),
        ],
        widget=forms.Select(attrs={"class": "select-filter"}),
    )
    urlhaus = forms.ChoiceField(
        required=False,
        label="URLhaus",
        choices=[
            ("", "All"),
            ("match", "Match found"),
            ("no_match", "No match found"),
        ],
        widget=forms.Select(attrs={"class": "select-filter"}),
    )
    status = forms.ChoiceField(
        required=False,
        label="Status",
        choices=[
            ("", "All"),
            ("completed", "Completed"),
            ("failed", "Failed"),
        ],
        widget=forms.Select(attrs={"class": "select-filter"}),
    )
    ml_result = forms.ChoiceField(
        required=False,
        label="ML Result",
        choices=[
            ("", "All"),
            ("phishing_like", "Phishing-like"),
            ("benign", "Not phishing-like"),
        ],
        widget=forms.Select(attrs={"class": "select-filter"}),
    )
