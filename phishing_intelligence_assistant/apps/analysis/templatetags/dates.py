"""Template tags for consistent English date and datetime formatting."""
from datetime import date, datetime
from typing import Any, Optional

from django import template
from django.conf import settings
from django.template.defaultfilters import date as django_date
from django.utils import translation

register = template.Library()


def _coerce_date(value: Any) -> Any:
    """Coerce string inputs to date or datetime objects if possible."""
    if isinstance(value, str):
        val_str = value.strip()
        if not val_str:
            return None
        try:
            return datetime.fromisoformat(val_str)
        except ValueError:
            try:
                return date.fromisoformat(val_str)
            except ValueError:
                return None
    return value


@register.filter(name="fmt_date")
def fmt_date(value: Optional[Any]) -> str:
    """Format date in consistent English day-month-year display format."""
    if value is None or value == "":
        return "-"
    coerced = _coerce_date(value)
    if coerced is None:
        return "-"
    fmt = getattr(settings, "DATE_DISPLAY_FORMAT", "d-M-Y")
    with translation.override("en"):
        result = django_date(coerced, fmt)
    return result if result else "-"


@register.filter(name="fmt_datetime")
def fmt_datetime(value: Optional[Any]) -> str:
    """Format datetime in consistent English day-month-year time AM/PM display format."""
    if value is None or value == "":
        return "-"
    coerced = _coerce_date(value)
    if coerced is None:
        return "-"
    fmt = getattr(settings, "DATETIME_DISPLAY_FORMAT", "d-M-Y h:i A")
    with translation.override("en"):
        result = django_date(coerced, fmt)
    return result if result else "-"
