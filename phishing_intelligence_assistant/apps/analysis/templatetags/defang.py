"""Template tags for safe URL defanging."""
from django import template

from apps.url_analyzer.defang import defang_url

register = template.Library()


@register.filter(name="defang")
def defang(value: str) -> str:
    """Defang URL for safe rendering as plain text."""
    if not value:
        return ""
    return defang_url(str(value))
