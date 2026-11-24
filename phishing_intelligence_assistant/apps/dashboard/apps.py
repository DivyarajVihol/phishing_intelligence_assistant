"""Application configuration for dashboard app."""
from django.apps import AppConfig


class DashboardConfig(AppConfig):
    """Configuration for dashboard application."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.dashboard"
