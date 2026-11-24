"""Root URL configuration for phishing_intelligence_assistant."""
from django.urls import include, path

urlpatterns = [
    path("", include("apps.analysis.urls")),
    path("dashboard/", include("apps.dashboard.urls")),
]
