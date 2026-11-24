"""Views for dashboard metrics visualization (Phase 14)."""
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from apps.dashboard.metrics import get_dashboard_metrics


def dashboard(request: HttpRequest) -> HttpResponse:
    """Render metrics dashboard with aggregated investigation statistics."""
    metrics = get_dashboard_metrics()
    return render(request, "dashboard/dashboard.html", {"metrics": metrics})
