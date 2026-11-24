"""URL patterns for reports application."""
from django.urls import path

from . import views

urlpatterns = [
    path("<int:id>/", views.report_html, name="report"),
    path("<int:id>/json/", views.report_json, name="report_json"),
]
