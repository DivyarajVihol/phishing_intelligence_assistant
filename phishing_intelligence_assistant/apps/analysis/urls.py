"""URL patterns for analysis application."""
from django.urls import path
from . import views

urlpatterns = [
    path("", views.submit, name="submit"),
    path("result/<int:id>/", views.result, name="result"),
    path("analysis/<int:id>/", views.result, name="analysis_result"),
]
