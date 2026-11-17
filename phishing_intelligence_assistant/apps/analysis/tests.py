"""Smoke tests for application."""
from django.test import TestCase


class SmokeTest(TestCase):
    """Smoke test ensuring base routing and template rendering work."""

    def test_root_url_returns_200(self) -> None:
        """Assert placeholder root URL returns HTTP 200."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
