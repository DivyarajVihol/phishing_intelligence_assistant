"""Analysis database models (plain Django ORM)."""
from django.db import models


class Investigation(models.Model):
    """Investigation run metadata and overall assessment."""
    submitted_url = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=32, default="completed")
    overall_level = models.CharField(max_length=32)
    score = models.IntegerField(null=True, blank=True)
    summary = models.TextField(blank=True)
    model_version = models.CharField(max_length=64, blank=True)

    def __str__(self) -> str:
        return f"Investigation {self.id}: {self.overall_level} ({self.status})"


class ParsedURLRecord(models.Model):
    """Parsed URL components for an investigation."""
    investigation = models.ForeignKey(
        Investigation, on_delete=models.CASCADE, related_name="parsed_urls"
    )
    original = models.TextField()
    normalized = models.TextField()
    scheme = models.CharField(max_length=32)
    scheme_assumed = models.BooleanField(default=False)
    hostname = models.CharField(max_length=255)
    subdomain = models.CharField(max_length=255, blank=True)
    registered_domain = models.CharField(max_length=255, blank=True)
    suffix = models.CharField(max_length=64, blank=True)
    port = models.IntegerField(null=True, blank=True)
    userinfo = models.CharField(max_length=255, blank=True)
    path = models.TextField(blank=True)
    query = models.TextField(blank=True)
    fragment = models.TextField(blank=True)
    is_ip_host = models.BooleanField(default=False)


class FindingRecord(models.Model):
    """Analytical finding or indicator associated with an investigation."""
    investigation = models.ForeignKey(
        Investigation, on_delete=models.CASCADE, related_name="findings"
    )
    check_name = models.CharField(max_length=128)
    category = models.CharField(max_length=64)
    status = models.CharField(max_length=32)
    severity = models.CharField(max_length=32)
    explanation = models.TextField()
    evidence = models.JSONField(default=dict, blank=True)
    source = models.CharField(max_length=64, blank=True)
    checked_at = models.DateTimeField(null=True, blank=True)


class ThreatIntelLookupRecord(models.Model):
    """External threat intelligence source query record."""
    investigation = models.ForeignKey(
        Investigation, on_delete=models.CASCADE, related_name="threat_lookups"
    )
    source = models.CharField(max_length=64)
    queried_at = models.DateTimeField(null=True, blank=True)
    query_status = models.CharField(max_length=32)
    matched = models.BooleanField(default=False)
    source_record_id = models.CharField(max_length=128, null=True, blank=True)
    response_summary = models.JSONField(default=dict, blank=True)
    error = models.TextField(null=True, blank=True)


class MLPredictionRecord(models.Model):
    """Machine learning model prediction result for an investigation."""
    investigation = models.ForeignKey(
        Investigation, on_delete=models.CASCADE, related_name="ml_predictions"
    )
    model_name = models.CharField(max_length=64)
    model_version = models.CharField(max_length=64)
    predicted_class = models.CharField(max_length=32)
    score = models.FloatField()
    threshold = models.FloatField()
