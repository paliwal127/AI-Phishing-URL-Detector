from django.conf import settings
from django.db import models


class URLScan(models.Model):
    class Verdict(models.TextChoices):
        SAFE = "safe", "Safe"
        SUSPICIOUS = "suspicious", "Suspicious"
        PHISHING = "phishing", "Phishing"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="url_scans",
        null=True, blank=True,
    )
    url = models.URLField(max_length=2048)
    verdict = models.CharField(max_length=16, choices=Verdict.choices)
    risk_score = models.PositiveSmallIntegerField()
    analysis_mode = models.CharField(max_length=16, default="rules")
    features = models.JSONField(default=dict)
    reasons = models.JSONField(default=list)
    model_explanations = models.JSONField(default=list)
    recommendations = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


class Feedback(models.Model):
    class ReviewStatus(models.TextChoices):
        PENDING = "pending", "Pending review"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    scan = models.ForeignKey(URLScan, on_delete=models.CASCADE, related_name="feedback")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    prediction_correct = models.BooleanField()
    suggested_label = models.CharField(max_length=16, blank=True)
    review_status = models.CharField(
        max_length=12, choices=ReviewStatus.choices, default=ReviewStatus.PENDING
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]