from django.contrib import admin

from scanner.models import Feedback, URLScan


@admin.register(URLScan)
class URLScanAdmin(admin.ModelAdmin):
    list_display = ["url", "verdict", "risk_score", "analysis_mode", "user", "created_at"]
    list_filter = ["verdict", "analysis_mode", "created_at"]
    search_fields = ["url", "user__username"]
    readonly_fields = ["created_at", "features", "reasons"]


@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ["scan", "prediction_correct", "suggested_label", "review_status", "created_at"]
    list_filter = ["review_status", "prediction_correct", "created_at"]
    list_editable = ["review_status"]
    readonly_fields = ["created_at"]