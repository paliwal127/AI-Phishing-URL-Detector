from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from scanner.models import Feedback, URLScan

User = get_user_model()


class URLScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = URLScan
        fields = [
            "id", "url", "verdict", "risk_score", "analysis_mode", "features",
            "reasons", "model_explanations", "recommendations", "created_at",
        ]


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=10)

    class Meta:
        model = User
        fields = ["id", "username", "email", "password"]

    def validate(self, attrs):
        candidate = User(username=attrs["username"], email=attrs.get("email", ""))
        try:
            validate_password(attrs["password"], user=candidate)
        except DjangoValidationError as error:
            raise serializers.ValidationError({"password": error.messages}) from error
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class FeedbackSerializer(serializers.ModelSerializer):
    scan_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = Feedback
        fields = ["id", "scan_id", "prediction_correct", "suggested_label", "created_at"]
        read_only_fields = ["id", "created_at"]

    def validate_scan_id(self, value):
        user = self.context["request"].user
        scans = URLScan.objects.filter(pk=value)
        if user.is_authenticated:
            scans = scans.filter(user=user)
        else:
            scans = scans.filter(user__isnull=True)
        if not scans.exists():
            raise serializers.ValidationError("Scan not found.")
        return value

    def validate_suggested_label(self, value):
        if value and value not in URLScan.Verdict.values:
            raise serializers.ValidationError("Choose safe, suspicious, or phishing.")
        return value

    def create(self, validated_data):
        scan_id = validated_data.pop("scan_id")
        request = self.context["request"]
        return Feedback.objects.create(
            scan_id=scan_id,
            user=request.user if request.user.is_authenticated else None,
            **validated_data,
        )