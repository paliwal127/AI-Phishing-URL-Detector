import re
from urllib.parse import urlsplit

from django.contrib.auth import get_user_model
from django.db.models import Avg, Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from scanner.detection.analyzer import analyze_url
from scanner.detection.features import BRANDS, extract_url_features, is_valid_hostname
from scanner.models import Feedback, URLScan
from scanner.serializers import FeedbackSerializer, RegisterSerializer, URLScanSerializer

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
TRAILING_PUNCTUATION = ".,;:!?)]}"


def validate_scan_url(value):
    if not isinstance(value, str) or not value.strip():
        return None, "Enter a URL to scan."
    value = value.strip()
    if len(value) > 2048:
        return None, "The URL must be 2,048 characters or fewer."
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        return None, "The URL must not contain whitespace or control characters."
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None, "Use a complete HTTP or HTTPS URL."
        if parts.username or parts.password:
            return None, "URLs containing embedded credentials cannot be scanned."
        _ = parts.port
        if not is_valid_hostname(parts.hostname):
            return None, "The URL hostname is invalid."
    except ValueError:
        return None, "The URL format is invalid."
    return value, None


def create_scan(url, user):
    result = analyze_url(url)
    scan = URLScan.objects.create(
        user=user if user.is_authenticated else None,
        url=url,
        verdict=result["verdict"],
        risk_score=result["risk_score"],
        analysis_mode=result["analysis_mode"],
        features=result["features"],
        reasons=result["reasons"],
        model_explanations=result["model_explanations"],
        recommendations=result["recommendations"],
    )
    serialized = URLScanSerializer(scan).data
    serialized["content_analysis"] = result["content_analysis"]
    serialized["redirect_analysis"] = result["redirect_analysis"]
    serialized["model_available"] = result["analysis_mode"] == "hybrid"
    return serialized


class RegisterView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer


class ScanView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        url, error = validate_scan_url(request.data.get("url"))
        if error:
            return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)
        return Response(create_scan(url, request.user), status=status.HTTP_201_CREATED)


class TextScanView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        text = request.data.get("text", "")
        if not isinstance(text, str) or len(text) > 20_000:
            return Response({"error": "Message text must be 20,000 characters or fewer."},
                            status=status.HTTP_400_BAD_REQUEST)
        urls = list(dict.fromkeys(
            match.rstrip(TRAILING_PUNCTUATION) for match in URL_PATTERN.findall(text)
        ))
        if not urls:
            return Response({"error": "No HTTP or HTTPS links were found in this message."},
                            status=status.HTTP_400_BAD_REQUEST)
        results = []
        for candidate in urls[:20]:
            url, error = validate_scan_url(candidate)
            if error:
                continue
            results.append(create_scan(url, request.user))
        return Response({"detected_count": len(results), "results": results},
                        status=status.HTTP_201_CREATED)


class QRScanView(ScanView):
    def post(self, request):
        decoded_url = request.data.get("decoded_url")
        url, error = validate_scan_url(decoded_url)
        if error:
            return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)
        return Response(create_scan(url, request.user), status=status.HTTP_201_CREATED)


class BrandCheckView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        url, error = validate_scan_url(request.data.get("url"))
        if error:
            return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)
        features = extract_url_features(url)
        return Response({
            "possible_impersonation": features["brand_lookalike"],
            "suspected_brand": features["suspected_brand"] or None,
            "similarity": features["brand_similarity"],
            "brands_checked": len(BRANDS),
        })


class HistoryView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = URLScanSerializer

    def get_queryset(self):
        return URLScan.objects.filter(user=self.request.user)[:100]


class ScanDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = URLScanSerializer

    def get_queryset(self):
        return URLScan.objects.filter(user=self.request.user)


class FeedbackView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = FeedbackSerializer
    queryset = Feedback.objects.all()


class DashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scans = URLScan.objects.filter(user=request.user)
        counts = scans.aggregate(
            total=Count("id"),
            safe=Count("id", filter=Q(verdict="safe")),
            suspicious=Count("id", filter=Q(verdict="suspicious")),
            phishing=Count("id", filter=Q(verdict="phishing")),
            average_risk=Avg("risk_score"),
        )
        today = timezone.localdate()
        since = today - timezone.timedelta(days=6)
        rows = (scans.filter(created_at__date__gte=since)
                .annotate(day=TruncDate("created_at"))
                .values("day", "verdict").annotate(count=Count("id")))
        trend_map = {(row["day"], row["verdict"]): row["count"] for row in rows}
        trends = [{
            "date": (since + timezone.timedelta(days=offset)).isoformat(),
            "safe": trend_map.get((since + timezone.timedelta(days=offset), "safe"), 0),
            "suspicious": trend_map.get((since + timezone.timedelta(days=offset), "suspicious"), 0),
            "phishing": trend_map.get((since + timezone.timedelta(days=offset), "phishing"), 0),
        } for offset in range(7)]
        return Response({
            **counts,
            "average_risk": round(counts["average_risk"] or 0, 1),
            "recent_scans": URLScanSerializer(scans[:8], many=True).data,
            "trends": trends,
        })


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = get_user_model().objects.get(pk=request.user.pk)
        return Response({"id": user.pk, "username": user.get_username(), "email": user.email})