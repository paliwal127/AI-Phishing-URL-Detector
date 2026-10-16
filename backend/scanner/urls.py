from django.urls import path

from scanner.views import (
    BrandCheckView,
    DashboardView,
    FeedbackView,
    HistoryView,
    ProfileView,
    QRScanView,
    ScanDetailView,
    ScanView,
    TextScanView,
)

urlpatterns = [
    path("scan/", ScanView.as_view(), name="scan"),
    path("scan/text/", TextScanView.as_view(), name="scan_text"),
    path("scan/qr/", QRScanView.as_view(), name="scan_qr"),
    path("scan/<int:pk>/", ScanDetailView.as_view(), name="scan_detail"),
    path("history/", HistoryView.as_view(), name="history"),
    path("feedback/", FeedbackView.as_view(), name="feedback"),
    path("dashboard/", DashboardView.as_view(), name="dashboard"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("brand-check/", BrandCheckView.as_view(), name="brand_check"),
]