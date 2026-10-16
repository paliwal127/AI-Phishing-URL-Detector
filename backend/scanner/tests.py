import csv
import importlib.util
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import joblib
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from ml_model.train import (
    _normalize_training_url,
    _stratified_group_splits,
    normalize_dataset_label,
    train,
)
from scanner.detection.analyzer import _load_model, analyze_url
from scanner.detection.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    extract_url_features,
    model_feature_row,
    registrable_domain,
)
from scanner.models import URLScan


class RulesOnlyTestCase(TestCase):
    def setUp(self):
        self.model_path_patch = patch(
            "scanner.detection.analyzer.MODEL_PATH",
            Path(__file__).with_name("no_test_model.joblib"),
        )
        self.model_path_patch.start()
        _load_model.cache_clear()

    def tearDown(self):
        _load_model.cache_clear()
        self.model_path_patch.stop()


class FeatureExtractionTests(RulesOnlyTestCase):
    def test_brand_lookalike_does_not_flag_exact_domain(self):
        self.assertFalse(extract_url_features("https://paypal.com/account")["brand_lookalike"])
        self.assertFalse(extract_url_features("https://www.paypal.com/account")["brand_lookalike"])
        self.assertFalse(extract_url_features("https://mail.google.com/")["brand_lookalike"])
        features = extract_url_features("http://paypa1-login-security.xyz/verify")
        self.assertTrue(features["brand_lookalike"])
        self.assertEqual(features["suspected_brand"], "paypal")
        self.assertTrue(extract_url_features("https://paypal-login-security.xyz/")["brand_lookalike"])
        self.assertTrue(extract_url_features("https://pay-pal-login.example/")["brand_lookalike"])
        deceptive_subdomain = extract_url_features("https://paypal.evil.example/")
        self.assertTrue(deceptive_subdomain["brand_lookalike"])
        self.assertEqual(deceptive_subdomain["registrable_label"], "evil")
        self.assertTrue(extract_url_features("https://раypal.example/")["brand_lookalike"])
        punycode = extract_url_features("https://xn--ypal-43d9g.com/")
        self.assertTrue(punycode["host_has_punycode"])
        self.assertTrue(punycode["brand_lookalike"])
        uk_domain = extract_url_features("https://paypal.co.uk/")
        self.assertFalse(uk_domain["brand_lookalike"])
        self.assertEqual(uk_domain["registrable_label"], "paypal")
        self.assertEqual(uk_domain["subdomain_count"], 0)
        self.assertEqual(registrable_domain("mail.paypal.co.uk"), "paypal.co.uk")
        self.assertEqual(registrable_domain("paypal.evil.example"), "evil.example")

    def test_model_feature_schema_and_types_are_stable(self):
        self.assertEqual(FEATURE_NAMES, [
            "url_length", "domain_length", "dot_count", "hyphen_count", "special_char_count",
            "subdomain_count", "has_ip_address", "uses_https", "digit_count",
            "suspicious_keyword_count", "has_at_symbol", "is_shortened", "suspicious_tld",
            "path_length", "query_parameter_count", "has_fragment", "url_entropy",
            "brand_keyword_count", "brand_lookalike", "host_has_punycode", "has_port",
        ])
        features = extract_url_features("https://example.com/a?x=1#fragment")
        row = model_feature_row(features)
        self.assertEqual(len(FEATURE_NAMES), 21)
        self.assertEqual(len(row), 21)
        self.assertTrue(all(isinstance(value, (int, float)) for value in row))
        self.assertEqual(features["query_parameter_count"], 1)
        self.assertTrue(features["has_fragment"])

    def test_malformed_urls_fail_with_value_error(self):
        for url in (
            "",
            "javascript:alert(1)",
            "https://user:password@example.com/",
            "https://example.com:99999/",
            "https://exa mple.com/",
            "https://example..com/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    extract_url_features(url)
        with self.assertRaises(ValueError):
            extract_url_features(None)

    def test_inference_error_is_logged_and_explicitly_falls_back_to_rules(self):
        class BrokenModel:
            classes_ = [0, 1]

            def predict_proba(self, rows):
                raise RuntimeError("prediction failed")

        with patch(
            "scanner.detection.analyzer._load_model",
            return_value={
                "model": BrokenModel(),
                "decision_threshold": 60,
            },
        ):
            with self.assertLogs("scanner.detection.analyzer", level="ERROR") as logs:
                result = analyze_url("https://example.com/")
        self.assertEqual(result["analysis_mode"], "rules")
        self.assertTrue(any("could not complete this scan" in item for item in result["reasons"]))
        self.assertTrue(any("failed during inference" in item for item in logs.output))

    def test_legacy_artifact_without_schema_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_path = Path(temp_dir) / "legacy.joblib"
            joblib.dump({"feature_names": FEATURE_NAMES}, artifact_path)
            with patch("scanner.detection.analyzer.MODEL_PATH", artifact_path):
                _load_model.cache_clear()
                with self.assertLogs("scanner.detection.analyzer", level="ERROR"):
                    result = analyze_url("https://example.com/")
                _load_model.cache_clear()
        self.assertEqual(result["analysis_mode"], "rules")

    def test_analysis_returns_explanations_without_model(self):
        result = analyze_url("http://192.0.2.1/verify-account")
        self.assertIn(result["verdict"], URLScan.Verdict.values)
        self.assertGreater(result["risk_score"], 0)
        self.assertTrue(result["reasons"])
        self.assertEqual(result["analysis_mode"], "rules")
        self.assertEqual(result["content_analysis"], "unavailable")


class ScanAPITests(RulesOnlyTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()

    def test_scan_can_classify_phishing_and_legitimate_urls(self):
        class FixedModel:
            classes_ = [0, 1]
            n_features_in_ = len(FEATURE_NAMES)

            def __init__(self, phishing_probability):
                self.phishing_probability = phishing_probability

            def predict_proba(self, rows):
                return [[1 - self.phishing_probability, self.phishing_probability]]

        cases = (
            ("https://example.com/", 0.01, "safe"),
            ("http://paypa1-login-security.xyz/verify", 0.99, "phishing"),
        )
        for url, probability, expected_verdict in cases:
            with self.subTest(expected_verdict=expected_verdict):
                with patch(
                    "scanner.detection.analyzer._load_model",
                    return_value={
                        "model": FixedModel(probability),
                        "decision_threshold": 43,
                    },
                ):
                    response = self.client.post("/api/scan/", {"url": url}, format="json")
                self.assertEqual(response.status_code, 201)
                self.assertEqual(response.data["verdict"], expected_verdict)
                self.assertEqual(response.data["analysis_mode"], "hybrid")
                self.assertTrue(response.data["model_available"])
                self.assertEqual(response.data["url"], url)

    def test_scan_reports_rules_mode_when_model_file_is_unavailable(self):
        response = self.client.post(
            "/api/scan/", {"url": "https://example.com/"}, format="json"
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["analysis_mode"], "rules")
        self.assertFalse(response.data["model_available"])

    def test_scan_reports_rules_fallback_when_model_prediction_fails(self):
        class BrokenModel:
            classes_ = [0, 1]

            def predict_proba(self, rows):
                raise RuntimeError("prediction failed")

        with patch(
            "scanner.detection.analyzer._load_model",
            return_value={"model": BrokenModel(), "decision_threshold": 43},
        ):
            with self.assertLogs("scanner.detection.analyzer", level="ERROR"):
                response = self.client.post(
                    "/api/scan/", {"url": "https://example.com/"}, format="json"
                )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["analysis_mode"], "rules")
        self.assertFalse(response.data["model_available"])
        self.assertTrue(any("could not complete this scan" in reason for reason in response.data["reasons"]))

    def test_scan_persists_features_and_explanation(self):
        response = self.client.post(
            "/api/scan/", {"url": "http://paypa1-login-security.xyz/verify"}, format="json"
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["verdict"], "phishing")
        self.assertEqual(response.data["analysis_mode"], "rules")
        self.assertTrue(response.data["features"]["brand_lookalike"])
        self.assertTrue(URLScan.objects.filter(pk=response.data["id"]).exists())

    def test_scan_response_shape_for_legitimate_and_phishing_labelled_examples(self):
        examples = (
            ("https://paypal.com/", "legitimate"),
            ("http://paypa1-login-security.xyz/verify", "phishing"),
        )
        for url, label in examples:
            with self.subTest(label=label):
                response = self.client.post("/api/scan/", {"url": url}, format="json")
                self.assertEqual(response.status_code, 201)
                self.assertEqual(response.data["url"], url)
                self.assertIn(response.data["verdict"], URLScan.Verdict.values)
                self.assertIsInstance(response.data["risk_score"], int)
                self.assertIn(response.data["analysis_mode"], ("rules", "hybrid"))
                self.assertIsInstance(response.data["features"], dict)
                self.assertIsInstance(response.data["reasons"], list)
                self.assertIsInstance(response.data["recommendations"], list)

    def test_rejects_invalid_and_credential_urls(self):
        for url in ["", "javascript:alert(1)", "https://user:pass@example.com"]:
            with self.subTest(url=url):
                response = self.client.post("/api/scan/", {"url": url}, format="json")
                self.assertEqual(response.status_code, 400)

    def test_scan_rejects_whitespace_and_malformed_hosts(self):
        for url in ("https://exa mple.com/", "https://example..com/"):
            with self.subTest(url=url):
                response = self.client.post("/api/scan/", {"url": url}, format="json")
                self.assertEqual(response.status_code, 400)

    def test_registration_hashes_password_and_returns_jwt(self):
        response = self.client.post("/api/auth/register/", {
            "username": "new-analyst",
            "email": "analyst@example.net",
            "password": "L!nkCheck9-Forest-River",
        }, format="json")
        self.assertEqual(response.status_code, 201)
        account = get_user_model().objects.get(username="new-analyst")
        self.assertNotEqual(account.password, "L!nkCheck9-Forest-River")
        token = self.client.post("/api/auth/token/", {
            "username": "new-analyst", "password": "L!nkCheck9-Forest-River",
        }, format="json")
        self.assertEqual(token.status_code, 200)
        self.assertIn("access", token.data)
        weak_password = self.client.post("/api/auth/register/", {
            "username": "weak-user", "email": "weak@example.net", "password": "password123",
        }, format="json")
        self.assertEqual(weak_password.status_code, 400)

    def test_cors_preflight_is_limited_to_configured_origins(self):
        allowed = self.client.options("/api/scan/", HTTP_ORIGIN="http://localhost:5173")
        denied = self.client.options("/api/scan/", HTTP_ORIGIN="https://untrusted.example")
        self.assertEqual(allowed["Access-Control-Allow-Origin"], "http://localhost:5173")
        self.assertNotIn("Access-Control-Allow-Origin", denied)

    def test_text_scan_extracts_each_distinct_link(self):
        response = self.client.post("/api/scan/text/", {
            "text": "Check https://example.org/login and https://paypal.com; https://example.org/login"
        }, format="json")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["detected_count"], 2)

    def test_qr_endpoint_accepts_only_a_decoded_web_url(self):
        response = self.client.post(
            "/api/scan/qr/", {"decoded_url": "https://example.org/account"}, format="json"
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["url"], "https://example.org/account")
        rejected = self.client.post(
            "/api/scan/qr/", {"decoded_url": "javascript:alert(1)"}, format="json"
        )
        self.assertEqual(rejected.status_code, 400)

    def test_history_and_dashboard_are_user_scoped(self):
        user_model = get_user_model()
        owner = user_model.objects.create_user(username="owner", password="StrongPass123!")
        other = user_model.objects.create_user(username="other", password="StrongPass456!")
        owned = URLScan.objects.create(user=owner, url="https://example.org", verdict="safe", risk_score=0)
        URLScan.objects.create(user=other, url="https://other.org", verdict="phishing", risk_score=70)
        self.client.force_authenticate(user=owner)

        history = self.client.get("/api/history/")
        dashboard = self.client.get("/api/dashboard/")
        detail = self.client.get(f"/api/scan/{owned.pk}/")
        self.assertEqual(history.data[0]["url"], "https://example.org")
        self.assertEqual(dashboard.data["total"], 1)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(self.client.get(f"/api/scan/{owned.pk + 1}/").status_code, 404)


class ModelTrainingTests(TestCase):
    def test_url_normalization_preserves_path_query_and_fragment_case(self):
        normalized, group = _normalize_training_url(
            "HTTPS://WWW.EXAMPLE.COM/KeepCase?Query=Yes#Frag"
        )
        self.assertEqual(normalized, "https://www.example.com/KeepCase?Query=Yes#Frag")
        self.assertEqual(group, "example.com")

    def test_grouped_split_rejects_insufficient_class_hostname_groups(self):
        labels = [0, 0, 0, 1, 1, 1]
        groups = ["legit-a", "legit-a", "legit-b", "phish-a", "phish-a", "phish-b"]
        with self.assertRaisesRegex(ValueError, "only 2 distinct hostname groups"):
            _stratified_group_splits(labels, groups, 3, "Test split")

    def test_numeric_dataset_labels_can_be_mapped_to_phishing_class(self):
        self.assertEqual(normalize_dataset_label(0, "0"), 1)
        self.assertEqual(normalize_dataset_label(1, "0"), 0)
        self.assertEqual(normalize_dataset_label("legitimate"), 0)
        self.assertEqual(normalize_dataset_label("phishing"), 1)
        self.assertEqual(normalize_dataset_label("suspicious"), 1)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            normalize_dataset_label(0)
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            normalize_dataset_label(2, "0")

    def test_training_calculates_real_holdout_metrics_and_saves_artifact(self):
        rows = [
            ("https://example.com/about", "legitimate"),
            ("HTTPS://EXAMPLE.COM/about", "legitimate"),
            ("https://docs.python.org/3/", "legitimate"),
            ("https://www.wikipedia.org/", "legitimate"),
            ("https://www.mozilla.org/en-US/", "legitimate"),
            ("https://www.iana.org/domains/reserved", "legitimate"),
            ("https://www.djangoproject.com/", "legitimate"),
            ("http://paypal-login-secure.xyz/verify", "phishing"),
            ("http://g00gle-account.top/signin", "phishing"),
            ("http://192.0.2.20/confirm", "phishing"),
            ("http://secure-apple-billing.click/login", "phishing"),
            ("http://xn--paypa1-9za.example/verify", "phishing"),
            ("http://account-update-login.work/confirm", "phishing"),
            ("https://example.com/about", "legitimate"),
            ("https://conflict.example/path", "legitimate"),
            ("https://conflict.example/path", "phishing"),
            ("javascript:alert(1)", "legitimate"),
            (None, "legitimate"),
            ("https://missing-label.example/path", None),
            ("https://user:password@example.test/path", "legitimate"),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "urls.csv"
            model_path = Path(temp_dir) / "model.joblib"
            reports_dir = Path(temp_dir) / "reports"
            with csv_path.open("w", newline="", encoding="utf-8") as dataset:
                writer = csv.writer(dataset)
                writer.writerow(["url", "label"])
                writer.writerows(rows)

            model_configs = [
                {
                    "n_estimators": 6,
                    "class_weight": "balanced",
                    "min_samples_leaf": 1,
                    "max_features": "sqrt",
                    "max_depth": None,
                    "min_samples_split": 2,
                },
                {
                    "n_estimators": 8,
                    "class_weight": None,
                    "min_samples_leaf": 2,
                    "max_features": 0.8,
                    "max_depth": 8,
                    "min_samples_split": 3,
                },
            ]
            metrics = train(
                csv_path,
                model_path,
                cv_folds=2,
                reports_dir=reports_dir,
                model_configs=model_configs,
            )

            self.assertEqual(metrics["test_samples"], 3)
            self.assertEqual(sum(sum(row) for row in metrics["confusion_matrix"]), 3)
            self.assertEqual(metrics["test_hosts"], metrics["test_samples"])
            self.assertTrue(model_path.exists())
            artifact = joblib.load(model_path)
            self.assertEqual(artifact["dataset_rows"], 12)
            self.assertEqual(artifact["excluded_invalid_urls"], 2)
            self.assertEqual(artifact["excluded_conflicting_urls"], 1)
            self.assertEqual(artifact["duplicate_urls_removed"], 2)
            self.assertEqual(
                artifact["model"].n_estimators,
                artifact["training_config"]["n_estimators"],
            )
            self.assertEqual(artifact["feature_names"], FEATURE_NAMES)
            self.assertEqual(artifact["schema_version"], FEATURE_SCHEMA_VERSION)
            self.assertEqual(artifact["class_mapping"], {"0": "legitimate", "1": "phishing"})
            self.assertGreaterEqual(artifact["decision_threshold"], 0)
            self.assertLessEqual(artifact["decision_threshold"], 100)
            self.assertEqual(metrics["baseline"]["metrics"]["test_samples"], metrics["test_samples"])
            self.assertEqual(metrics["cleaning"]["rows_dropped_for_missing_values"], 2)
            self.assertEqual(metrics["cleaning"]["class_counts_after_cleaning"], {
                "legitimate": 6,
                "phishing": 6,
            })
            self.assertEqual(metrics["holdout"]["hostname_group_overlap"], 0)
            self.assertTrue(
                metrics["threshold_selection"]["selection_method"].startswith(
                    "maximize phishing F1"
                )
            )
            report = json.loads(Path(metrics["report_path"]).read_text(encoding="utf-8"))
            self.assertEqual(
                report["dataset"]["label_convention"],
                "0=legitimate, 1=phishing after normalization",
            )
            self.assertEqual(
                report["improved"]["metrics"]["confusion_matrix_labels"],
                ["legitimate", "phishing"],
            )
            self.assertIn("false_negative_examples", report["improved"])
            for image in (
                "confusion_matrix.png",
                "roc_curve.png",
                "precision_recall_curve.png",
                "feature_importance.png",
                "baseline_vs_improved.png",
            ):
                self.assertTrue((reports_dir / image).exists(), image)
            repeat_metrics = train(
                csv_path,
                Path(temp_dir) / "repeat.joblib",
                cv_folds=2,
                reports_dir=Path(temp_dir) / "repeat-reports",
                model_configs=model_configs,
            )
            self.assertEqual(
                repeat_metrics["decision_threshold"],
                metrics["decision_threshold"],
            )
            self.assertEqual(
                repeat_metrics["cross_validation"]["selected_phishing_f1_mean"],
                metrics["cross_validation"]["selected_phishing_f1_mean"],
            )
            self.assertEqual(
                repeat_metrics["confusion_matrix"],
                metrics["confusion_matrix"],
            )
            with patch("scanner.detection.analyzer.MODEL_PATH", model_path):
                from scanner.detection.analyzer import _load_model

                _load_model.cache_clear()
                result = analyze_url("http://paypal-login-security.xyz/verify")
                response = APIClient().post(
                    "/api/scan/",
                    {"url": "http://paypal-login-security.xyz/verify"},
                    format="json",
                )
                _load_model.cache_clear()
            self.assertEqual(result["analysis_mode"], "hybrid")
            self.assertIn(result["verdict"], URLScan.Verdict.values)
            self.assertEqual(response.status_code, 201)
            self.assertEqual(response.data["analysis_mode"], "hybrid")
            self.assertTrue(response.data["model_available"])
            self.assertEqual(response.data["verdict"], result["verdict"])
            self.assertEqual(response.data["risk_score"], result["risk_score"])
            from scanner.detection.scoring import classify_risk_score

            self.assertEqual(
                result["verdict"],
                classify_risk_score(result["risk_score"], artifact["decision_threshold"]),
            )
            if importlib.util.find_spec("shap"):
                self.assertTrue(result["model_explanations"])