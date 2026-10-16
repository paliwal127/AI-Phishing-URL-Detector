import logging
import math
import os
from functools import lru_cache
from pathlib import Path

import joblib

from scanner.detection.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    extract_url_features,
    model_feature_row,
)
from scanner.detection.scoring import (
    DEFAULT_DECISION_THRESHOLD,
    classify_risk_score,
    combine_risk_score,
)

MODEL_PATH = Path(os.environ.get(
    "PHISHING_MODEL_PATH",
    Path(__file__).resolve().parents[2] / "ml_model" / "models" / "phishing_rf.joblib",
))
logger = logging.getLogger(__name__)
FEATURE_LABELS = {
    "url_length": "URL length",
    "domain_length": "Hostname length",
    "dot_count": "Hostname dot count",
    "hyphen_count": "URL hyphen count",
    "special_char_count": "Special-character count",
    "subdomain_count": "Subdomain count",
    "digit_count": "URL digit count",
    "suspicious_keyword_count": "Account-related keyword count",
    "path_length": "URL path length",
    "query_parameter_count": "Query parameter count",
    "url_entropy": "URL character entropy",
    "brand_keyword_count": "Brand keyword count",
}


@lru_cache(maxsize=1)
def _load_model():
    if not MODEL_PATH.exists():
        logger.info("No trained URL model at %s; using URL rules only.", MODEL_PATH)
        return None
    try:
        artifact = joblib.load(MODEL_PATH)
        if not isinstance(artifact, dict):
            raise ValueError("The model artifact must contain a metadata dictionary.")
        if artifact.get("schema_version") != FEATURE_SCHEMA_VERSION:
            raise ValueError("The model artifact uses an incompatible feature schema.")
        if artifact.get("feature_names") != FEATURE_NAMES:
            raise ValueError("The model artifact feature names or ordering do not match.")
        if artifact.get("class_mapping") != {"0": "legitimate", "1": "phishing"}:
            raise ValueError("The model artifact class mapping is missing or incompatible.")
        model = artifact.get("model")
        if model is None or list(model.classes_) != [0, 1]:
            raise ValueError("The model artifact must expose classes 0=legitimate and 1=phishing.")
        threshold = float(artifact.get("decision_threshold", DEFAULT_DECISION_THRESHOLD))
        if not math.isfinite(threshold) or not 0 <= threshold <= 100:
            raise ValueError("The model artifact decision threshold must be between 0 and 100.")
        artifact["decision_threshold"] = threshold
        return artifact
    except Exception:
        logger.exception("The trained URL model could not be loaded; using URL rules only.")
        return None


def _rule_score(features):
    score = 0
    reasons = []

    def add(condition, points, explanation):
        nonlocal score
        if condition:
            score += points
            reasons.append(explanation)

    add(features["has_ip_address"], 30, "The hostname is an IP address rather than a recognizable domain.")
    add(features["has_at_symbol"], 22, "An @ symbol can disguise the destination in a URL.")
    add(features["brand_lookalike"], 28,
        f"The domain resembles {features['suspected_brand']}.com (possible brand impersonation).")
    add(features["suspicious_keyword_count"] >= 2, 16, "Several account or verification-related words appear in the URL.")
    add(features["suspicious_keyword_count"] == 1, 8, "An account or verification-related word appears in the URL.")
    add(features["url_length"] > 100, 12, "The URL is unusually long.")
    add(features["url_length"] > 70, 6, "The URL is longer than typical.")
    add(features["subdomain_count"] >= 3, 16, "The hostname uses several subdomains.")
    add(features["subdomain_count"] == 2, 7, "The hostname has multiple subdomains.")
    add(features["suspicious_tld"], 12, f"The .{features['domain_suffix']} suffix is frequently abused.")
    add(features["is_shortened"], 10, "This is a shortened link, so its destination is not visible here.")
    add(features["host_has_punycode"], 10, "The hostname uses encoded international characters.")
    add(features["hyphen_count"] >= 3, 8, "The URL contains an unusually high number of hyphens.")
    add(not features["uses_https"], 4, "The URL does not use HTTPS.")
    add(features["has_port"], 5, "The URL uses a non-default port.")
    add(features["digit_count"] >= 8, 6, "The URL contains many digits.")
    add(features["url_entropy"] >= 4.0 and features["url_length"] > 45, 7,
        "The URL contains a high proportion of varied characters.")
    if not reasons:
        reasons.append("No strong lexical warning signs were found. This is not a guarantee that the site is safe.")
    return min(score, 100), reasons


def _describe_model_feature(name, features):
    if name == "has_ip_address":
        return "IP address hostname" if features[name] else "Domain-name hostname"
    if name == "uses_https":
        return "URL uses HTTPS" if features[name] else "URL does not use HTTPS"
    if name == "has_at_symbol":
        return "URL contains an @ symbol" if features[name] else "URL has no @ symbol"
    if name == "is_shortened":
        return "URL uses a known shortener" if features[name] else "URL is not a known shortened link"
    if name == "suspicious_tld":
        suffix = features["domain_suffix"]
        return f".{suffix} suffix classified as frequently abused" if features[name] else f".{suffix} domain suffix"
    if name == "has_fragment":
        return "URL contains a fragment" if features[name] else "URL has no fragment"
    if name == "brand_lookalike":
        brand = features["suspected_brand"]
        return f"Hostname resembles {brand}" if features[name] else "No detected brand lookalike"
    if name == "host_has_punycode":
        return "Hostname contains punycode" if features[name] else "Hostname has no punycode"
    if name == "has_port":
        return "URL specifies a port" if features[name] else "URL uses no explicit port"
    value = features[name]
    if name in {"url_entropy"}:
        return f"{FEATURE_LABELS[name]} ({value})"
    return f"{FEATURE_LABELS[name]} ({value})"


def _model_explanations(artifact, row, phishing_index, features):
    try:
        import numpy as np
        import shap

        explanation = shap.TreeExplainer(artifact["model"])(np.asarray([row]))
        values = explanation.values
        if values.ndim == 3:
            contributions = values[0, :, phishing_index]
        else:
            contributions = values[0]
        ranked = sorted(
            ((float(value), _describe_model_feature(name, features))
             for name, value in zip(FEATURE_NAMES, contributions) if value > 0),
            reverse=True,
        )
        return [label for _, label in ranked[:3]]
    except Exception:
        return []


def analyze_url(url):
    features = extract_url_features(url)
    rule_score, reasons = _rule_score(features)
    artifact = _load_model()
    mode = "rules"
    risk_score = rule_score
    model_explanations = []
    model_error = False
    if artifact:
        try:
            row = model_feature_row(features)
            probabilities = artifact["model"].predict_proba([row])[0]
            phishing_index = list(artifact["model"].classes_).index(1)
            model_probability = float(probabilities[phishing_index])
            risk_score = combine_risk_score(model_probability, rule_score)
            model_explanations = _model_explanations(artifact, row, phishing_index, features)
            reasons.append(
                f"The trained classifier assigned a {model_probability:.0%} raw phishing score "
                "from its labeled training data; this is not a calibrated real-world probability."
            )
            mode = "hybrid"
        except Exception:
            logger.exception("The trained URL model failed during inference; using URL rules only.")
            model_error = True

    if model_error:
        reasons.append("The trained model could not complete this scan; this result uses URL rules only.")
    threshold = artifact["decision_threshold"] if artifact and not model_error else DEFAULT_DECISION_THRESHOLD
    verdict = classify_risk_score(risk_score, threshold)
    recommendations = (
        ["Do not enter passwords or payment details on this site.",
         "Open the organization’s official website directly instead of following this link."]
        if verdict != "safe" else
        ["No strong URL-based warning signs were found. Verify the domain before entering sensitive information."]
    )
    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "analysis_mode": mode,
        "features": features,
        "reasons": reasons[:6],
        "model_explanations": model_explanations,
        "recommendations": recommendations,
        "content_analysis": "unavailable",
        "redirect_analysis": "not_performed",
    }