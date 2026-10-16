import argparse
import logging
from pathlib import Path

import joblib

from scanner.detection.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    extract_url_features,
    model_feature_row,
)

ROOT = Path(__file__).resolve().parent
DEFAULT_MODEL = ROOT / "models" / "phishing_rf.joblib"
CLASS_NAMES = {0: "legitimate", 1: "phishing"}
TEST_URLS = (
    ("ordinary-looking candidate (not ground truth)", "https://example.com/"),
    ("brand-lookalike candidate (not ground truth)", "http://paypa1-login-security.xyz/verify"),
    ("empty URL (expected rejection)", ""),
    ("malformed hostname (expected rejection)", "https://example..com/"),
)
logger = logging.getLogger(__name__)


def validate_artifact(artifact):
    if not isinstance(artifact, dict):
        raise ValueError("The model artifact must contain a metadata dictionary.")
    if artifact.get("schema_version") != FEATURE_SCHEMA_VERSION:
        raise ValueError("The artifact uses an incompatible feature schema version.")
    if artifact.get("feature_names") != FEATURE_NAMES:
        raise ValueError("Artifact feature names or ordering do not match the feature module.")
    if artifact.get("class_mapping") != {"0": "legitimate", "1": "phishing"}:
        raise ValueError("Artifact class mapping must be 0=legitimate and 1=phishing.")

    model = artifact.get("model")
    if model is None or getattr(model, "n_features_in_", None) != len(FEATURE_NAMES):
        raise ValueError(f"The classifier must accept exactly {len(FEATURE_NAMES)} ordered features.")
    if list(getattr(model, "classes_", ())) != [0, 1]:
        raise ValueError("The classifier must expose classes 0=legitimate and 1=phishing.")
    native_feature_names = getattr(model, "feature_names_in_", None)
    if native_feature_names is not None and list(native_feature_names) != FEATURE_NAMES:
        raise ValueError("Classifier feature names or ordering do not match the feature module.")
    if not callable(getattr(model, "predict", None)):
        raise ValueError("The classifier does not support predict().")
    return model


def check_model(model_path):
    artifact = joblib.load(model_path)
    model = validate_artifact(artifact)
    print(f"Loaded model: {Path(model_path).resolve()}")
    print(f"Feature schema: {FEATURE_SCHEMA_VERSION} ({len(FEATURE_NAMES)} ordered features)")
    if getattr(model, "feature_names_in_", None) is None:
        print("Feature order is verified from artifact metadata; the classifier stores positional inputs.")
    print("Class mapping: 0=legitimate, 1=phishing")

    errors = 0
    for label, url in TEST_URLS:
        try:
            features = extract_url_features(url)
        except ValueError as error:
            print(f"Rejected {label}: {error}")
            continue

        row = model_feature_row(features)
        if len(row) != model.n_features_in_:
            raise ValueError(
                f"{label}: extracted {len(row)} features, but the model expects "
                f"{model.n_features_in_}."
            )

        try:
            prediction = model.predict([row])[0]
            if prediction not in CLASS_NAMES:
                raise ValueError(f"Classifier returned unsupported class {prediction!r}.")
            print(f"{label}: predicted {CLASS_NAMES[prediction]} (class {prediction})")
            predict_proba = getattr(model, "predict_proba", None)
            if callable(predict_proba):
                probabilities = predict_proba([row])[0]
                scores = {
                    CLASS_NAMES[class_id]: float(probability)
                    for class_id, probability in zip(model.classes_, probabilities)
                }
                print(f"  raw model scores (not calibrated): {scores}")
        except Exception:
            logger.exception("Prediction failed for test case %s.", label)
            errors += 1

    if errors:
        logger.error("Model verification failed for %d test case(s).", errors)
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Load and locally smoke-test a phishing URL model without visiting test URLs."
    )
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL, help="Path to a trusted joblib model.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.ERROR, format="%(levelname)s: %(message)s")
    return 0 if check_model(args.model) else 1


if __name__ == "__main__":
    raise SystemExit(main())
