import argparse
import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import matplotlib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedGroupKFold

from scanner.detection.analyzer import _rule_score
from scanner.detection.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    extract_url_features,
    model_feature_row,
)
from scanner.detection.scoring import DEFAULT_DECISION_THRESHOLD, combine_risk_score

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT = ROOT / "models" / "phishing_rf.joblib"
DEFAULT_REPORTS = ROOT / "reports"
RANDOM_STATE = 42
CLASS_MAPPING = {"0": "legitimate", "1": "phishing"}
BASELINE_CONFIG = {
    "n_estimators": 500,
    "class_weight": "balanced",
    "min_samples_leaf": 2,
    "max_leaf_nodes": 2048,
    "random_state": RANDOM_STATE,
    "n_jobs": -1,
}
MODEL_CONFIGS = [
    {
        "n_estimators": 100,
        "class_weight": "balanced",
        "min_samples_leaf": 1,
        "max_features": "sqrt",
        "max_depth": None,
        "min_samples_split": 2,
    },
    {
        "n_estimators": 150,
        "class_weight": None,
        "min_samples_leaf": 2,
        "max_features": 0.8,
        "max_depth": 32,
        "min_samples_split": 5,
    },
    {
        "n_estimators": 200,
        "class_weight": "balanced_subsample",
        "min_samples_leaf": 2,
        "max_features": "sqrt",
        "max_depth": 24,
        "min_samples_split": 2,
    },
]
logger = logging.getLogger(__name__)


def normalize_dataset_label(value, phishing_label=None):
    label_map = {
        "legitimate": 0,
        "legit": 0,
        "benign": 0,
        "safe": 0,
        "good": 0,
        "phishing": 1,
        "phish": 1,
        "malicious": 1,
        "suspicious": 1,
        "bad": 1,
    }
    label_text = str(value).strip().lower()
    if label_text in label_map:
        return label_map[label_text]
    try:
        numeric_label = float(label_text)
    except ValueError as error:
        raise ValueError(f"Unsupported dataset label: {value!r}") from error
    if numeric_label not in {0, 1}:
        raise ValueError(f"Unsupported numeric dataset label: {value!r}; only 0 and 1 are accepted.")
    if phishing_label not in {"0", "1"}:
        raise ValueError(
            f"Numeric label {value!r} is ambiguous; specify --phishing-label as 0 or 1."
        )
    return int(numeric_label == int(phishing_label))


def _normalize_training_url(value):
    if not isinstance(value, str):
        return None
    url = value.strip()
    if (not url or len(url) > 2048
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url)):
        return None
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if (parts.scheme.lower() not in {"http", "https"} or not host
            or parts.username is not None or parts.password is not None):
        return None
    try:
        host.encode("idna")
    except UnicodeError:
        return None
    if ":" in host and not host.startswith("["):
        authority = f"[{host}]"
    else:
        authority = host
    if port is not None:
        authority = f"{authority}:{port}"
    normalized_url = urlunsplit((
        parts.scheme.lower(),
        authority,
        parts.path,
        parts.query,
        parts.fragment,
    ))
    grouping_host = host[4:] if host.startswith("www.") else host
    return normalized_url, grouping_host


def _label_counts(labels):
    counts = pd.Series(labels).value_counts().to_dict()
    return {
        "legitimate": int(counts.get(0, 0)),
        "phishing": int(counts.get(1, 0)),
    }


def _stratified_group_splits(labels, groups, n_splits, description):
    if n_splits < 2:
        raise ValueError(f"{description} requires at least two group folds.")
    labels = np.asarray(labels)
    groups = np.asarray(groups)
    for label, class_name in ((0, "legitimate"), (1, "phishing")):
        class_groups = np.unique(groups[labels == label]).size
        if class_groups < n_splits:
            raise ValueError(
                f"{description} cannot stratify {class_name} URLs across {n_splits} folds: "
                f"only {class_groups} distinct hostname groups are available."
            )
    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=RANDOM_STATE,
    )
    try:
        splits = list(splitter.split(np.zeros(len(labels)), labels, groups))
    except ValueError as error:
        raise ValueError(f"{description} failed to create stratified hostname folds: {error}") from error
    for fold_number, (train_indices, validation_indices) in enumerate(splits, start=1):
        if set(np.unique(labels[train_indices])) != {0, 1} or set(
            np.unique(labels[validation_indices])
        ) != {0, 1}:
            raise ValueError(
                f"{description} fold {fold_number} does not contain both classes in its "
                "training and validation groups. Add independent hostname groups or reduce "
                "the fold count; no ungrouped fallback is used."
            )
        if set(groups[train_indices]).intersection(groups[validation_indices]):
            raise ValueError(f"{description} fold {fold_number} leaks hostname groups.")
    return splits


def _phishing_probability(model, rows):
    classes = list(model.classes_)
    if classes != [0, 1]:
        raise ValueError("The trained classifier must use 0=legitimate and 1=phishing classes.")
    return model.predict_proba(rows)[:, classes.index(1)]


def _combined_scores(probabilities, rule_scores):
    return np.asarray([
        combine_risk_score(float(probability), int(rule_score))
        for probability, rule_score in zip(probabilities, rule_scores)
    ], dtype=int)


def _metrics(labels, probabilities, risk_scores, threshold):
    labels = np.asarray(labels, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    risk_scores = np.asarray(risk_scores, dtype=int)
    predictions = (risk_scores >= threshold).astype(int)
    confusion = confusion_matrix(labels, predictions, labels=[0, 1])
    report = classification_report(
        labels,
        predictions,
        labels=[0, 1],
        target_names=["legitimate", "phishing"],
        output_dict=True,
        zero_division=0,
    )
    metrics = {
        "decision_threshold": float(threshold),
        "accuracy": float(accuracy_score(labels, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(labels, predictions)),
        "phishing_precision": float(precision_score(labels, predictions, pos_label=1, zero_division=0)),
        "phishing_recall": float(recall_score(labels, predictions, pos_label=1, zero_division=0)),
        "phishing_f1": float(f1_score(labels, predictions, pos_label=1, zero_division=0)),
        "legitimate_precision": float(precision_score(labels, predictions, pos_label=0, zero_division=0)),
        "legitimate_recall": float(recall_score(labels, predictions, pos_label=0, zero_division=0)),
        "macro_f1": float(f1_score(labels, predictions, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(labels, predictions, average="weighted", zero_division=0)),
        "confusion_matrix": confusion.tolist(),
        "confusion_matrix_labels": ["legitimate", "phishing"],
        "classification_report": report,
        "test_samples": int(len(labels)),
        "false_positive_count": int(confusion[0, 1]),
        "false_negative_count": int(confusion[1, 0]),
        "false_positive_rate": float(confusion[0, 1] / max(confusion[0].sum(), 1)),
        "false_negative_rate": float(confusion[1, 0] / max(confusion[1].sum(), 1)),
    }
    if len(np.unique(labels)) == 2:
        metrics["roc_auc"] = float(roc_auc_score(labels, probabilities))
        metrics["precision_recall_auc"] = float(average_precision_score(labels, probabilities))
    else:
        metrics["roc_auc"] = None
        metrics["precision_recall_auc"] = None
    return metrics, predictions


def _select_threshold(labels, risk_scores):
    precision, recall, thresholds = precision_recall_curve(labels, risk_scores, pos_label=1)
    if not len(thresholds):
        return DEFAULT_DECISION_THRESHOLD
    f1_scores = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-12)
    best_f1 = f1_scores.max()
    best_indices = np.flatnonzero(np.isclose(f1_scores, best_f1))
    return float(thresholds[best_indices[-1]])


def _false_examples(urls, labels, predictions, scores, reasons, target_class, limit=10):
    indices = [
        index for index, (actual, predicted) in enumerate(zip(labels, predictions))
        if actual == target_class and predicted != target_class
    ]
    indices.sort(key=lambda index: scores[index])
    return [
        {
            "url": urls[index],
            "actual_class": "phishing" if labels[index] == 1 else "legitimate",
            "predicted_class": "phishing" if predictions[index] == 1 else "legitimate",
            "risk_score": int(scores[index]),
            "rule_signals": reasons[index],
        }
        for index in indices[:limit]
    ]


def _save_plots(report_dir, labels, baseline, improved, feature_names, importances):
    report_dir.mkdir(parents=True, exist_ok=True)
    confusion = np.asarray(improved["metrics"]["confusion_matrix"])
    figure, axis = plt.subplots(figsize=(6.5, 5.5))
    image = axis.imshow(confusion, interpolation="nearest", cmap="Blues")
    figure.colorbar(image, ax=axis)
    axis.set(
        xticks=[0, 1],
        yticks=[0, 1],
        xticklabels=["Legitimate", "Phishing"],
        yticklabels=["Legitimate", "Phishing"],
        xlabel="Predicted class",
        ylabel="Actual class",
        title="Improved model confusion matrix",
    )
    for row in range(2):
        for column in range(2):
            axis.text(column, row, str(confusion[row, column]), ha="center", va="center")
    figure.tight_layout()
    figure.savefig(report_dir / "confusion_matrix.png", dpi=150)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(7, 5.5))
    for model_name, result in (("Baseline", baseline), ("Improved", improved)):
        false_positive_rate, true_positive_rate, _ = roc_curve(labels, result["probabilities"])
        auc = result["metrics"]["roc_auc"]
        axis.plot(false_positive_rate, true_positive_rate, label=f"{model_name} (AUC={auc:.3f})")
    axis.plot([0, 1], [0, 1], linestyle="--", color="grey")
    axis.set(xlabel="False positive rate", ylabel="Phishing recall", title="ROC curve")
    axis.legend()
    figure.tight_layout()
    figure.savefig(report_dir / "roc_curve.png", dpi=150)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(7, 5.5))
    for model_name, result in (("Baseline", baseline), ("Improved", improved)):
        precision, recall, _ = precision_recall_curve(labels, result["probabilities"])
        average_precision = result["metrics"]["precision_recall_auc"]
        axis.plot(recall, precision, label=f"{model_name} (AP={average_precision:.3f})")
    axis.set(xlabel="Phishing recall", ylabel="Phishing precision", title="Precision-recall curve")
    axis.legend()
    figure.tight_layout()
    figure.savefig(report_dir / "precision_recall_curve.png", dpi=150)
    plt.close(figure)

    ordered = np.argsort(importances)[-15:]
    figure, axis = plt.subplots(figsize=(8, 6))
    axis.barh(np.asarray(feature_names)[ordered], np.asarray(importances)[ordered])
    axis.set(xlabel="Random Forest impurity importance", title="Top feature importances")
    figure.tight_layout()
    figure.savefig(report_dir / "feature_importance.png", dpi=150)
    plt.close(figure)

    comparison_names = [
        ("accuracy", "Accuracy"),
        ("balanced_accuracy", "Balanced accuracy"),
        ("phishing_precision", "Phishing precision"),
        ("phishing_recall", "Phishing recall"),
        ("phishing_f1", "Phishing F1"),
        ("macro_f1", "Macro F1"),
    ]
    x_values = np.arange(len(comparison_names))
    width = 0.36
    figure, axis = plt.subplots(figsize=(10, 5.5))
    axis.bar(
        x_values - width / 2,
        [baseline["metrics"][key] for key, _ in comparison_names],
        width,
        label="Baseline",
    )
    axis.bar(
        x_values + width / 2,
        [improved["metrics"][key] for key, _ in comparison_names],
        width,
        label="Improved",
    )
    axis.set(
        xticks=x_values,
        xticklabels=[label for _, label in comparison_names],
        ylim=(0, 1),
        title="Baseline versus improved model on the untouched test set",
    )
    axis.tick_params(axis="x", labelrotation=20)
    axis.legend()
    figure.tight_layout()
    figure.savefig(report_dir / "baseline_vs_improved.png", dpi=150)
    plt.close(figure)


def train(
    dataset_path,
    output_path=DEFAULT_OUTPUT,
    phishing_label=None,
    *,
    cv_folds=3,
    reports_dir=DEFAULT_REPORTS,
    model_configs=None,
):
    started_at = time.perf_counter()
    dataset_path = Path(dataset_path)
    output_path = Path(output_path)
    reports_dir = Path(reports_dir)
    if phishing_label not in {None, "0", "1"}:
        raise ValueError("phishing_label must be explicitly set to '0' or '1'.")

    previous_config = BASELINE_CONFIG.copy()
    if output_path.exists():
        try:
            previous_artifact = joblib.load(output_path)
            if isinstance(previous_artifact, dict):
                stored_config = previous_artifact.get("training_config", {})
                if stored_config:
                    previous_config.update({
                        key: stored_config[key]
                        for key in BASELINE_CONFIG
                        if key in stored_config
                    })
        except Exception:
            logger.exception("Could not read the previous artifact configuration; using the known baseline.")

    data = pd.read_csv(
        dataset_path,
        usecols=lambda column: str(column).strip().lower() in {"url", "label"},
        dtype="string",
    )
    data.columns = [str(column).strip().lower() for column in data.columns]
    if not {"url", "label"}.issubset(data.columns):
        raise ValueError("Dataset must contain 'url' and 'label' columns.")
    if data.columns.tolist().count("url") != 1 or data.columns.tolist().count("label") != 1:
        raise ValueError("Dataset must contain exactly one URL column and one label column.")

    input_rows = len(data)
    missing_url_rows = int(data["url"].isna().sum())
    missing_label_rows = int(data["label"].isna().sum())
    missing_rows = int(data[["url", "label"]].isna().any(axis=1).sum())
    nonmissing_labels = data.loc[data["label"].notna(), "label"]
    normalized_labels = []
    for row_index, value in nonmissing_labels.items():
        try:
            normalized_labels.append(normalize_dataset_label(value, phishing_label))
        except ValueError as error:
            raise ValueError(f"Invalid label at CSV row {row_index + 2}: {error}") from error
    labels_before_cleaning = _label_counts(normalized_labels)
    print(
        "Class counts before URL cleaning "
        "(0=legitimate, 1=phishing): "
        f"{json.dumps(labels_before_cleaning, sort_keys=True)}"
    )

    data["label"] = pd.Series(
        dict(zip(nonmissing_labels.index, normalized_labels)),
        dtype="int64",
    )
    data = data.dropna(subset=["url", "label"]).copy()
    data["label"] = data["label"].astype(int)
    normalized_urls = []
    grouping_hosts = []
    for value in data["url"]:
        normalized = _normalize_training_url(str(value))
        normalized_urls.append(normalized[0] if normalized else None)
        grouping_hosts.append(normalized[1] if normalized else None)
    data["url"] = normalized_urls
    data["host_group"] = grouping_hosts
    invalid_urls = int(data["url"].isna().sum())
    data = data.dropna(subset=["url", "host_group"]).copy()

    label_conflicts = data.groupby("url", sort=False)["label"].nunique()
    conflicting_urls = set(label_conflicts[label_conflicts > 1].index)
    conflicting_rows = int(data["url"].isin(conflicting_urls).sum())
    data = data.loc[~data["url"].isin(conflicting_urls)].copy()
    duplicate_rows_removed = int(data["url"].duplicated().sum())
    data = data.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)

    rows = []
    rule_scores = []
    rule_reasons = []
    feature_invalid_indices = []
    for index, url in enumerate(data["url"]):
        try:
            features = extract_url_features(url)
        except ValueError:
            feature_invalid_indices.append(index)
            continue
        rows.append(model_feature_row(features))
        rule_score, reasons = _rule_score(features)
        rule_scores.append(rule_score)
        rule_reasons.append(reasons)
    feature_invalid_urls = len(feature_invalid_indices)
    if feature_invalid_indices:
        data = data.drop(index=feature_invalid_indices).reset_index(drop=True)
    if not rows:
        raise ValueError("No valid URLs remain after URL validation and duplicate cleaning.")

    matrix = np.asarray(rows, dtype=float)
    labels = data["label"].to_numpy(dtype=int)
    groups = data["host_group"].to_numpy(dtype=str)
    rule_scores = np.asarray(rule_scores, dtype=int)
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_NAMES):
        raise ValueError(
            f"Feature schema mismatch: expected {len(FEATURE_NAMES)} ordered features, "
            f"received shape {matrix.shape}."
        )
    counts_after_cleaning = _label_counts(labels)
    print(
        "Class counts after URL, conflict, and duplicate cleaning "
        "(0=legitimate, 1=phishing): "
        f"{json.dumps(counts_after_cleaning, sort_keys=True)}"
    )
    if len(data) < 10 or set(np.unique(labels)) != {0, 1}:
        raise ValueError(
            "Need at least 10 valid, unambiguous URLs and examples from both classes after cleaning."
        )

    holdout_splits = _stratified_group_splits(
        labels,
        groups,
        5,
        "Final hostname-grouped test split",
    )
    train_indices, test_indices = holdout_splits[0]
    train_groups = groups[train_indices]
    train_labels = labels[train_indices]
    cv_splits_local = _stratified_group_splits(
        train_labels,
        train_groups,
        cv_folds,
        "Training-only cross-validation",
    )
    cv_splits = [
        (train_indices[local_train], train_indices[local_validation])
        for local_train, local_validation in cv_splits_local
    ]

    candidate_configs = model_configs or MODEL_CONFIGS
    if not candidate_configs:
        raise ValueError("At least one Random Forest candidate configuration is required.")
    cv_results = []
    out_of_fold_results = []
    for config_number, candidate_config in enumerate(candidate_configs, start=1):
        config = {
            **candidate_config,
            "random_state": RANDOM_STATE,
            "n_jobs": -1,
        }
        oof_probabilities = np.full(len(train_indices), np.nan, dtype=float)
        fold_f1 = []
        for fold_number, (fit_indices, validation_indices) in enumerate(cv_splits, start=1):
            model = RandomForestClassifier(**config)
            model.fit(matrix[fit_indices], labels[fit_indices])
            probabilities = _phishing_probability(model, matrix[validation_indices])
            oof_positions = np.searchsorted(train_indices, validation_indices)
            oof_probabilities[oof_positions] = probabilities
            validation_scores = _combined_scores(
                probabilities,
                rule_scores[validation_indices],
            )
            fold_f1.append(
                float(f1_score(
                    labels[validation_indices],
                    validation_scores >= DEFAULT_DECISION_THRESHOLD,
                    pos_label=1,
                    zero_division=0,
                ))
            )
            print(
                f"Candidate {config_number}/{len(candidate_configs)}, fold "
                f"{fold_number}/{cv_folds}: phishing F1={fold_f1[-1]:.4f}"
            )
        if np.isnan(oof_probabilities).any():
            raise ValueError("Cross-validation did not produce out-of-fold scores for every training URL.")
        cv_results.append({
            "config": config,
            "phishing_f1_mean": float(np.mean(fold_f1)),
            "phishing_f1_std": float(np.std(fold_f1, ddof=1)) if len(fold_f1) > 1 else 0.0,
            "fold_phishing_f1": fold_f1,
        })
        out_of_fold_results.append(oof_probabilities)

    best_config_index = max(
        range(len(cv_results)),
        key=lambda index: (cv_results[index]["phishing_f1_mean"], -index),
    )
    selected_cv = cv_results[best_config_index]
    selected_oof_probabilities = out_of_fold_results[best_config_index]
    selected_oof_risk_scores = _combined_scores(
        selected_oof_probabilities,
        rule_scores[train_indices],
    )
    decision_threshold = _select_threshold(train_labels, selected_oof_risk_scores)
    default_threshold_metrics, _ = _metrics(
        train_labels,
        selected_oof_probabilities,
        selected_oof_risk_scores,
        DEFAULT_DECISION_THRESHOLD,
    )
    selected_threshold_metrics, _ = _metrics(
        train_labels,
        selected_oof_probabilities,
        selected_oof_risk_scores,
        decision_threshold,
    )

    improved_model = RandomForestClassifier(**selected_cv["config"])
    improved_model.fit(matrix[train_indices], labels[train_indices])
    improved_probabilities = _phishing_probability(improved_model, matrix[test_indices])
    improved_scores = _combined_scores(improved_probabilities, rule_scores[test_indices])
    improved_metrics, improved_predictions = _metrics(
        labels[test_indices],
        improved_probabilities,
        improved_scores,
        decision_threshold,
    )

    baseline_model = RandomForestClassifier(**previous_config)
    baseline_model.fit(matrix[train_indices], labels[train_indices])
    baseline_probabilities = _phishing_probability(baseline_model, matrix[test_indices])
    baseline_scores = _combined_scores(baseline_probabilities, rule_scores[test_indices])
    baseline_metrics, baseline_predictions = _metrics(
        labels[test_indices],
        baseline_probabilities,
        baseline_scores,
        DEFAULT_DECISION_THRESHOLD,
    )
    test_urls = data["url"].iloc[test_indices].tolist()
    test_reasons = [rule_reasons[index] for index in test_indices]
    improved_false_negatives = _false_examples(
        test_urls,
        labels[test_indices],
        improved_predictions,
        improved_scores,
        test_reasons,
        target_class=1,
    )
    improved_false_positives = _false_examples(
        test_urls,
        labels[test_indices],
        improved_predictions,
        improved_scores,
        test_reasons,
        target_class=0,
    )

    baseline = {
        "config": previous_config,
        "metrics": baseline_metrics,
        "probabilities": baseline_probabilities,
    }
    improved = {
        "config": selected_cv["config"],
        "metrics": improved_metrics,
        "probabilities": improved_probabilities,
    }
    feature_importances = improved_model.feature_importances_.tolist()
    fingerprint = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    elapsed_seconds = time.perf_counter() - started_at
    cleaning = {
        "source_rows": int(input_rows),
        "missing_url_rows": missing_url_rows,
        "missing_label_rows": missing_label_rows,
        "rows_dropped_for_missing_values": missing_rows,
        "class_counts_before_cleaning": labels_before_cleaning,
        "invalid_urls": invalid_urls + feature_invalid_urls,
        "conflicting_urls": len(conflicting_urls),
        "rows_removed_for_conflicting_labels": conflicting_rows,
        "duplicate_urls_removed": duplicate_rows_removed,
        "rows_after_cleaning": int(len(data)),
        "class_counts_after_cleaning": counts_after_cleaning,
        "unique_hostname_groups": int(np.unique(groups).size),
        "phishing_label_argument": phishing_label,
        "label_mapping": CLASS_MAPPING,
    }
    baseline_output = {
        "config": previous_config,
        "metrics": baseline_metrics,
        "false_negative_examples": _false_examples(
            test_urls,
            labels[test_indices],
            baseline_predictions,
            baseline_scores,
            test_reasons,
            target_class=1,
        ),
        "false_positive_examples": _false_examples(
            test_urls,
            labels[test_indices],
            baseline_predictions,
            baseline_scores,
            test_reasons,
            target_class=0,
        ),
    }
    improved_output = {
        "config": selected_cv["config"],
        "metrics": improved_metrics,
        "false_negative_examples": improved_false_negatives,
        "false_positive_examples": improved_false_positives,
    }
    report = {
        "dataset": {
            "path": str(dataset_path.resolve()),
            "sha256": fingerprint,
            "label_convention": "0=legitimate, 1=phishing after normalization",
        },
        "cleaning": cleaning,
        "holdout": {
            "strategy": "first fold of a shuffled stratified 5-fold hostname-grouped split",
            "train_rows": int(len(train_indices)),
            "test_rows": int(len(test_indices)),
            "train_hostname_groups": int(np.unique(groups[train_indices]).size),
            "test_hostname_groups": int(np.unique(groups[test_indices]).size),
            "hostname_group_overlap": int(len(
                set(groups[train_indices]).intersection(groups[test_indices])
            )),
        },
        "cross_validation": {
            "strategy": f"{cv_folds}-fold stratified hostname-grouped CV on training groups only",
            "selection_metric": "phishing F1 at default hybrid risk threshold 60",
            "candidates": cv_results,
            "selected_config_index": best_config_index,
            "selected_phishing_f1_mean": selected_cv["phishing_f1_mean"],
            "selected_phishing_f1_std": selected_cv["phishing_f1_std"],
        },
        "threshold_selection": {
            "score": "hybrid risk score on a 0-100 scale",
            "default_threshold": DEFAULT_DECISION_THRESHOLD,
            "selected_threshold": decision_threshold,
            "selection_method": "maximize phishing F1 on training-only out-of-fold predictions; ties prefer higher threshold",
            "default_oof_metrics": default_threshold_metrics,
            "selected_oof_metrics": selected_threshold_metrics,
        },
        "baseline": baseline_output,
        "improved": improved_output,
        "feature_importance": [
            {"feature": name, "importance": float(importance)}
            for name, importance in zip(FEATURE_NAMES, feature_importances)
        ],
        "runtime_seconds": float(elapsed_seconds),
        "reproducibility": {
            "random_state": RANDOM_STATE,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": FEATURE_NAMES,
            "class_mapping": CLASS_MAPPING,
            "preprocessing_fitted_on_test_data": False,
        },
    }
    _save_plots(
        reports_dir,
        labels[test_indices],
        baseline,
        improved,
        FEATURE_NAMES,
        feature_importances,
    )
    report_path = reports_dir / "evaluation.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    metrics = {
        **improved_metrics,
        "baseline": baseline_output,
        "improved": improved_output,
        "cross_validation": report["cross_validation"],
        "holdout": report["holdout"],
        "threshold_selection": report["threshold_selection"],
        "cleaning": cleaning,
        "runtime_seconds": float(elapsed_seconds),
        "test_hosts": int(np.unique(groups[test_indices]).size),
        "report_path": str(report_path),
        "feature_importance": report["feature_importance"],
    }
    artifact = {
        "model": improved_model,
        "feature_names": FEATURE_NAMES,
        "schema_version": FEATURE_SCHEMA_VERSION,
        "class_mapping": CLASS_MAPPING,
        "decision_threshold": decision_threshold,
        "decision_threshold_scale": "hybrid risk score from 0 to 100",
        "metrics": metrics,
        "dataset_sha256": fingerprint,
        "dataset_rows": int(len(data)),
        "excluded_invalid_urls": cleaning["invalid_urls"],
        "excluded_conflicting_urls": cleaning["conflicting_urls"],
        "duplicate_urls_removed": cleaning["duplicate_urls_removed"],
        "numeric_phishing_label": phishing_label,
        "holdout_strategy": report["holdout"]["strategy"],
        "training_config": selected_cv["config"],
        "baseline_config": previous_config,
        "training_report": str(report_path),
        "training_runtime_seconds": float(elapsed_seconds),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_path = tempfile.mkstemp(
        prefix=f"{output_path.stem}.",
        suffix=".joblib",
        dir=output_path.parent,
    )
    os.close(handle)
    try:
        joblib.dump(artifact, temporary_path)
        os.replace(temporary_path, output_path)
    finally:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train and evaluate a grouped Random Forest URL phishing classifier."
    )
    parser.add_argument("dataset", help="CSV containing url,label columns")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--reports-dir", default=str(DEFAULT_REPORTS))
    parser.add_argument("--cv-folds", type=int, default=3)
    parser.add_argument(
        "--phishing-label",
        choices=["0", "1"],
        help="Required for numeric labels; UCI PhiUSIIL documents 0=phishing, 1=legitimate.",
    )
    args = parser.parse_args()
    print(json.dumps(
        train(
            args.dataset,
            args.output,
            args.phishing_label,
            cv_folds=args.cv_folds,
            reports_dir=args.reports_dir,
        ),
        indent=2,
    ))
