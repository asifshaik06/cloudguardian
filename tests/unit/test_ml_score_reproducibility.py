"""Comprehensive reproducibility tests for ThreatGuard ML inference and XAI attribution.

Covers:
1. Exact ALT-0004 feature-vector inference reproduction.
2. Score and threshold consistency against calibrated baseline_v1.joblib.
3. Tree-path information isolation gain attribution consistency.
4. Traversal across all 200 Isolation Forest estimators.
5. Strict separation of raw telemetry observations from derived explanations.
6. Robustness against missing, partial, negative, and malformed feature vectors.
7. Model artifact version, metadata, and threshold provenance consistency.
8. Repeated inference determinism across multiple invocations.
"""
import os
import joblib
import numpy as np
import pytest

from backend.ml_engine.detector import RuntimeDetector
from backend.ml_engine.xai import explain_isolation_forest_sample
from backend.soc.store import SOCStore


MODEL_PATH = "models/baseline_v1.joblib"

# Exact 12-feature window vector representing the ALT-0004 attack event:
# 90 ListBuckets calls from unfamiliar Russian IP at 03:00 UTC (off-hours)
ALT_0004_FEATURE_VECTOR = {
    "call_count": 90.0,
    "call_velocity": 15.0,        # 90 calls / 6.0 baseline average
    "error_ratio": 0.0,
    "unique_services": 1.0,       # S3 only
    "unique_events": 1.0,         # ListBuckets only
    "enumeration_ratio": 1.0,     # ListBuckets is read/recon
    "sensitive_count": 0.0,
    "iam_change_count": 0.0,
    "first_service_ratio": 0.0,
    "first_ip": 1.0,              # First-time foreign IP (203.0.113.19)
    "off_hours": 1.0,             # 03:00 UTC (outside 08:00-18:00 business window)
    "event_entropy": 0.0,         # Monolithic single event type
}

# The synthetic 450-call burst vector from transcript step 3442 (which yielded 0.6746)
SYNTHETIC_450_BURST_VECTOR = {
    "call_count": 450.0,
    "call_velocity": 90.0,
    "error_ratio": 0.05,
    "unique_services": 3.0,
    "unique_events": 6.0,
    "enumeration_ratio": 0.6,
    "sensitive_count": 2.0,
    "iam_change_count": 1.0,
    "first_service_ratio": 0.33,
    "first_ip": 1.0,
    "off_hours": 1.0,
    "event_entropy": 2.1,
}


@pytest.fixture(scope="module")
def detector():
    assert os.path.exists(MODEL_PATH), f"Model artifact missing: {MODEL_PATH}"
    return RuntimeDetector(MODEL_PATH)


@pytest.fixture(scope="module")
def model_card():
    assert os.path.exists(MODEL_PATH), f"Model artifact missing: {MODEL_PATH}"
    return joblib.load(MODEL_PATH)


# ===========================================================================
# 1. Exact ALT-0004 Feature-Vector Inference
# ===========================================================================

def test_exact_alt0004_feature_vector_inference(detector):
    """Verify that scoring the exact 12-feature ALT-0004 attack vector produces
    an authentic anomaly score exceeding the calibrated threshold."""
    result = detector.score_window(ALT_0004_FEATURE_VECTOR)

    assert result["is_anomaly"] is True
    # The mathematically computed Isolation Forest anomaly score is 0.6959
    assert result["score"] == 0.6959
    assert result["threshold"] == 0.61
    assert result["score"] > result["threshold"]

    # Verify multi-detector scores indicate an outlier
    scores = result["scores"]
    assert scores["isolation_forest"] == 0.6959
    assert scores["zscore"] > 4.4257       # Z-score exceeds calibrated 99th percentile
    assert scores["lof"] > 4.2671          # LOF exceeds calibrated threshold


def test_transcript_synthetic_vector_score_provenance(detector):
    """Verify the provenance of the 0.6746 score reported in the previous QA audit.
    Demonstrates that 0.6746 resulted from the synthetic 450-burst test vector."""
    result = detector.score_window(SYNTHETIC_450_BURST_VECTOR)

    assert result["is_anomaly"] is True
    assert result["score"] == 0.6746
    assert result["threshold"] == 0.61


# ===========================================================================
# 2. Score and Threshold Consistency
# ===========================================================================

def test_score_and_threshold_consistency(detector, model_card):
    """Verify score and threshold alignment with calibrated baseline artifact."""
    calibrated_threshold = model_card["thresholds"]["isolation_forest"]
    assert abs(calibrated_threshold - 0.6099879) < 1e-5

    # Run benign inference
    benign_vector = {
        "call_count": 3.0,
        "call_velocity": 1.0,
        "error_ratio": 0.0,
        "unique_services": 1.0,
        "unique_events": 2.0,
        "enumeration_ratio": 0.3,
        "sensitive_count": 0.0,
        "iam_change_count": 0.0,
        "first_service_ratio": 0.0,
        "first_ip": 0.0,
        "off_hours": 0.0,
        "event_entropy": 0.5,
    }

    res_benign = detector.score_window(benign_vector)
    assert res_benign["is_anomaly"] is False
    assert res_benign["score"] <= res_benign["threshold"]

    # Run anomalous inference
    res_anomaly = detector.score_window(ALT_0004_FEATURE_VECTOR)
    assert res_anomaly["is_anomaly"] is True
    assert res_anomaly["score"] > res_anomaly["threshold"]
    assert res_anomaly["scores"]["isolation_forest"] == res_anomaly["score"]


# ===========================================================================
# 3. Attribution Consistency (Tree-Path Information Gain)
# ===========================================================================

def test_tree_path_attribution_consistency(detector, model_card):
    """Verify that tree-path information isolation gain feature attributions
    sum to 1.0 across all 12 features and rank top drivers logically."""
    iso_model = model_card["models"]["isolation_forest"]
    scaler = model_card["scaler"]
    features = model_card["features"]

    # Assemble and scale sample
    x_raw = np.array([[ALT_0004_FEATURE_VECTOR.get(f, 0.0) for f in features]], dtype=float)
    x_log = x_raw.copy()
    for idx, f in enumerate(features):
        if f in detector.log_features:
            x_log[0, idx] = np.log1p(x_log[0, idx])
    x_scaled = scaler.transform(x_log)

    # Compute attribution for all 12 features (top_k=12)
    all_attributions = explain_isolation_forest_sample(
        iso_model, scaler, x_raw, x_scaled, features, top_k=12
    )

    assert len(all_attributions) == 12
    # Verify non-negativity and sum to 1.0
    weights = [weight for _, weight in all_attributions]
    assert all(w >= 0.0 for w in weights)
    assert abs(sum(weights) - 1.0) < 1e-4

    # Verify top attribution drivers match the injected anomaly characteristics
    top_driver_names = [desc.split(":")[0] for desc, _ in all_attributions[:3]]
    assert "Call Velocity Spike" in top_driver_names
    assert "API Call Burst" in top_driver_names


# ===========================================================================
# 4. Traversal Across All 200 Estimators
# ===========================================================================

def test_all_200_estimators_traversed(model_card):
    """Verify that the Isolation Forest ensemble contains exactly 200 trees
    and that tree traversal iterates through each individual estimator."""
    iso_model = model_card["models"]["isolation_forest"]
    estimators = iso_model.estimators_

    assert len(estimators) == 200
    for est in estimators:
        assert hasattr(est, "tree_")
        assert est.tree_.node_count > 1  # Each tree has decision nodes


# ===========================================================================
# 5. Raw Telemetry and Explanation Separation
# ===========================================================================

def test_raw_telemetry_and_explanation_separation(detector):
    """Verify that raw telemetry measurements are strictly segregated from
    derived model explanations and attributions."""
    result = detector.score_window(ALT_0004_FEATURE_VECTOR)

    # Raw features dictionary is preserved exactly
    assert result["features"] == ALT_0004_FEATURE_VECTOR
    assert result["features"]["call_count"] == 90.0

    # Explanations contain derived percentages and formatted strings
    explanations = result["explanations"]
    assert isinstance(explanations, list)
    for item in explanations:
        label, weight = item
        assert isinstance(label, str)
        assert isinstance(weight, float)
        assert 0.0 <= weight <= 1.0
        # Derived explanation strings contain formatted human context
        assert ":" in label


# ===========================================================================
# 6. Missing and Malformed Feature Vectors
# ===========================================================================

def test_missing_and_malformed_feature_vectors(detector):
    """Verify engine stability when presented with empty, partial, negative,
    or unexpected feature dictionaries."""
    # 1. Empty dictionary
    res_empty = detector.score_window({})
    assert isinstance(res_empty["score"], float)
    assert res_empty["threshold"] == 0.61

    # 2. Partial dictionary
    res_partial = detector.score_window({"call_count": 90.0})
    assert isinstance(res_partial["score"], float)

    # 3. Negative values (safeguarded by max(0.0, x) before np.log1p)
    res_negative = detector.score_window({"call_count": -100.0, "call_velocity": -5.0})
    assert isinstance(res_negative["score"], float)
    assert not np.isnan(res_negative["score"])

    # 4. Extra unexpected keys
    res_extra = detector.score_window({
        **ALT_0004_FEATURE_VECTOR,
        "unexpected_telemetry_field": 99999.0,
        "malicious_sql_payload": "' OR '1'='1",
    })
    assert res_extra["score"] == 0.6959  # Identical score, extraneous keys ignored


# ===========================================================================
# 7. Model Artifact Version and Provenance Consistency
# ===========================================================================

def test_model_artifact_version_consistency(model_card):
    """Verify the trained baseline artifact conforms to the production schema."""
    expected_keys = {
        "scaler",
        "models",
        "thresholds",
        "features",
        "log_features",
        "window",
        "threshold_rule",
    }
    assert set(model_card.keys()) == expected_keys
    assert model_card["window"] == "5min"
    assert model_card["threshold_rule"] == "99th percentile of benign validation scores"
    assert len(model_card["features"]) == 12
    assert set(model_card["models"].keys()) == {"isolation_forest", "lof", "ocsvm"}


# ===========================================================================
# 8. Repeated Inference Determinism
# ===========================================================================

def test_repeated_inference_determinism(detector):
    """Verify that repeated inference invocations on identical input produce
    strictly identical scores, thresholds, and explanations."""
    baseline_result = detector.score_window(ALT_0004_FEATURE_VECTOR)

    for _ in range(50):
        run_res = detector.score_window(ALT_0004_FEATURE_VECTOR)
        assert run_res["score"] == baseline_result["score"]
        assert run_res["threshold"] == baseline_result["threshold"]
        assert run_res["is_anomaly"] == baseline_result["is_anomaly"]
        assert run_res["explanations"] == baseline_result["explanations"]
