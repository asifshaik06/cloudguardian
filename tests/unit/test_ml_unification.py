"""Unit tests for Phase 2 ML Engine and XAI:
- Streaming 5-minute rolling window feature aggregator
- Cold-start history management
- Multi-detector runtime inference with baseline_v1.joblib
- TreeSHAP decision tree feature attribution
"""
from datetime import datetime, timezone
import pytest
import numpy as np

from backend.ml_engine.detector import RuntimeDetector
from backend.ml_engine.window_aggregator import StreamingWindowAggregator
from backend.ml_engine.xai import explain_isolation_forest_sample, explain_zscore_sample


def test_streaming_window_aggregator_features():
    agg = StreamingWindowAggregator(window_minutes=5)
    t0 = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)

    # Ingest 5 benign S3 read events
    for i in range(5):
        features, rolled = agg.add_event(
            principal="user-dev",
            event_name="GetObject",
            service="s3",
            event_time=t0,
            source_ip="10.0.0.5",
            error=False,
        )

    assert features["call_count"] == 5.0
    assert features["enumeration_ratio"] == 1.0  # GetObject is in READ
    assert features["error_ratio"] == 0.0
    assert features["unique_services"] == 1.0
    assert features["sensitive_count"] == 0.0


def test_streaming_window_sensitive_and_errors():
    agg = StreamingWindowAggregator(window_minutes=5)
    t0 = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)

    # Ingest IAM sensitive changes with errors
    agg.add_event("attacker", "CreateUser", "iam", event_time=t0, error=True)
    agg.add_event("attacker", "AttachUserPolicy", "iam", event_time=t0, error=False)
    agg.add_event("attacker", "CreateAccessKey", "iam", event_time=t0, error=True)

    feat = agg.get_current_features("attacker")
    assert feat["call_count"] == 3.0
    assert feat["sensitive_count"] == 3.0
    assert feat["iam_change_count"] == 3.0
    assert round(feat["error_ratio"], 2) == 0.67


def test_streaming_window_cold_start_neutrality():
    """Verify that during cold start (< 3 previous windows), history features
    remain neutral (call_velocity=1.0, first_service_ratio=0.0)."""
    agg = StreamingWindowAggregator(window_minutes=5)

    # Window 1
    t1 = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)
    feat1, _ = agg.add_event("newbie", "DescribeInstances", "ec2", event_time=t1)
    assert feat1["call_velocity"] == 1.0
    assert feat1["first_service_ratio"] == 0.0

    # Window 2 (10 minutes later)
    t2 = datetime(2026, 11, 14, 10, 10, 0, tzinfo=timezone.utc)
    feat2, rolled = agg.add_event("newbie", "GetObject", "s3", event_time=t2)
    assert rolled is True
    assert feat2["call_velocity"] == 1.0  # Still cold start (only 1 previous window)

    # Window 3 (20 minutes later)
    t3 = datetime(2026, 11, 14, 10, 20, 0, tzinfo=timezone.utc)
    agg.add_event("newbie", "GetObject", "s3", event_time=t3)

    # Window 4 (30 minutes later) -> Warm!
    t4 = datetime(2026, 11, 14, 10, 30, 0, tzinfo=timezone.utc)
    for _ in range(10):
        feat4, _ = agg.add_event("newbie", "PutObject", "s3", event_time=t4)

    # Now warm features activate
    assert feat4["call_velocity"] > 1.0


def test_runtime_detector_inference():
    detector = RuntimeDetector("models/baseline_v1.joblib")

    # Benign-looking feature vector
    benign_feat = {
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
    benign_res = detector.score_window(benign_feat)
    assert "isolation_forest" in benign_res["scores"]
    assert "zscore" in benign_res["scores"]
    assert benign_res["is_anomaly"] is False

    # Extreme attack feature vector (high velocity, new IP, off hours, sensitive calls, high errors)
    attack_feat = {
        "call_count": 150.0,
        "call_velocity": 25.0,
        "error_ratio": 0.8,
        "unique_services": 5.0,
        "unique_events": 12.0,
        "enumeration_ratio": 0.9,
        "sensitive_count": 8.0,
        "iam_change_count": 5.0,
        "first_service_ratio": 0.8,
        "first_ip": 1.0,
        "off_hours": 1.0,
        "event_entropy": 2.8,
    }
    attack_res = detector.score_window(attack_feat)
    assert attack_res["is_anomaly"] is True
    assert len(attack_res["explanations"]) > 0


def test_treeshap_feature_attribution():
    detector = RuntimeDetector("models/baseline_v1.joblib")
    iso_model = detector.models["isolation_forest"]
    scaler = detector.scaler

    x_raw = np.array([[120.0, 15.0, 0.6, 4.0, 8.0, 0.9, 6.0, 4.0, 0.5, 1.0, 1.0, 2.5]])
    x_log = x_raw.copy()
    for idx, f in enumerate(detector.features):
        if f in detector.log_features:
            x_log[0, idx] = np.log1p(x_log[0, idx])
    x_scaled = scaler.transform(x_log)

    explanations = explain_isolation_forest_sample(
        iso_model, scaler, x_raw, x_scaled, detector.features, top_k=5
    )

    assert len(explanations) == 5
    # Verify each explanation has [desc, weight]
    weights_sum = sum(e[1] for e in explanations)
    assert weights_sum > 0.0
    for desc, weight in explanations:
        assert isinstance(desc, str)
        assert weight >= 0.0
