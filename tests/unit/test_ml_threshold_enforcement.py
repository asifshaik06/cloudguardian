"""Unit tests for ML Anomaly Threshold Enforcement.

Verifies:
1. Strict decision threshold comparison (score > threshold).
2. Scores below or equal to threshold do not create ML alerts.
3. Scores exceeding threshold create valid ML alerts.
4. Missing or invalid ML anomaly score rejects alert creation.
5. Dynamic threshold loading and configuration.
6. Rule-based security findings remain 100% independent of ML threshold gating.
7. Alert lifecycle and deduplication behavior.
"""
import pytest

from backend.soc.models import AlertRecord, AlertSeverity, AlertStatus
from backend.soc.store import SOCStore


@pytest.fixture
def store():
    return SOCStore()


def test_score_below_threshold_suppresses_ml_alert(store):
    """Verify an ML event with score below 0.610 is suppressed and returns None."""
    alert = store.create_alert(
        title="Benign Behavioral Jitter",
        severity=AlertSeverity.MEDIUM,
        affected_resource="iam/user/intern-dev",
        detection_source="ML Anomaly Detector (Isolation Forest)",
        category="Credential Abuse",
        rule_ref="ML Anomaly / T1078.004",
        ml_anomaly_score=0.585,
        ml_explanation={"threshold": 0.610},
    )
    assert alert is None
    # Verify no active alert was stored
    alerts = store.list_alerts()
    assert not any(a.title == "Benign Behavioral Jitter" for a in alerts)


def test_score_equal_to_threshold_suppresses_ml_alert(store):
    """Verify an ML event with score exactly equal to threshold is suppressed."""
    alert = store.create_alert(
        title="Boundary Event",
        severity=AlertSeverity.HIGH,
        affected_resource="iam/user/intern-dev",
        detection_source="ML Anomaly Detector",
        rule_ref="ML Anomaly",
        ml_anomaly_score=0.610,
        ml_explanation={"threshold": 0.610},
    )
    assert alert is None


def test_score_above_threshold_creates_ml_alert(store):
    """Verify an ML event with score strictly above threshold creates an active alert."""
    alert = store.create_alert(
        title="Anomalous IAM Access-Key Behavior Detected",
        severity=AlertSeverity.HIGH,
        affected_resource="iam/user/analyst-attacker/access-key",
        detection_source="ML Anomaly Detector (Isolation Forest)",
        category="Credential Abuse",
        rule_ref="ML Anomaly / MITRE T1078.004",
        risk_score=88,
        ml_anomaly_score=0.696,
        ml_explanation={
            "threshold": 0.610,
            "anomaly_delta": "+0.086 above baseline",
            "top_features": [["Call Velocity Spike", 0.45]],
        },
    )
    assert alert is not None
    assert isinstance(alert, AlertRecord)
    assert alert.ml_anomaly_score == 0.696
    assert alert.status == AlertStatus.NEW


def test_missing_or_invalid_score_rejects_ml_alert(store):
    """Verify ML anomaly alert creation without a valid score is rejected."""
    # Missing score (None)
    alert_none = store.create_alert(
        title="Unverified Anomaly",
        severity=AlertSeverity.HIGH,
        affected_resource="iam/user/intern-dev",
        detection_source="ML Anomaly Detector",
        rule_ref="ML Anomaly",
        ml_anomaly_score=None,
    )
    assert alert_none is None


def test_dynamic_threshold_configuration(store):
    """Verify that a customized or calibrated threshold is respected."""
    # Test with custom high threshold of 0.750: score 0.720 should be suppressed
    alert_suppressed = store.create_alert(
        title="Elevated Behavior",
        severity=AlertSeverity.HIGH,
        affected_resource="iam/user/intern-dev",
        detection_source="ML Anomaly Detector",
        rule_ref="ML Anomaly",
        ml_anomaly_score=0.720,
        ml_explanation={"threshold": 0.750},
    )
    assert alert_suppressed is None

    # Score 0.780 exceeds 0.750 threshold -> created
    alert_created = store.create_alert(
        title="Extreme Burst",
        severity=AlertSeverity.CRITICAL,
        affected_resource="iam/user/intern-dev",
        detection_source="ML Anomaly Detector",
        rule_ref="ML Anomaly",
        ml_anomaly_score=0.780,
        ml_explanation={"threshold": 0.750},
    )
    assert alert_created is not None
    assert alert_created.ml_anomaly_score == 0.780


def test_rule_based_alerts_independent_of_ml_threshold(store):
    """Verify rule-based security alerts are never blocked or gated by ML thresholds."""
    # Rule engine alert with no ML score
    cis_alert = store.create_alert(
        title="S3 Bucket Public Access Enabled",
        severity=AlertSeverity.CRITICAL,
        affected_resource="s3/student-records-demo",
        detection_source="Rule Engine (CIS)",
        rule_ref="CIS 2.1.1",
        trigger_reason="Public access block configuration disabled.",
    )
    assert cis_alert is not None
    assert cis_alert.title == "S3 Bucket Public Access Enabled"
    assert cis_alert.ml_anomaly_score is None

    # Security Group rule alert
    sg_alert = store.create_alert(
        title="Security Group Allows Unrestricted Ingress (0.0.0.0/0)",
        severity=AlertSeverity.HIGH,
        affected_resource="ec2/sg-12345",
        detection_source="Rule Engine (CIS)",
        rule_ref="CIS 4.1",
    )
    assert sg_alert is not None


def test_alert_lifecycle_and_deduplication(store):
    """Verify deduplication updates the existing alert's timeline without duplicating records."""
    alert1 = store.create_alert(
        title="S3 Public Exposure",
        severity=AlertSeverity.HIGH,
        affected_resource="s3/test-bucket",
        detection_source="Rule Engine (CIS)",
        rule_ref="CIS 2.1.1",
    )
    initial_count = len(store.list_alerts())

    # Duplicate alert for same resource and rule within active state
    alert2 = store.create_alert(
        title="S3 Public Exposure",
        severity=AlertSeverity.HIGH,
        affected_resource="s3/test-bucket",
        detection_source="Rule Engine (CIS)",
        rule_ref="CIS 2.1.1",
    )
    assert alert1.id == alert2.id
    assert len(store.list_alerts()) == initial_count
    assert len(alert2.timeline) >= 2
    assert "deduplicated" in alert2.timeline[-1]["event"].lower()
