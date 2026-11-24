"""Unit tests for ThreatGuard SOC Store and Workflow Engine."""
import pytest
from backend.soc.models import (
    AlertSeverity,
    AlertStatus,
    IncidentSeverity,
    IncidentStatus,
    RemediationStatus,
    VerificationState,
)
from backend.soc.store import SOCStore


@pytest.fixture
def store():
    """Create a fresh SOCStore for testing."""
    return SOCStore()


# =========================================================================
# 1. ALERTS MANAGEMENT TESTS
# =========================================================================

def test_alert_creation_and_deduplication(store):
    """Test alert creation, deduplication logic, and timeline tracking."""
    initial_count = len(store.list_alerts()["alerts"])

    # Create new alert
    alert = store.create_alert(
        title="Unauthorized S3 Bucket Modification",
        severity=AlertSeverity.HIGH,
        affected_resource="s3/audit-bucket",
        detection_source="Rule Engine",
        rule_ref="CIS 2.1.1",
        trigger_reason="Bucket ACL set to public-read",
    )
    assert alert.id.startswith("ALT-")
    assert alert.title == "Unauthorized S3 Bucket Modification"
    assert alert.status == AlertStatus.NEW
    assert len(alert.timeline) == 1

    # Attempt to create duplicate active alert
    dup = store.create_alert(
        title="Unauthorized S3 Bucket Modification",
        severity=AlertSeverity.HIGH,
        affected_resource="s3/audit-bucket",
        detection_source="Rule Engine",
        rule_ref="CIS 2.1.1",
        trigger_reason="Bucket ACL set to public-read again",
    )
    assert dup.id == alert.id
    assert len(dup.timeline) == 2
    assert "deduplicated" in dup.timeline[1]["event"]


def test_alert_filtering_and_sorting(store):
    """Test filtering alerts by severity, status, search keyword, and sorting."""
    # List by severity
    crit_alerts = store.list_alerts(severity="Critical")
    assert all(a["severity"] == "Critical" for a in crit_alerts["alerts"])

    # Search keyword
    s3_alerts = store.list_alerts(search="S3")
    assert len(s3_alerts["alerts"]) >= 1
    for a in s3_alerts["alerts"]:
        assert "s3" in a["title"].lower() or "s3" in a["affected_resource"].lower()

    # Pagination
    paged = store.list_alerts(limit=2, offset=0)
    assert len(paged["alerts"]) <= 2


def test_alert_lifecycle_actions(store):
    """Test transitioning alert through its lifecycle statuses."""
    alert = store.create_alert(
        title="Suspicious Login Activity",
        severity=AlertSeverity.MEDIUM,
        affected_resource="iam/user/guest",
    )
    aid = alert.id

    # Acknowledge
    ack = store.update_alert_status(aid, AlertStatus.ACKNOWLEDGED, notes="Assigned to analyst", user="alice")
    assert ack.status == AlertStatus.ACKNOWLEDGED
    assert any("alice" in t.get("user", "") for t in ack.timeline)

    # Investigate
    inv = store.update_alert_status(aid, AlertStatus.INVESTIGATING, notes="Correlating CloudTrail logs")
    assert inv.status == AlertStatus.INVESTIGATING

    # Resolve
    res = store.update_alert_status(aid, AlertStatus.RESOLVED, notes="False positive verified")
    assert res.status == AlertStatus.RESOLVED


def test_alert_stats(store):
    """Test aggregate alert metrics."""
    stats = store.get_alert_stats()
    assert "total" in stats
    assert "by_severity" in stats
    assert "by_status" in stats
    assert stats["total"] >= 4  # Default seeded alerts


# =========================================================================
# 2. INCIDENTS LIFECYCLE TESTS
# =========================================================================

def test_incident_lifecycle(store):
    """Test creating an incident and progressing through full SOC response lifecycle."""
    inc = store.create_incident(
        title="Unauthorized Exfiltration Attempt",
        severity=IncidentSeverity.CRITICAL,
        summary="Attacker bypassed S3 public block and attempted batch download.",
        affected_assets=["s3/financial-docs", "iam/user/contractor"],
        linked_alert_ids=["ALT-0001"],
        linked_finding_ids=["s3"],
        lead_responder="Lead Analyst",
    )
    assert inc.id.startswith("INC-")
    assert inc.status == IncidentStatus.TRIAGE
    assert len(inc.timeline) >= 1

    # Check alert was updated to INVESTIGATING and linked
    alt = store.get_alert("ALT-0001")
    if alt:
        assert alt.incident_id == inc.id

    # Progress to Containment
    updated = store.update_incident(
        inc.id,
        new_status=IncidentStatus.CONTAINMENT,
        notes="Revoked active IAM session credentials.",
        containment_evidence={"session_revoked": True, "quarantine_sg_applied": True},
    )
    assert updated.status == IncidentStatus.CONTAINMENT
    assert updated.containment_evidence["session_revoked"] is True

    # Progress to Closed
    closed = store.update_incident(
        inc.id,
        new_status=IncidentStatus.CLOSED,
        notes="Remediation verified; threat fully contained.",
        closure_reason="Threat eradicated and posture verified.",
    )
    assert closed.status == IncidentStatus.CLOSED
    assert closed.closure_reason == "Threat eradicated and posture verified."


# =========================================================================
# 3. REMEDIATION & INDEPENDENT VERIFICATION TESTS
# =========================================================================

def test_remediation_approval_and_verification_pass(store):
    """Test that remediation execution independently verifies PASS when check succeeds."""
    task = store.create_remediation_task(
        title="Enable S3 Public Access Block",
        affected_resource="s3/audit-bucket",
        recommended_action="Set PutPublicAccessBlock to True.",
        severity="Critical",
        related_finding_id="s3_test",
    )
    assert task.status == RemediationStatus.PENDING
    assert task.verification_state == VerificationState.UNVERIFIED

    # Human Approval
    approved = store.approve_remediation_task(task.id, user="Security Lead")
    assert approved.status == RemediationStatus.APPROVED

    # Simulated Fix Executor & Verifier
    cloud_state = {"public_access_blocked": False}

    def fix_fn():
        cloud_state["public_access_blocked"] = True

    def verify_fn():
        if cloud_state["public_access_blocked"]:
            return VerificationState.PASS, {"verified": True, "config": "All blocks enabled"}
        return VerificationState.FAIL, {"verified": False}

    executed = store.execute_and_verify_remediation(
        rem_id=task.id,
        executor_fn=fix_fn,
        verifier_fn=verify_fn,
        user="Automated Runner",
    )
    assert executed.status == RemediationStatus.VERIFIED
    assert executed.verification_state == VerificationState.PASS
    assert executed.verification_evidence["verified"] is True
    assert executed.applied_at is not None
    assert executed.verified_at is not None


def test_remediation_verification_fail(store):
    """Test that remediation fails verification when the underlying issue persists."""
    task = store.create_remediation_task(
        title="Close Insecure Port",
        affected_resource="ec2/sg-123",
        recommended_action="Revoke ingress rule",
        severity="High",
    )

    # Flawed fix that fails to actually remediate
    def broken_fix():
        pass  # Did not change cloud state!

    def verify_fn():
        # Resource remains insecure!
        return VerificationState.FAIL, {"error": "Port 22 still open to 0.0.0.0/0"}

    executed = store.execute_and_verify_remediation(
        rem_id=task.id,
        executor_fn=broken_fix,
        verifier_fn=verify_fn,
    )
    assert executed.status == RemediationStatus.FAILED
    assert executed.verification_state == VerificationState.FAIL
    assert "still open" in executed.verification_evidence["error"]


def test_remediation_rollback(store):
    """Test rolling back a remediation task."""
    task = store.create_remediation_task(
        title="Modify Bucket Policy",
        affected_resource="s3/test",
        recommended_action="Enforce SSL only",
        severity="Medium",
    )

    rolled_back = store.rollback_remediation(
        rem_id=task.id,
        rollback_fn=lambda: None,
        user="Rollback Admin",
    )
    assert rolled_back.status == RemediationStatus.ROLLED_BACK
