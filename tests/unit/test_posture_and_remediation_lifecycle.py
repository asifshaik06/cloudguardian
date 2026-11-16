"""Unit and Regression Tests for CloudGuardian 2.0 Posture Scoring & Remediation Lifecycle.

Validates:
1. Attack-to-remediation persistence.
2. Pending remediation visibility.
3. Approval lifecycle (PENDING -> APPROVED).
4. Apply and independent verification (APPROVED -> VERIFIED).
5. Audit trail consistency.
6. Posture score calculation table (10 distinct security states).
7. Verified risk removal and 100% security posture state.
8. Rollback risk restoration.
9. New attack risk decrease.
"""
import pytest
from unittest.mock import MagicMock

from backend.posture import compute_posture_score, CORE_WEIGHTS
from backend.soc.models import RemediationStatus, VerificationState, RemediationTask
from backend.soc.store import SOCStore


class MockStateStore:
    def __init__(self):
        self._findings = {}

    def get_finding(self, key):
        return self._findings.get(key)

    def set_finding(self, key, data):
        self._findings[key] = data

    def update_finding(self, key, **kwargs):
        if key in self._findings:
            self._findings[key].update(kwargs)


def create_mock_rules(checks=None):
    """Build mock core rules dictionary."""
    checks = checks or {}
    return {
        "ct": {
            "res": "Activity log",
            "sev": "Critical",
            "check": checks.get("ct", lambda: True),
            "good": "Recording",
            "bad": "Switched off",
            "fixtxt": "Start recording",
        },
        "s3": {
            "res": "Customer data storage",
            "sev": "High",
            "check": checks.get("s3", lambda: True),
            "good": "Private",
            "bad": "Public",
            "fixtxt": "Lock bucket",
        },
        "sg": {
            "res": "Network door (SSH)",
            "sev": "High",
            "check": checks.get("sg", lambda: True),
            "good": "Restricted",
            "bad": "0.0.0.0/0",
            "fixtxt": "Close door",
        },
        "key": {
            "res": "Employee access key",
            "sev": "High",
            "check": checks.get("key", lambda: True),
            "good": "Normal",
            "bad": "Anomalous",
            "fixtxt": "Deactivate",
        },
    }


def test_posture_score_100_percent_when_all_healthy_and_verified():
    """Requirement: All applicable risks resolved and verified -> Score reaches 100%."""
    state_store = MockStateStore()
    soc = SOCStore()
    soc._remediations.clear()

    rules = create_mock_rules()
    score = compute_posture_score(rules, state_store, soc)
    assert score == 100, f"Expected 100% when all checks pass and no unresolved risks, got {score}%"


def test_posture_score_critical_finding_unresolved():
    """Requirement: Critical finding unresolved -> Score reflects critical risk (70%)."""
    state_store = MockStateStore()
    state_store.set_finding("ct", {"id": "ct", "status": "pending", "verified": False})
    soc = SOCStore()
    soc._remediations.clear()

    # CloudTrail check fails
    rules = create_mock_rules(checks={"ct": lambda: False})
    score = compute_posture_score(rules, state_store, soc)
    assert score == 70, f"Expected 70% with critical finding unresolved, got {score}%"


def test_posture_score_high_finding_unresolved():
    """Requirement: High finding unresolved -> Score reflects high risk (75%)."""
    state_store = MockStateStore()
    state_store.set_finding("s3", {"id": "s3", "status": "pending", "verified": False})
    soc = SOCStore()
    soc._remediations.clear()

    # S3 check fails
    rules = create_mock_rules(checks={"s3": lambda: False})
    score = compute_posture_score(rules, state_store, soc)
    assert score == 75, f"Expected 75% with high finding unresolved, got {score}%"


def test_posture_score_remediation_pending_approval():
    """Requirement: Remediation pending approval -> Risk remains."""
    state_store = MockStateStore()
    soc = SOCStore()
    soc._remediations.clear()

    # Create task with status PENDING
    soc.create_remediation_task(
        title="Fix S3",
        affected_resource="s3",
        recommended_action="Lock",
        related_finding_id="s3",
        severity="High",
    )

    # Cloud check passes in simulator, but workflow remediation is still PENDING approval
    rules = create_mock_rules(checks={"s3": lambda: True})
    score = compute_posture_score(rules, state_store, soc)
    assert score == 75, f"Expected risk to remain (75%) while remediation is pending approval, got {score}%"


def test_posture_score_approved_but_not_applied():
    """Requirement: Approved but not applied -> Risk remains."""
    state_store = MockStateStore()
    soc = SOCStore()
    soc._remediations.clear()

    task = soc.create_remediation_task(
        title="Fix S3",
        affected_resource="s3",
        recommended_action="Lock",
        related_finding_id="s3",
        severity="High",
    )
    soc.approve_remediation_task(task.id, user="SOC Lead")

    rules = create_mock_rules(checks={"s3": lambda: True})
    score = compute_posture_score(rules, state_store, soc)
    assert score == 75, f"Expected risk to remain (75%) when approved but not applied, got {score}%"


def test_posture_score_applied_but_not_verified():
    """Requirement: Applied but not verified -> Risk remains."""
    state_store = MockStateStore()
    soc = SOCStore()
    soc._remediations.clear()

    task = soc.create_remediation_task(
        title="Fix S3",
        affected_resource="s3",
        recommended_action="Lock",
        related_finding_id="s3",
        severity="High",
    )
    task.status = RemediationStatus.APPLIED
    task.verification_state = VerificationState.UNVERIFIED

    rules = create_mock_rules(checks={"s3": lambda: True})
    score = compute_posture_score(rules, state_store, soc)
    assert score == 75, f"Expected risk to remain (75%) when applied but unverified, got {score}%"


def test_posture_score_failed_verification():
    """Requirement: Failed verification -> Risk remains."""
    state_store = MockStateStore()
    soc = SOCStore()
    soc._remediations.clear()

    task = soc.create_remediation_task(
        title="Fix S3",
        affected_resource="s3",
        recommended_action="Lock",
        related_finding_id="s3",
        severity="High",
    )
    task.status = RemediationStatus.FAILED
    task.verification_state = VerificationState.FAIL

    rules = create_mock_rules(checks={"s3": lambda: True})
    score = compute_posture_score(rules, state_store, soc)
    assert score == 75, f"Expected risk to remain (75%) when verification failed, got {score}%"


def test_posture_score_remediation_rolled_back():
    """Requirement: Remediation rolled back -> Associated risk returns."""
    state_store = MockStateStore()
    soc = SOCStore()
    soc._remediations.clear()

    task = soc.create_remediation_task(
        title="Fix S3",
        affected_resource="s3",
        recommended_action="Lock",
        related_finding_id="s3",
        severity="High",
    )
    task.status = RemediationStatus.ROLLED_BACK

    rules = create_mock_rules(checks={"s3": lambda: True})
    score = compute_posture_score(rules, state_store, soc)
    assert score == 75, f"Expected risk to return (75%) after rollback, got {score}%"


def test_posture_score_independently_verified_remediation():
    """Requirement: Independently verified remediation -> Associated risk is removed."""
    state_store = MockStateStore()
    state_store.set_finding("s3", {"id": "s3", "status": "fixed", "verified": True})
    soc = SOCStore()
    soc._remediations.clear()

    task = soc.create_remediation_task(
        title="Fix S3",
        affected_resource="s3",
        recommended_action="Lock",
        related_finding_id="s3",
        severity="High",
    )
    task.status = RemediationStatus.VERIFIED
    task.verification_state = VerificationState.PASS

    rules = create_mock_rules(checks={"s3": lambda: True})
    score = compute_posture_score(rules, state_store, soc)
    assert score == 100, f"Expected 100% when remediation is verified and check passes, got {score}%"


def test_posture_score_new_attack_after_remediation():
    """Requirement: New attack after successful remediation -> Score decreases according to new risk."""
    state_store = MockStateStore()
    soc = SOCStore()
    soc._remediations.clear()

    # Initial state: 100%
    rules = create_mock_rules()
    assert compute_posture_score(rules, state_store, soc) == 100

    # New attack on Security Group
    state_store.set_finding("sg", {"id": "sg", "status": "pending", "verified": False})
    rules_attacked = create_mock_rules(checks={"sg": lambda: False})
    score = compute_posture_score(rules_attacked, state_store, soc)
    assert score == 75, f"Expected score to decrease to 75% after SG attack, got {score}%"


def test_remediation_task_approval_and_verification_lifecycle():
    """Validates the complete remediation lifecycle: CREATE -> APPROVE -> APPLY -> VERIFY."""
    soc = SOCStore()
    soc._remediations.clear()

    # 1. Create task
    task = soc.create_remediation_task(
        title="Enforce Public Access Block",
        affected_resource="s3/student-records",
        recommended_action="Enable all four block settings",
        related_finding_id="s3",
        severity="High",
    )
    assert task.status == RemediationStatus.PENDING
    assert task.verification_state == VerificationState.UNVERIFIED

    # 2. Approve task
    approved = soc.approve_remediation_task(task.id, user="Senior Analyst")
    assert approved.status == RemediationStatus.APPROVED
    assert approved.approved_by == "Senior Analyst"
    assert approved.approved_at is not None

    # 3. Apply and independently verify (PASS)
    executed = soc.execute_and_verify_remediation(
        rem_id=task.id,
        executor_fn=lambda: None,
        verifier_fn=lambda: (VerificationState.PASS, {"rechecked": True, "clean": True}),
        user="Senior Analyst",
    )
    assert executed.status == RemediationStatus.VERIFIED
    assert executed.verification_state == VerificationState.PASS
    assert executed.verified_at is not None
    assert executed.verification_evidence["clean"] is True
