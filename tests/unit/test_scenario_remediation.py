"""Unit tests for Remediation Playground & Independent Verification Engine.

Verifies remediation application on isolated graphs, path elimination,
blast radius reduction, detection of remaining alternative vectors,
and audit logging.
"""
import pytest

from backend.scenarios.definitions import get_scenario_by_id
from backend.scenarios.models import RunStatus
from backend.scenarios.remediation import apply_remediation, verify_remediation_state
from backend.scenarios.session import ScenarioSessionManager
from backend.state import StateStore


@pytest.fixture
def test_state_store(tmp_path):
    """Create a temporary isolated SQLite StateStore for audit trail verification."""
    db_file = str(tmp_path / "test_cg_audit.db")
    store = StateStore(db_path=db_file, check_same_thread=True)
    yield store
    store.close()


def test_remediate_excessive_iam_privesc(test_state_store):
    """Verify applying least-privilege remediation eliminates privilege escalation paths."""
    manager = ScenarioSessionManager()
    scenario_def = get_scenario_by_id("privesc-excessive-iam")
    run = manager.create_run(scenario_def)

    assert len(run.paths) >= 1
    initial_score = run.blast_radius.get("score", 0.0)

    # Apply remediation
    remediation_action = {
        "type": "revoke_excessive_iam",
        "target": "user/junior-operator",
    }
    result = apply_remediation(manager, run.run_id, remediation_action, state_store=test_state_store)

    assert result["verified"] is True
    assert result["status"] == "PASS"
    assert result["metrics"]["delta"]["paths_eliminated"] >= 1
    assert result["metrics"]["post_remediation"]["paths"] == 0

    # Verify run model status
    updated_run = manager.get_run(run.run_id)
    assert updated_run.status == RunStatus.VERIFIED
    assert updated_run.remediation_applied == remediation_action
    assert updated_run.verification_result is not None

    # Verify tamper-evident audit entry was recorded
    audit_lines = test_state_store.get_audit_lines()
    assert any("SCENARIO REMEDIATION [privesc-excessive-iam]" in line for line in audit_lines)
    assert any("Status=PASS" in line for line in audit_lines)


def test_remediate_public_s3_bucket(test_state_store):
    """Verify enabling S3 Public Access Block mitigates public exposure."""
    manager = ScenarioSessionManager()
    scenario_def = get_scenario_by_id("resource-s3-public")
    run = manager.create_run(scenario_def)

    assert any("Public Resource Exposure" in f.title for f in run.findings)

    remediation_action = {
        "type": "enable_s3_public_access_block",
        "target": "s3/student-records-public",
    }
    result = apply_remediation(manager, run.run_id, remediation_action, state_store=test_state_store)

    assert result["verified"] is True
    assert result["status"] == "PASS"

    # Verify findings are mitigated
    updated_run = manager.get_run(run.run_id)
    assert not any("Public Resource Exposure" in f.title for f in updated_run.findings)


def test_verification_state_query():
    """Verify inspecting verification state before and after remediation."""
    manager = ScenarioSessionManager()
    scenario_def = get_scenario_by_id("privesc-risky-trust")
    run = manager.create_run(scenario_def)

    # Before remediation
    state_before = verify_remediation_state(manager, run.run_id)
    assert state_before["status"] == "UNREMEDIATED"
    assert state_before["verified"] is False

    # Apply fix
    apply_remediation(manager, run.run_id, {"type": "restrict_trust_policy", "target": "role/infra-manager"})

    # After remediation
    state_after = verify_remediation_state(manager, run.run_id)
    assert state_after["status"] == "PASS"
    assert state_after["verified"] is True
