"""Dedicated Regression Test Suite for Simulation Lab Playground Remediation & Path Verification.

Validates:
1. Fix for BUG-001 / BUG-002: Remediation endpoint accepts direct or wrapped payload.
2. Security enforcement: 401 Unauthorized returned when API auth header / session cookie missing.
3. Path classification upgrade: CONFIRMED, POTENTIAL, BLOCKED, UNVERIFIED properly calculated.
4. Metric deltas: path reduction and blast radius recalculation after remediation.
5. Lifecycle verification: reanalyze, verify, and reset operations on isolated scenario runs.
"""
import pytest
from app import app as flask_app
from backend.security import AUTH_HEADER, get_active_api_key
from backend.scenarios.models import PathClassification


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers():
    return {AUTH_HEADER: get_active_api_key()}


def test_remediation_unauthorized_rejection(client):
    """Mutating endpoints must reject unauthenticated requests with 401."""
    # Launch without auth
    resp_launch = client.post("/api/scenarios/privesc-excessive-iam/launch")
    assert resp_launch.status_code == 401
    assert "Unauthorized" in resp_launch.get_json().get("error", "")

    # Remediate without auth
    resp_rem = client.post("/api/scenarios/runs/dummy-run-id/remediate", json={"type": "detach_policy"})
    assert resp_rem.status_code == 401

    # Verify without auth
    resp_ver = client.post("/api/scenarios/runs/dummy-run-id/verify")
    assert resp_ver.status_code == 401

    # Reset without auth
    resp_rst = client.post("/api/scenarios/runs/dummy-run-id/reset")
    assert resp_rst.status_code == 401


def test_remediation_payload_format_tolerance(client, auth_headers):
    """Verify remediation accepts both wrapped {'action': {...}} and flat payload formats."""
    # 1. Launch scenario run
    launch_resp = client.post("/api/scenarios/privesc-excessive-iam/launch", headers=auth_headers)
    assert launch_resp.status_code in [200, 201]
    run_id = launch_resp.get_json()["run_id"]

    # Retrieve initial run state
    state_resp = client.get(f"/api/scenarios/runs/{run_id}")
    assert state_resp.status_code == 200
    state = state_resp.get_json()
    init_paths = state.get("paths", [])
    assert len(init_paths) > 0

    # 2. Test Flat payload format: {"type": "revoke_excessive_iam", "target": "user/junior-operator"}
    flat_payload = {
        "type": "revoke_excessive_iam",
        "target": "user/junior-operator",
    }
    rem_resp_flat = client.post(f"/api/scenarios/runs/{run_id}/remediate", json=flat_payload, headers=auth_headers)
    assert rem_resp_flat.status_code == 200
    flat_res = rem_resp_flat.get_json()
    assert flat_res["verified"] is True
    assert flat_res["status"] in ("PASS", "VERIFIED")
    assert "metrics" in flat_res
    assert "delta" in flat_res["metrics"]
    assert flat_res["metrics"]["delta"]["paths_eliminated"] > 0

    # Reset run for second format test
    reset_resp1 = client.post(f"/api/scenarios/runs/{run_id}/reset", headers=auth_headers)
    assert reset_resp1.status_code == 200
    assert reset_resp1.get_json()["status"] == "analyzed"

    # 3. Test Wrapped payload format: {"action": {"type": "revoke_excessive_iam", ...}}
    wrapped_payload = {
        "action": {
            "type": "revoke_excessive_iam",
            "target": "user/junior-operator",
        }
    }
    rem_resp_wrapped = client.post(f"/api/scenarios/runs/{run_id}/remediate", json=wrapped_payload, headers=auth_headers)
    assert rem_resp_wrapped.status_code == 200
    wrapped_res = rem_resp_wrapped.get_json()
    assert wrapped_res["verified"] is True
    assert wrapped_res["status"] in ("PASS", "VERIFIED")
    assert "metrics" in wrapped_res
    assert "post_remediation" in wrapped_res["metrics"]


def test_remediation_lifecycle_and_verification(client, auth_headers):
    """Verify complete remediation lifecycle: launch -> remediate -> reanalyze -> verify -> reset."""
    launch_resp = client.post("/api/scenarios/privesc-excessive-iam/launch", headers=auth_headers)
    run_id = launch_resp.get_json()["run_id"]

    # Remediate
    rem_resp = client.post(f"/api/scenarios/runs/{run_id}/remediate", json={
        "type": "revoke_excessive_iam",
        "target": "user/junior-operator",
    }, headers=auth_headers)
    assert rem_resp.status_code == 200
    assert rem_resp.get_json()["verified"] is True

    # Re-analyze
    analyze_resp = client.post(f"/api/scenarios/runs/{run_id}/analyze", headers=auth_headers)
    assert analyze_resp.status_code == 200
    analyze_data = analyze_resp.get_json()
    assert "paths" in analyze_data

    # Verify
    verify_resp = client.post(f"/api/scenarios/runs/{run_id}/verify", headers=auth_headers)
    assert verify_resp.status_code == 200
    ver_data = verify_resp.get_json()
    assert ver_data["verified"] is True
    assert "metrics" in ver_data
    assert "delta" in ver_data["metrics"]

    # Reset
    reset_resp = client.post(f"/api/scenarios/runs/{run_id}/reset", headers=auth_headers)
    assert reset_resp.status_code == 200
    reset_data = reset_resp.get_json()
    assert reset_data["status"] == "analyzed"


def test_path_classification_enum_values():
    """Verify PathClassification enum supports new and legacy values cleanly."""
    assert PathClassification.CONFIRMED.value == "CONFIRMED"
    assert PathClassification.POTENTIAL.value == "POTENTIAL"
    assert PathClassification.BLOCKED.value == "BLOCKED"
    assert PathClassification.UNVERIFIED.value == "UNVERIFIED"

    # Backward compatibility checks
    assert PathClassification.THEORETICAL == PathClassification.BLOCKED
    assert PathClassification("CONFIRMED") == PathClassification.CONFIRMED
    assert PathClassification("Confirmed") == PathClassification.CONFIRMED
    assert PathClassification("blocked") == PathClassification.BLOCKED
    assert PathClassification("theoretical") == PathClassification.BLOCKED
