"""Integration tests for Scenario Simulation Lab REST API endpoints.

Covers all 10 Part H endpoints:
1. GET /api/scenarios (catalog list & filters)
2. GET /api/scenarios/<id> (details & 404 handling)
3. POST /api/scenarios/<id>/launch (launch run)
4. GET /api/scenarios/runs/<run_id> (run state & ECharts graph)
5. POST /api/scenarios/runs/<run_id>/analyze (deep re-analysis)
6. POST /api/scenarios/runs/<run_id>/remediate (simulated fix application)
7. POST /api/scenarios/runs/<run_id>/verify (post-remediation verification)
8. POST /api/scenarios/runs/<run_id>/reset (state rollback)
9. POST /api/scenarios/custom (dynamic scenario builder)
10. POST /api/scenarios/validate-policy (policy syntax & condition validation)
"""
import pytest
from app import app as flask_app
from backend.security import AUTH_HEADER, get_active_api_key


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers():
    return {AUTH_HEADER: get_active_api_key()}


# 1. GET /api/scenarios
def test_get_scenarios_catalog(client):
    """Verify listing all predefined scenarios and applying category filters."""
    resp = client.get("/api/scenarios")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["total"] == 12
    assert len(data["scenarios"]) == 12

    # Filter by category
    resp_filter = client.get("/api/scenarios?category=Privilege+Escalation")
    assert resp_filter.status_code == 200
    filter_data = resp_filter.get_json()
    assert filter_data["total"] == 4
    for s in filter_data["scenarios"]:
        assert s["category"] == "Privilege Escalation"


# 2. GET /api/scenarios/<id>
def test_get_scenario_details(client):
    """Verify retrieving scenario details by ID and 404 for unknown IDs."""
    resp = client.get("/api/scenarios/privesc-excessive-iam")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["id"] == "privesc-excessive-iam"
    assert "Excessive IAM Permissions" in data["name"]
    assert len(data["identities"]) >= 1
    assert len(data["resources"]) >= 1

    # 404 check
    resp_404 = client.get("/api/scenarios/non-existent-scenario")
    assert resp_404.status_code == 404


# 3. POST /api/scenarios/<id>/launch
def test_launch_scenario(client, auth_headers):
    """Verify launching an isolated scenario simulation run."""
    resp = client.post("/api/scenarios/privesc-risky-trust/launch", headers=auth_headers)
    assert resp.status_code == 201
    data = resp.get_json()

    assert "run_id" in data
    assert data["scenario_id"] == "privesc-risky-trust"
    assert data["status"] in ("initialized", "analyzed")
    assert data["paths_count"] >= 1


# 4. GET /api/scenarios/runs/<run_id>
def test_get_run_state_and_graph(client, auth_headers):
    """Verify fetching run state and ECharts graph topology."""
    # First launch
    launch_resp = client.post("/api/scenarios/privesc-excessive-iam/launch", headers=auth_headers)
    run_id = launch_resp.get_json()["run_id"]

    resp = client.get(f"/api/scenarios/runs/{run_id}")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["run_id"] == run_id
    assert "graph" in data
    assert "nodes" in data["graph"]
    assert "links" in data["graph"]
    assert len(data["findings"]) >= 1


# 5. POST /api/scenarios/runs/<run_id>/analyze
def test_reanalyze_run(client, auth_headers):
    """Verify triggering deep re-analysis of a scenario run."""
    launch_resp = client.post("/api/scenarios/privesc-excessive-iam/launch", headers=auth_headers)
    run_id = launch_resp.get_json()["run_id"]

    resp = client.post(f"/api/scenarios/runs/{run_id}/analyze", headers=auth_headers, json={"context": {"mfa_present": True}})
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["run_id"] == run_id
    assert "findings" in data
    assert "paths" in data
    assert "blast_radius" in data


# 6. POST /api/scenarios/runs/<run_id>/remediate
def test_remediate_run(client, auth_headers):
    """Verify applying a simulated remediation action to an active run."""
    launch_resp = client.post("/api/scenarios/privesc-excessive-iam/launch", headers=auth_headers)
    run_id = launch_resp.get_json()["run_id"]

    action = {
        "type": "revoke_excessive_iam",
        "target": "user/junior-operator",
    }
    # Test standard wrapped format
    resp = client.post(f"/api/scenarios/runs/{run_id}/remediate", headers=auth_headers, json={"action": action})
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["verified"] is True
    assert data["status"] == "PASS"
    assert data["metrics"]["delta"]["paths_eliminated"] >= 1

    # Test direct payload format without wrapping (BUG-008 fix)
    launch_resp2 = client.post("/api/scenarios/privesc-excessive-iam/launch", headers=auth_headers)
    run_id2 = launch_resp2.get_json()["run_id"]
    resp2 = client.post(f"/api/scenarios/runs/{run_id2}/remediate", headers=auth_headers, json=action)
    assert resp2.status_code == 200
    assert resp2.get_json()["verified"] is True


# 7. POST /api/scenarios/runs/<run_id>/verify
def test_verify_run(client, auth_headers):
    """Verify inspecting post-remediation security status."""
    launch_resp = client.post("/api/scenarios/resource-s3-public/launch", headers=auth_headers)
    run_id = launch_resp.get_json()["run_id"]

    # Apply fix
    client.post(
        f"/api/scenarios/runs/{run_id}/remediate",
        headers=auth_headers,
        json={"action": {"type": "enable_s3_public_access_block", "target": "s3/student-records-public"}},
    )

    resp = client.post(f"/api/scenarios/runs/{run_id}/verify", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["verified"] is True
    assert data["status"] == "PASS"


# 8. POST /api/scenarios/runs/<run_id>/reset
def test_reset_run(client, auth_headers):
    """Verify resetting an isolated scenario run restores initial topology."""
    launch_resp = client.post("/api/scenarios/privesc-excessive-iam/launch", headers=auth_headers)
    run_id = launch_resp.get_json()["run_id"]

    # Remediate (removes paths)
    client.post(
        f"/api/scenarios/runs/{run_id}/remediate",
        headers=auth_headers,
        json={"action": {"type": "revoke_excessive_iam", "target": "user/junior-operator"}},
    )

    # Reset
    resp = client.post(f"/api/scenarios/runs/{run_id}/reset", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["status"] in ("reset", "analyzed")
    assert data["paths_count"] >= 1


# 9. POST /api/scenarios/custom
def test_create_custom_scenario(client, auth_headers):
    """Verify dynamic custom scenario builder endpoint."""
    custom_payload = {
        "id": "custom-devops-privesc",
        "name": "Custom DevOps Escalation Test",
        "description": "User-defined custom scenario connecting dev to s3 via admin role.",
        "category": "Custom Scenario",
        "difficulty": "Intermediate",
        "learning_objective": "Test dynamic builder API.",
        "identities": [
            {
                "id": "user/custom-dev",
                "name": "custom-dev",
                "type": "user",
                "arn": "arn:aws:iam::123456789012:user/custom-dev",
            },
            {
                "id": "role/custom-admin",
                "name": "custom-admin",
                "type": "role",
                "arn": "arn:aws:iam::123456789012:role/custom-admin",
                "is_admin": True,
            },
        ],
        "resources": [
            {
                "id": "s3/custom-secrets",
                "name": "custom-secrets",
                "type": "s3",
                "arn": "arn:aws:s3:::custom-secrets",
                "is_sensitive": True,
            }
        ],
        "relationships": [
            {
                "source_id": "user/custom-dev",
                "target_id": "role/custom-admin",
                "relationship": "AssumesRole",
                "actions": ["sts:AssumeRole"],
            },
            {
                "source_id": "role/custom-admin",
                "target_id": "s3/custom-secrets",
                "relationship": "CanAccessResource",
                "actions": ["s3:*"],
            },
        ],
    }

    resp = client.post("/api/scenarios/custom", headers=auth_headers, json=custom_payload)
    assert resp.status_code == 201
    data = resp.get_json()

    assert "run_id" in data
    assert len(data["paths"]) >= 1
    assert "graph" in data


# 10. POST /api/scenarios/validate-policy
def test_validate_policy(client, auth_headers):
    """Verify real-time IAM policy validation endpoint."""
    policy_payload = {
        "statements": [
            {
                "sid": "AdminStmt",
                "effect": "Allow",
                "actions": ["*"],
                "resources": ["*"],
            },
            {
                "sid": "DenyDelete",
                "effect": "Deny",
                "actions": ["s3:Delete*"],
                "resources": ["arn:aws:s3:::audit/*"],
            },
        ]
    }

    resp = client.post("/api/scenarios/validate-policy", headers=auth_headers, json=policy_payload)
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["valid"] is True
    assert data["has_explicit_deny"] is True
    assert data["statement_count"] == 2
    assert len(data["warnings"]) >= 1


def test_scenario_mutating_endpoints_require_auth(client):
    """Verify that unauthenticated mutating scenario requests are rejected with 401."""
    # 1. Launch
    assert client.post("/api/scenarios/privesc-excessive-iam/launch").status_code == 401
    # 2. Analyze
    assert client.post("/api/scenarios/runs/run-test/analyze").status_code == 401
    # 3. Remediate
    assert client.post("/api/scenarios/runs/run-test/remediate", json={"action": {}}).status_code == 401
    # 4. Verify
    assert client.post("/api/scenarios/runs/run-test/verify").status_code == 401
    # 5. Reset
    assert client.post("/api/scenarios/runs/run-test/reset").status_code == 401
    # 6. Custom
    assert client.post("/api/scenarios/custom", json={}).status_code == 401
    # 7. Validate policy
    assert client.post("/api/scenarios/validate-policy", json={}).status_code == 401
