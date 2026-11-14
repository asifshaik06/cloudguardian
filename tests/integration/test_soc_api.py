"""Integration tests for CloudGuardian SOC REST API Endpoints."""
import pytest
from app import app as flask_app


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


# =========================================================================
# 1. ALERTS API ENDPOINTS
# =========================================================================

def test_alerts_list_and_filters(client):
    """Test listing alerts and filtering by severity and status."""
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "alerts" in data
    assert "total" in data
    assert data["total"] >= 4

    # Filter by severity
    resp_crit = client.get("/api/alerts?severity=Critical")
    assert resp_crit.status_code == 200
    crit_data = resp_crit.get_json()
    for a in crit_data["alerts"]:
        assert a["severity"] == "Critical"


def test_alert_details_and_404(client):
    """Test getting alert details and handling unknown alert ID."""
    resp = client.get("/api/alerts/ALT-0001")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["id"] == "ALT-0001"
    assert "timeline" in data

    resp_404 = client.get("/api/alerts/ALT-9999")
    assert resp_404.status_code == 404


def test_alert_lifecycle_actions_api(client):
    """Test updating alert status via action endpoint."""
    resp = client.post(
        "/api/alerts/ALT-0001/action",
        json={"action": "acknowledge", "notes": "Triaged by security team", "user": "analyst1"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["alert"]["status"] == "Acknowledged"

    # Invalid action
    resp_bad = client.post("/api/alerts/ALT-0001/action", json={"action": "destroy"})
    assert resp_bad.status_code == 400


def test_alert_escalation_to_incident_api(client):
    """Test escalating an alert into a new incident."""
    resp = client.post(
        "/api/alerts/ALT-0001/escalate",
        json={
            "title": "Escalated S3 Breach Investigation",
            "severity": "Critical",
            "summary": "Urgent escalation from alert ALT-0001.",
            "lead_responder": "Incident Commander",
        },
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert "incident" in data
    assert data["incident"]["id"].startswith("INC-")
    assert "ALT-0001" in data["incident"]["linked_alert_ids"]


def test_alert_stats_api(client):
    """Test retrieving alert statistics."""
    resp = client.get("/api/alerts/stats")
    assert resp.status_code == 200
    stats = resp.get_json()
    assert "total" in stats
    assert "by_severity" in stats
    assert "by_status" in stats


# =========================================================================
# 2. INCIDENTS API ENDPOINTS
# =========================================================================

def test_incidents_list_and_details(client):
    """Test listing incidents and retrieving individual incident."""
    resp = client.get("/api/incidents")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "incidents" in data
    assert data["total"] >= 1

    inc_id = data["incidents"][0]["id"]
    detail_resp = client.get(f"/api/incidents/{inc_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.get_json()["id"] == inc_id


def test_incident_create_and_action(client):
    """Test creating an incident and updating its status/notes."""
    create_resp = client.post(
        "/api/incidents",
        json={
            "title": "Ransomware Defense Simulation",
            "severity": "High",
            "summary": "Simulated ransomware canary trigger.",
            "affected_assets": ["s3/prod-backup"],
            "lead_responder": "Lead Responder",
        },
    )
    assert create_resp.status_code == 201
    inc = create_resp.get_json()
    inc_id = inc["id"]

    # Update to Containment
    act_resp = client.post(
        f"/api/incidents/{inc_id}/action",
        json={
            "status": "Containment",
            "notes": "Isolated network access",
            "containment_evidence": {"isolated": True},
        },
    )
    assert act_resp.status_code == 200
    assert act_resp.get_json()["status"] == "Containment"


# =========================================================================
# 3. REMEDIATION API ENDPOINTS (WITH INDEPENDENT VERIFICATION)
# =========================================================================

def test_remediations_list_and_stats(client):
    """Test listing remediations and getting stats."""
    resp = client.get("/api/remediations")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "remediations" in data
    assert "stats" in data
    assert data["total"] >= 4

    stats_resp = client.get("/api/remediations/stats")
    assert stats_resp.status_code == 200
    assert "total" in stats_resp.get_json()


def test_remediation_approval_and_apply(client):
    """Test approving and applying remediation task."""
    # Find a task with finding_id 's3'
    list_resp = client.get("/api/remediations")
    rems = list_resp.get_json()["remediations"]
    target = next((r for r in rems if r["related_finding_id"] == "s3"), rems[0])
    rem_id = target["id"]

    # Approve
    appr_resp = client.post(f"/api/remediations/{rem_id}/approve", json={"user": "admin_auditor"})
    assert appr_resp.status_code == 200
    assert appr_resp.get_json()["remediation"]["status"] == "Approved"

    # Apply (triggers executor and independent verifier)
    apply_resp = client.post(f"/api/remediations/{rem_id}/apply", json={"user": "admin_auditor"})
    assert apply_resp.status_code == 200
    app_data = apply_resp.get_json()
    assert "remediation" in app_data
    assert app_data["remediation"]["verification_state"] in ("PASS", "FAIL", "PARTIAL")


def test_remediation_independent_verify_endpoint(client):
    """Test standalone verify endpoint for remediation."""
    resp = client.post("/api/remediations/REM-0001/verify")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "verification_state" in data
    assert data["verification_state"] in ("PASS", "FAIL", "PARTIAL", "UNVERIFIED")


# =========================================================================
# 4. ARCHITECTURE & GUIDED DEMO DOCUMENTATION ENDPOINTS
# =========================================================================

def test_architecture_documentation_api(client):
    """Test retrieving structured architecture documentation."""
    resp = client.get("/api/architecture")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "pipeline" in data
    assert len(data["pipeline"]) == 10  # 10 pipeline stages
    assert "problem_statement" in data
    assert "core_differentiators" in data
    assert "tech_stack" in data


def test_guided_demo_script_api(client):
    """Test retrieving 17-step viva demonstration presentation."""
    resp = client.get("/api/demo")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "steps" in data
    assert len(data["steps"]) == 17  # 17 viva steps
    assert "total_steps" in data
    assert data["total_steps"] == 17
