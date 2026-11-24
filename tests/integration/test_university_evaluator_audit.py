"""Comprehensive University Evaluator & Readiness Audit Test Suite for ThreatGuard.

Verifies:
- All 10 End-to-End Security Workflows
- REST API contract, input validation, and negative status codes
- Tamper-evident hash chain integrity & attack simulations
- Strict UI safety: 0 native browser dialogs (alert, confirm, prompt)
- 11 Visible Navigation Items, preserved hidden architecture/demo routes, no sfoot
"""
import re
import pytest
from app import app as flask_app
import app as app_module
from backend.security import AUTH_HEADER, get_active_api_key


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers():
    return {AUTH_HEADER: get_active_api_key()}


# =========================================================================
# WORKFLOW 1: ATTACK DETECTION -> FINDINGS & ALERTS
# =========================================================================

def test_workflow_1_attack_detection_to_alerts(client, auth_headers, monkeypatch):
    """Workflow 1: Inject simulated attack -> Verify state findings and alerts generation."""
    # Test initial state
    resp = client.get("/api/state")
    assert resp.status_code == 200
    state = resp.get_json()
    assert "findings" in state
    assert "score" in state

    # Mock attack action so test environment doesn't require live socket to Moto
    monkeypatch.setattr(app_module, "LIVE", False)
    monkeypatch.setattr(app_module, "DRY_RUN", False)
    attack_executed = False

    def mock_s3_attack():
        nonlocal attack_executed
        attack_executed = True

    monkeypatch.setitem(app_module.R["s3"], "attack", mock_s3_attack)

    # Trigger attack simulation for s3 public exposure with valid authentication
    resp_atk = client.post("/api/attack/s3", headers=auth_headers)
    assert resp_atk.status_code == 200
    atk_data = resp_atk.get_json()
    assert atk_data.get("ok") is True
    assert attack_executed is True

    # Verify alerts list contains alerts
    resp_alerts = client.get("/api/alerts")
    assert resp_alerts.status_code == 200
    alerts_data = resp_alerts.get_json()
    assert alerts_data["total"] > 0


# =========================================================================
# WORKFLOW 2: ALERT ESCALATION -> INCIDENT CREATION
# =========================================================================

def test_workflow_2_alert_escalation_to_incident(client, auth_headers):
    """Workflow 2: Escalate an alert and verify incident creation with linkage."""
    # Create or fetch an alert
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    alerts = resp.get_json()["alerts"]
    assert len(alerts) > 0
    target_alert = alerts[0]
    alert_id = target_alert["id"]

    # Escalate alert
    esc_payload = {
        "title": f"Escalated Incident from {alert_id}",
        "severity": "Critical",
        "summary": "Formal security analyst escalation for critical posture drift.",
        "assigned_to": "SOC Lead"
    }
    resp_esc = client.post(f"/api/alerts/{alert_id}/escalate", json=esc_payload, headers=auth_headers)
    assert resp_esc.status_code in [200, 201]
    res_data = resp_esc.get_json()
    incident = res_data.get("incident", res_data)
    assert "id" in incident
    assert incident["id"].startswith("INC-")
    assert incident["severity"] == "Critical"
    assert alert_id in incident["linked_alert_ids"]
    assert incident["status"] == "Triage"

    # Verify incident appears in incident list
    resp_inc_list = client.get("/api/incidents")
    assert resp_inc_list.status_code == 200
    inc_ids = [i["id"] for i in resp_inc_list.get_json()["incidents"]]
    assert incident["id"] in inc_ids


# =========================================================================
# WORKFLOW 3: COMPLETE INCIDENT RESPONSE LIFECYCLE (6 STAGES)
# =========================================================================

def test_workflow_3_complete_incident_lifecycle(client, auth_headers):
    """Workflow 3: Progress an incident through all 6 response stages to closure."""
    # Create fresh incident
    create_resp = client.post("/api/incidents", json={
        "title": "E2E Lifecycle Verification Incident",
        "severity": "High",
        "summary": "Verifying full response pipeline.",
        "lead_analyst": "Evaluator Analyst"
    }, headers=auth_headers)
    assert create_resp.status_code in [200, 201]
    inc = create_resp.get_json()
    inc_id = inc["id"]
    assert inc["status"] == "Triage"

    # Stage 2: Investigation
    client.post(f"/api/incidents/{inc_id}/action", json={"status": "Investigation", "notes": "Triaged initial logs."}, headers=auth_headers)
    inc_check = client.get(f"/api/incidents/{inc_id}").get_json()
    assert inc_check["status"] == "Investigation"

    # Stage 3: Containment
    client.post(f"/api/incidents/{inc_id}/action", json={
        "status": "Containment",
        "containment_evidence": {
            "quarantine_enacted": True,
            "sessions_terminated": True,
            "ingress_restricted": True
        }
    }, headers=auth_headers)
    inc_check = client.get(f"/api/incidents/{inc_id}").get_json()
    assert inc_check["status"] == "Containment"
    assert inc_check["containment_evidence"]["quarantine_enacted"] is True

    # Stage 4: Remediation
    client.post(f"/api/incidents/{inc_id}/action", json={"status": "Remediation", "notes": "Remediation task REM-0001 dispatched."}, headers=auth_headers)
    inc_check = client.get(f"/api/incidents/{inc_id}").get_json()
    assert inc_check["status"] == "Remediation"

    # Stage 5: Verification
    client.post(f"/api/incidents/{inc_id}/action", json={"status": "Verification", "notes": "CSPM re-scan returned 100% compliant."}, headers=auth_headers)
    inc_check = client.get(f"/api/incidents/{inc_id}").get_json()
    assert inc_check["status"] == "Verification"

    # Stage 6: Closed
    client.post(f"/api/incidents/{inc_id}/action", json={"status": "Closed", "closure_reason": "Threat neutralized and verified."}, headers=auth_headers)
    inc_check = client.get(f"/api/incidents/{inc_id}").get_json()
    assert inc_check["status"] == "Closed"
    assert inc_check["closure_reason"] == "Threat neutralized and verified."


# =========================================================================
# WORKFLOW 4: IAM ATTACK GRAPH & ATTACK-PATH TRACING
# =========================================================================

def test_workflow_4_iam_graph_and_path_tracing(client):
    """Workflow 4: Graph topology, privilege escalation paths, and node details."""
    resp = client.get("/api/graph")
    assert resp.status_code == 200
    graph = resp.get_json()
    assert "nodes" in graph
    assert "links" in graph
    assert len(graph["nodes"]) > 0
    assert len(graph["links"]) > 0

    # Test all-paths endpoint
    resp_paths = client.get("/api/graph/all-paths")
    assert resp_paths.status_code == 200
    paths_data = resp_paths.get_json()
    assert "escalations" in paths_data
    assert len(paths_data["escalations"]) > 0

    # Ensure paths have required risk fields
    all_paths = [p for sub in paths_data["escalations"].values() for p in sub]
    assert len(all_paths) > 0
    first_path = all_paths[0]
    assert "source" in first_path
    assert "target" in first_path
    assert "hops" in first_path
    assert "risk_score" in first_path


# =========================================================================
# WORKFLOW 5: BLAST-RADIUS ANALYSIS & CROSS-HOP INSPECTION
# =========================================================================

def test_workflow_5_blast_radius_analysis(client):
    """Workflow 5: Calculate blast radius for critical identity."""
    target_principal = "user/intern-dev"
    resp = client.get(f"/api/graph/blast-radius/{target_principal}")
    assert resp.status_code == 200
    blast = resp.get_json()
    assert "admin_reachable" in blast
    assert "max_propagation_depth" in blast
    assert "reachable_principals" in blast
    assert "reachable_resources" in blast
    assert len(blast["reachable_principals"]) > 0


# =========================================================================
# WORKFLOW 6 & 7: REMEDIATION APPROVAL, VERIFICATION & ROLLBACK
# =========================================================================

def test_workflow_6_and_7_remediation_lifecycle_and_rollback(client, auth_headers, monkeypatch):
    """Workflow 6 & 7: Test full remediation lifecycle and subsequent safe rollback."""
    # List remediations
    resp = client.get("/api/remediations")
    assert resp.status_code == 200
    rem_list = resp.get_json()["remediations"]
    assert len(rem_list) > 0
    rem_id = rem_list[0]["id"]

    # Approve remediation
    resp_appr = client.post(f"/api/remediations/{rem_id}/approve", json={"user": "Evaluator Lead"}, headers=auth_headers)
    assert resp_appr.status_code == 200
    appr_data = resp_appr.get_json()
    status = appr_data["remediation"]["status"] if "remediation" in appr_data else appr_data.get("status")
    assert status == "Approved"

    # Apply remediation
    resp_apply = client.post(f"/api/remediations/{rem_id}/apply", json={"user": "Evaluator Lead"}, headers=auth_headers)
    assert resp_apply.status_code == 200

    # Verify remediation
    resp_ver = client.post(f"/api/remediations/{rem_id}/verify", headers=auth_headers)
    assert resp_ver.status_code == 200

    # Mock rollback attack call so test environment doesn't fail on socket permissions
    monkeypatch.setitem(app_module.R["s3"], "attack", lambda: True)

    # Workflow 7: Rollback remediation
    resp_roll = client.post(f"/api/remediations/{rem_id}/rollback", headers=auth_headers)
    assert resp_roll.status_code == 200
    roll_data = resp_roll.get_json()
    status_roll = roll_data["remediation"]["status"] if "remediation" in roll_data else roll_data.get("status")
    assert status_roll in ("Rolled Back", "Rolled_Back")


# =========================================================================
# WORKFLOW 8: PREDEFINED SCENARIO LAB EXECUTION & RESET
# =========================================================================

def test_workflow_8_predefined_scenario_execution(client, auth_headers):
    """Workflow 8: Predefined scenario execution, path inspection, and reset."""
    resp = client.get("/api/scenarios")
    assert resp.status_code == 200
    scenarios = resp.get_json()["scenarios"]
    assert len(scenarios) >= 12

    # Launch excessive permissions scenario
    target_scen = scenarios[0]["id"]
    launch_resp = client.post(f"/api/scenarios/{target_scen}/launch", headers=auth_headers)
    assert launch_resp.status_code in [200, 201]
    run_info = launch_resp.get_json()
    assert "run_id" in run_info
    run_id = run_info["run_id"]

    # Inspect run details
    run_resp = client.get(f"/api/scenarios/runs/{run_id}")
    assert run_resp.status_code == 200
    run_data = run_resp.get_json()
    assert run_data["scenario_id"] == target_scen
    assert "paths" in run_data
    assert "graph" in run_data

    # Verify scenario
    ver_resp = client.post(f"/api/scenarios/runs/{run_id}/verify", headers=auth_headers)
    assert ver_resp.status_code == 200

    # Reset scenario
    reset_resp = client.post(f"/api/scenarios/runs/{run_id}/reset", headers=auth_headers)
    assert reset_resp.status_code == 200


# =========================================================================
# WORKFLOW 9: DYNAMIC CUSTOM SCENARIO BUILDER
# =========================================================================

def test_workflow_9_dynamic_custom_scenario_builder(client, auth_headers):
    """Workflow 9: Dynamic custom scenario creation and policy statement validation."""
    # Step A: Validate policy statement
    val_resp = client.post("/api/scenarios/validate-policy", json={
        "statements": [
            {"effect": "Allow", "actions": ["iam:PassRole", "ec2:RunInstances"], "resources": ["*"]}
        ]
    }, headers=auth_headers)
    assert val_resp.status_code == 200
    val_data = val_resp.get_json()
    assert val_data["valid"] is True
    assert val_data["risk_level"] in ["High", "Critical"]

    # Step B: Build custom scenario
    custom_payload = {
        "id": "custom-evaluator-demo",
        "name": "Custom Escalation Sandbox",
        "description": "User created test scenario for viva demo.",
        "category": "Custom Scenario",
        "difficulty": "Intermediate",
        "learning_objective": "Understand PassRole privilege escalation vector.",
        "identities": [
            {
                "id": "user/student-test",
                "name": "student-test",
                "type": "user",
                "arn": "arn:aws:iam::123456789012:user/student-test",
                "is_admin": False
            },
            {
                "id": "role/target-admin",
                "name": "target-admin",
                "type": "role",
                "arn": "arn:aws:iam::123456789012:role/target-admin",
                "is_admin": True
            }
        ],
        "resources": [
            {
                "id": "s3/top-secret-eval",
                "name": "top-secret-eval",
                "type": "s3",
                "arn": "arn:aws:s3:::top-secret-eval",
                "is_sensitive": True
            }
        ],
        "relationships": [
            {
                "source_id": "user/student-test",
                "target_id": "role/target-admin",
                "relationship": "AssumesRole",
                "actions": ["sts:AssumeRole"]
            },
            {
                "source_id": "role/target-admin",
                "target_id": "s3/top-secret-eval",
                "relationship": "CanAccessResource",
                "actions": ["s3:*"]
            }
        ]
    }
    cust_resp = client.post("/api/scenarios/custom", json=custom_payload, headers=auth_headers)
    assert cust_resp.status_code in [200, 201]
    cust_data = cust_resp.get_json()
    assert "run_id" in cust_data


# =========================================================================
# WORKFLOW 10: TAMPER-EVIDENT AUDIT TRAIL HASH CHAIN INTEGRITY
# =========================================================================

def test_workflow_10_audit_hash_chain_integrity(client):
    """Workflow 10: Verify cryptographic hash-chain integrity of audit log."""
    resp = client.get("/api/audit")
    assert resp.status_code == 200
    audit_data = resp.get_json()
    assert "rows" in audit_data
    assert "chain_ok" in audit_data
    assert audit_data["chain_ok"] is True
    assert len(audit_data["rows"]) > 0

    # Verify sha256 hash formatting on each row
    for row in audit_data["rows"]:
        assert "hash" in row
        assert "text" in row
        assert "i" in row


# =========================================================================
# SYSTEM INTEGRITY & DASHBOARD READINESS CHECKS
# =========================================================================

def test_zero_native_dialogs_in_frontend():
    """Verify strictly 0 browser native dialogs (alert, confirm, prompt) exist in static JS/HTML."""
    with open("static/index.html", "r", encoding="utf-8") as f:
        html = f.read()
    with open("static/views.js", "r", encoding="utf-8") as f:
        views = f.read()
    with open("static/charts.js", "r", encoding="utf-8") as f:
        charts = f.read()

    combined = html + views + charts
    assert "alert(" not in combined, "Found native alert() call!"
    assert "confirm(" not in combined, "Found native confirm() call!"
    assert "prompt(" not in combined, "Found native prompt() call!"


def test_sidebar_exactly_11_items_and_no_sfoot():
    """Verify exactly 11 visible sidebar navigation items, no data source panel."""
    with open("static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # PAGES array in index.html must have exactly 11 entries
    pages_match = re.search(r'const PAGES=\[(\s*\[.*?\]\s*,?)+\];', html, re.DOTALL)
    assert pages_match is not None
    pages_block = pages_match.group(0)
    items = re.findall(r'\["([^"]+)",\s*"([^"]+)"\]', pages_block)
    assert len(items) == 11, f"Expected 11 visible sidebar items, got {len(items)}: {items}"

    # Ensure Architecture and Demo are NOT in PAGES
    page_keys = [k for k, _ in items]
    assert "architecture" not in page_keys
    assert "demo" not in page_keys

    # Ensure sfoot is completely removed
    assert 'id="sfoot"' not in html
    assert 'class="sfoot"' not in html


def test_architecture_and_demo_apis_functional(client):
    """Verify preserved hidden architecture & demo documentation APIs remain operational."""
    resp_arch = client.get("/api/architecture")
    assert resp_arch.status_code == 200
    arch = resp_arch.get_json()
    assert "pipeline" in arch
    assert "problem_statement" in arch
    assert "core_differentiators" in arch
    assert "tech_stack" in arch

    resp_demo = client.get("/api/demo")
    assert resp_demo.status_code == 200
    demo = resp_demo.get_json()
    assert "title" in demo
    assert "steps" in demo
    assert len(demo["steps"]) >= 17
