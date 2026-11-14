"""Integration tests for CloudGuardian Flask API endpoints:
- Session cookie bootstrap and require_auth protection
- Attack simulation endpoint validation and Live mode guard
- Decision approval/rejection lifecycle
- Stale state detection and rollback validation
- Audit trail integrity query
"""
import json
import pytest
from app import app as flask_app, store, R
from backend.security import AUTH_HEADER, SESSION_COOKIE_NAME, get_active_api_key


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers():
    return {AUTH_HEADER: get_active_api_key()}


def test_home_page_serves_html_and_sets_cookie(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"CloudGuardian" in resp.data
    # Verify session cookie was attached
    cookie_header = resp.headers.get("Set-Cookie", "")
    assert SESSION_COOKIE_NAME in cookie_header


def test_api_state_returns_expected_structure(client):
    resp = client.get("/api/state")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "resources" in data
    assert "findings" in data
    assert "events" in data
    assert "score" in data
    assert "mode" in data
    assert "polls" in data


# ---- Attack Endpoint Tests ----

def test_api_attack_unauthorized_returns_401(client):
    resp = client.post("/api/attack/s3")
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["ok"] is False
    assert "Unauthorized" in data["error"]


def test_api_attack_invalid_key_returns_400(client, auth_headers):
    resp = client.post("/api/attack/nonexistent_service", headers=auth_headers)
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["ok"] is False
    assert "Invalid attack target" in data["error"]


def test_api_attack_live_mode_blocks_simulation(client, auth_headers, monkeypatch):
    import app
    monkeypatch.setattr(app, "LIVE", True)
    resp = client.post("/api/attack/s3", headers=auth_headers)
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["ok"] is False
    assert "disabled in Live AWS mode" in data["error"]


def test_api_attack_success_in_simulation(client, auth_headers, monkeypatch):
    import app
    monkeypatch.setattr(app, "LIVE", False)
    monkeypatch.setattr(app, "DRY_RUN", False)

    # Mock attack action so it doesn't require live network
    attack_called = False
    def mock_attack():
        nonlocal attack_called
        attack_called = True

    orig_attack = R["s3"]["attack"]
    R["s3"]["attack"] = mock_attack
    try:
        resp = client.post("/api/attack/s3", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert attack_called is True
    finally:
        R["s3"]["attack"] = orig_attack


# ---- Decide Endpoint Tests ----

def test_api_decide_unauthorized_returns_401(client):
    resp = client.post("/api/decide/s3/ok")
    assert resp.status_code == 401
    assert resp.get_json()["ok"] is False


def test_api_decide_unknown_key_returns_404(client, auth_headers):
    resp = client.post("/api/decide/unknown_res/ok", headers=auth_headers)
    assert resp.status_code == 404
    data = resp.get_json()
    assert "Unknown resource target" in data["error"]


def test_api_decide_invalid_decision_returns_400(client, auth_headers):
    resp = client.post("/api/decide/s3/maybe", headers=auth_headers)
    assert resp.status_code == 400
    data = resp.get_json()
    assert "Invalid decision" in data["error"]


def test_api_decide_not_pending_returns_400(client, auth_headers):
    # Ensure finding is not in pending status
    store.pop_finding("s3")
    resp = client.post("/api/decide/s3/ok", headers=auth_headers)
    assert resp.status_code == 400
    data = resp.get_json()
    assert "No pending finding" in data["error"]


def test_api_decide_approval_workflow(client, auth_headers):
    # Stage a pending finding
    store.set_finding("s3", {"id": "s3", "status": "pending", "ver": "abc123ver"})

    fix_called = False
    def mock_fix():
        nonlocal fix_called
        fix_called = True

    orig_fix = R["s3"]["fix"]
    orig_check = R["s3"]["check"]
    R["s3"]["fix"] = mock_fix
    R["s3"]["check"] = lambda: True

    try:
        resp = client.post("/api/decide/s3/ok", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert fix_called is True

        f = store.get_finding("s3")
        assert f["status"] == "fixed"
        assert f["verified"] is True
    finally:
        R["s3"]["fix"] = orig_fix
        R["s3"]["check"] = orig_check


def test_api_decide_rejection_workflow(client, auth_headers):
    store.set_finding("ct", {"id": "ct", "status": "pending"})
    resp = client.post("/api/decide/ct/no", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    f = store.get_finding("ct")
    assert f["status"] == "rejected"


# ---- Rollback Endpoint Tests ----

def test_api_rollback_unauthorized_returns_401(client):
    resp = client.post("/api/rollback/s3")
    assert resp.status_code == 401


def test_api_rollback_unknown_key_returns_404(client, auth_headers):
    resp = client.post("/api/rollback/invalid_resource", headers=auth_headers)
    assert resp.status_code == 404


def test_api_rollback_not_fixed_returns_400(client, auth_headers):
    store.set_finding("s3", {"id": "s3", "status": "pending"})
    resp = client.post("/api/rollback/s3", headers=auth_headers)
    assert resp.status_code == 400
    assert "nothing to roll back" in resp.get_json()["error"]


# ---- Audit and Rules Endpoints ----

def test_api_audit_query_returns_chain_ok(client):
    resp = client.get("/api/audit")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["chain_ok"] is True
    assert "rows" in data


def test_api_rules_endpoint(client):
    resp = client.get("/api/rules")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) >= 4
    rule_ids = [r["id"] for r in data]
    assert "s3" in rule_ids
    assert "ct" in rule_ids


def test_api_ml_endpoint(client):
    resp = client.get("/api/ml")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "results" in data
    assert "card" in data
