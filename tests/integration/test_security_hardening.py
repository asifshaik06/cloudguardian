"""Security Hardening and Operator Authentication Regression Tests.

Verifies:
- Public read-only endpoints do not leak credentials or API keys.
- Homepage does not dispense master API key via cookies or payload.
- /api/auth/session does not expose secrets.
- Unauthenticated mutating/write requests are rejected with 401 Unauthorized.
- Operator login validates credentials and establishes an HttpOnly session.
- Session-based mutating requests require valid CSRF tokens (403 Forbidden on missing/invalid).
- Authenticated requests with valid CSRF tokens succeed.
- Operator logout invalidates the session and expires the session cookie.
- Programmatic API key header authentication continues to function without CSRF requirement.
"""
import pytest
from app import app as flask_app
from backend.security import (
    AUTH_HEADER,
    CSRF_HEADER,
    SESSION_COOKIE_NAME,
    get_active_api_key,
    session_store,
)


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    session_store.clear()
    with flask_app.test_client() as client:
        yield client
    session_store.clear()


@pytest.fixture
def active_key():
    return get_active_api_key()


def test_public_homepage_does_not_distribute_api_key(client, active_key):
    """Verify that unauthenticated GET / serves dashboard without setting or exposing API key."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"ThreatGuard" in resp.data

    # Ensure master API key is never in HTML or headers
    assert active_key.encode("utf-8") not in resp.data
    cookie_header = resp.headers.get("Set-Cookie", "")
    assert active_key not in cookie_header


def test_auth_session_endpoint_does_not_leak_api_key(client, active_key):
    """Verify GET /api/auth/session returns sanitized role metadata without secrets."""
    resp = client.get("/api/auth/session")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["authenticated"] is False
    assert data["role"] == "viewer"
    assert "api_key" not in data

    cookie_header = resp.headers.get("Set-Cookie", "")
    assert active_key not in cookie_header


def test_public_read_endpoints_accessible_without_auth(client):
    """Verify public read endpoints return expected data to unauthenticated visitors."""
    read_routes = [
        "/api/state",
        "/api/metrics",
        "/api/events",
        "/api/rules",
        "/api/alerts",
        "/api/alerts/stats",
        "/api/incidents",
        "/api/remediations",
        "/api/remediations/stats",
        "/api/scenarios",
        "/api/graph",
        "/api/graph/all-paths",
        "/api/graph/stats",
        "/api/audit",
        "/api/ml",
        "/api/datasets",
        "/api/replay/datasets",
        "/api/architecture",
        "/api/demo",
    ]
    for route in read_routes:
        resp = client.get(route)
        assert resp.status_code == 200, f"Public read route {route} failed with {resp.status_code}"


def test_unauthenticated_write_endpoints_rejected_with_401(client):
    """Verify that unauthenticated state-modifying requests fail with 401 Unauthorized."""
    write_attempts = [
        ("POST", "/api/attack/s3", None),
        ("POST", "/api/decide/s3/ok", None),
        ("POST", "/api/rollback/s3", None),
        ("POST", "/api/alerts/ALT-0001/action", {"action": "resolve"}),
        ("POST", "/api/alerts/ALT-0001/escalate", {"title": "Test"}),
        ("POST", "/api/incidents", {"title": "Test Incident"}),
        ("POST", "/api/incidents/INC-0001/action", {"status": "Investigation"}),
        ("POST", "/api/remediations/REM-0001/approve", {"user": "Analyst"}),
        ("POST", "/api/remediations/REM-0001/apply", {"user": "Analyst"}),
        ("POST", "/api/remediations/REM-0001/verify", None),
        ("POST", "/api/remediations/REM-0001/rollback", None),
        ("POST", "/api/scenarios/privesc-excessive-iam/launch", None),
        ("POST", "/api/scenarios/custom", {"id": "custom-1"}),
        ("POST", "/api/scenarios/validate-policy", {"statements": []}),
        ("POST", "/api/replay/splunk_s3_public_bucket", None),
    ]
    for method, url, payload in write_attempts:
        if method == "POST":
            resp = client.post(url, json=payload)
        else:
            resp = client.open(url, method=method, json=payload)
        assert resp.status_code == 401, f"Expected 401 for unauthenticated {method} {url}, got {resp.status_code}"
        data = resp.get_json()
        assert data.get("ok") is False
        assert "Unauthorized" in data.get("error", "")


def test_operator_login_invalid_credential_fails(client):
    """Verify login with incorrect credential returns 401."""
    resp = client.post("/api/auth/login", json={"key": "wrong-secret-key"})
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["ok"] is False
    assert "Invalid operator" in data["error"]


def test_operator_login_valid_credential_establishes_session(client, active_key):
    """Verify login with active key establishes session, sets HttpOnly cookie, returns CSRF token."""
    resp = client.post("/api/auth/login", json={"key": active_key})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["authenticated"] is True
    assert data["role"] == "operator"
    assert "csrf_token" in data
    assert len(data["csrf_token"]) >= 24

    # Verify session cookie was set with HttpOnly and SameSite
    cookie_header = resp.headers.get("Set-Cookie", "")
    assert SESSION_COOKIE_NAME in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=Lax" in cookie_header

    # Verify session status check reflects authenticated operator
    session_resp = client.get("/api/auth/session")
    assert session_resp.status_code == 200
    sess_data = session_resp.get_json()
    assert sess_data["authenticated"] is True
    assert sess_data["role"] == "operator"
    assert sess_data["csrf_token"] == data["csrf_token"]


def test_session_state_modifying_request_without_csrf_fails_with_403(client, active_key):
    """Verify session-authenticated mutating request without CSRF header is rejected with 403."""
    login_resp = client.post("/api/auth/login", json={"key": active_key})
    assert login_resp.status_code == 200

    # Attempt state mutation without CSRF token
    resp = client.post("/api/attack/s3")
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["ok"] is False
    assert "CSRF validation failed" in data["error"]


def test_session_state_modifying_request_with_invalid_csrf_fails_with_403(client, active_key):
    """Verify session-authenticated mutating request with mismatched CSRF header is rejected with 403."""
    login_resp = client.post("/api/auth/login", json={"key": active_key})
    assert login_resp.status_code == 200

    # Attempt state mutation with invalid CSRF token
    resp = client.post("/api/attack/s3", headers={CSRF_HEADER: "invalid-tampered-token"})
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["ok"] is False
    assert "CSRF validation failed" in data["error"]


def test_session_state_modifying_request_with_valid_csrf_succeeds(client, active_key, monkeypatch):
    """Verify session-authenticated mutating request with valid CSRF token succeeds."""
    login_resp = client.post("/api/auth/login", json={"key": active_key})
    assert login_resp.status_code == 200
    csrf_token = login_resp.get_json()["csrf_token"]

    # Mock attack action so test environment doesn't require live network
    import app as app_module
    monkeypatch.setattr(app_module, "LIVE", False)
    monkeypatch.setattr(app_module, "DRY_RUN", False)
    monkeypatch.setitem(app_module.R["s3"], "attack", lambda: None)

    resp = client.post("/api/attack/s3", headers={CSRF_HEADER: csrf_token})
    assert resp.status_code == 200
    assert resp.get_json().get("ok") is True


def test_operator_logout_terminates_session(client, active_key):
    """Verify logout invalidates session in store and expires session cookie."""
    login_resp = client.post("/api/auth/login", json={"key": active_key})
    assert login_resp.status_code == 200

    logout_resp = client.post("/api/auth/logout")
    assert logout_resp.status_code == 200
    assert logout_resp.get_json()["ok"] is True

    # Check status endpoint now reports unauthenticated viewer
    session_resp = client.get("/api/auth/session")
    assert session_resp.status_code == 200
    assert session_resp.get_json()["authenticated"] is False
    assert session_resp.get_json()["role"] == "viewer"

    # Attempting mutating request with old cookie fails with 401
    resp = client.post("/api/attack/s3")
    assert resp.status_code == 401


def test_programmatic_api_key_header_bypasses_browser_csrf(client, active_key, monkeypatch):
    """Verify automated scripts and tests using X-API-Key work without requiring CSRF token."""
    import app as app_module
    monkeypatch.setattr(app_module, "LIVE", False)
    monkeypatch.setattr(app_module, "DRY_RUN", False)
    monkeypatch.setitem(app_module.R["s3"], "attack", lambda: None)

    # Calling with direct API key header
    resp = client.post("/api/attack/s3", headers={AUTH_HEADER: active_key})
    assert resp.status_code == 200
    assert resp.get_json().get("ok") is True
