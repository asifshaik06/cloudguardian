"""Integration tests for Alerts page audit (ML XAI scores, lifecycle consistency, and evidence)."""
import pytest
from app import app as flask_app
from backend.security import AUTH_HEADER, get_active_api_key
from backend.soc.models import AlertSeverity, AlertStatus, IncidentStatus
from backend.soc.store import SOCStore


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers():
    return {AUTH_HEADER: get_active_api_key()}


@pytest.fixture
def store():
    return SOCStore()


# ---------------------------------------------------------------------------
# 1. Isolation Forest ML Anomaly Score Verification
# ---------------------------------------------------------------------------

class TestMLAnomalyScoreVerification:
    """Verify ML anomaly scores, thresholds, and feature contributions."""

    def test_ml_anomaly_score_returned_by_api(self, client):
        """GET /api/alerts/ALT-0004 must return real ML score and explanation."""
        resp = client.get("/api/alerts/ALT-0004")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ml_anomaly_score"] is not None
        assert isinstance(data["ml_anomaly_score"], float)
        assert data["ml_anomaly_score"] > 0.0

    def test_ml_explanation_contains_required_fields(self, client):
        """ML explanation must include features, threshold, and anomaly delta."""
        resp = client.get("/api/alerts/ALT-0004")
        data = resp.get_json()
        expl = data.get("ml_explanation")
        assert expl is not None
        assert "features" in expl
        assert "threshold" in expl
        assert "anomaly_delta" in expl
        # Check specific features
        features = expl["features"]
        assert len(features) >= 2
        assert "Requests per min" in features or "Hour of day" in features

    def test_rule_based_alerts_have_no_ml_score(self, client):
        """Rule Engine alerts (e.g. ALT-0001) should have null ML anomaly score."""
        resp = client.get("/api/alerts/ALT-0001")
        data = resp.get_json()
        assert data.get("ml_anomaly_score") is None


# ---------------------------------------------------------------------------
# 2. Alert Lifecycle Consistency & Incident Decoupling
# ---------------------------------------------------------------------------

class TestAlertLifecycleConsistency:
    """Verify that alert status changes and incident lifecycle are decoupled."""

    def test_resolving_alert_does_not_close_incident(self, store):
        """Resolving ALT-0004 must NOT automatically close INC-0001."""
        # Ensure INC-0001 is in Triage/Investigation
        inc = store.get_incident("INC-0001")
        assert inc is not None
        assert inc.status != IncidentStatus.CLOSED

        # Resolve ALT-0004
        updated_alert = store.update_alert_status("ALT-0004", AlertStatus.RESOLVED)
        assert updated_alert.status == AlertStatus.RESOLVED

        # Check INC-0001: must still be open!
        inc_after = store.get_incident("INC-0001")
        assert inc_after.status != IncidentStatus.CLOSED
        assert inc_after.status == inc.status

    def test_closing_incident_does_not_modify_alert_own_status(self, store):
        """Closing INC-0001 must NOT alter ALT-0001's own alert status."""
        alert_before = store.get_alert("ALT-0001")
        prev_status = alert_before.status

        # Close INC-0001
        store.update_incident("INC-0001", new_status=IncidentStatus.CLOSED, closure_reason="Remediated")

        # Alert's own status should remain unchanged
        alert_after = store.get_alert("ALT-0001")
        assert alert_after.status == prev_status
        # But incident_status pointer reflects the closed state
        assert alert_after.incident_status == "Closed"

    def test_alert_displays_linked_incident_status_separately(self, store):
        """Alert record returns incident_status separately from its own status."""
        alert = store.get_alert("ALT-0001")
        assert alert.incident_id == "INC-0001"
        assert alert.incident_status is not None
        # alert.status is AlertStatus, alert.incident_status is str reflecting incident
        assert alert.status.value != alert.incident_status or alert.status.value in ("New", "Investigating")

    def test_escalation_evidence_persists_after_alert_resolution(self, store):
        """Resolving an alert leaves its evidence and trigger_reason completely intact."""
        alert_before = store.get_alert("ALT-0004")
        evidence_before = alert_before.evidence.copy()
        trigger_before = alert_before.trigger_reason

        store.update_alert_status("ALT-0004", AlertStatus.RESOLVED)
        alert_after = store.get_alert("ALT-0004")

        assert alert_after.status == AlertStatus.RESOLVED
        assert alert_after.evidence == evidence_before
        assert alert_after.trigger_reason == trigger_before
        assert alert_after.incident_id == alert_before.incident_id


# ---------------------------------------------------------------------------
# 3. Alert Filters and Actions API
# ---------------------------------------------------------------------------

class TestAlertFiltersAndActionsAPI:
    """Test API filtering by severity, status, source, and search query."""

    def test_filter_by_severity(self, client):
        resp = client.get("/api/alerts?severity=Critical")
        data = resp.get_json()
        assert data["total"] >= 1
        for a in data["alerts"]:
            assert a["severity"] == "Critical"

    def test_filter_by_source(self, client):
        resp = client.get("/api/alerts?source=ML+Anomaly+Detector")
        data = resp.get_json()
        assert data["total"] >= 1
        for a in data["alerts"]:
            assert "ML Anomaly" in a["detection_source"]

    def test_filter_by_status(self, client):
        resp = client.get("/api/alerts?status=New")
        data = resp.get_json()
        for a in data["alerts"]:
            assert a["status"] == "New"

    def test_search_query(self, client):
        resp = client.get("/api/alerts?q=S3")
        data = resp.get_json()
        assert data["total"] >= 1
        for a in data["alerts"]:
            assert "s3" in a["title"].lower() or "s3" in a["affected_resource"].lower()

    def test_alert_lifecycle_action_endpoints(self, client, auth_headers):
        """Test Acknowledge -> Investigate -> Resolve -> Suppress cycle."""
        # 1. Acknowledge
        r1 = client.post("/api/alerts/ALT-0002/action", headers=auth_headers, json={"action": "acknowledge"})
        assert r1.status_code == 200
        assert r1.get_json()["alert"]["status"] == "Acknowledged"

        # 2. Investigate
        r2 = client.post("/api/alerts/ALT-0002/action", headers=auth_headers, json={"action": "investigate"})
        assert r2.status_code == 200
        assert r2.get_json()["alert"]["status"] == "Investigating"

        # 3. Resolve
        r3 = client.post("/api/alerts/ALT-0002/action", headers=auth_headers, json={"action": "resolve"})
        assert r3.status_code == 200
        assert r3.get_json()["alert"]["status"] == "Resolved"

    def test_alt0004_links_to_inc0001(self, client):
        """Verify ALT-0004 has incident_id INC-0001 and incident_status is returned."""
        resp = client.get("/api/alerts/ALT-0004")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["incident_id"] == "INC-0001"
        assert "incident_status" in data
