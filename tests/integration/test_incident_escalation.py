"""Tests for enriched alert-to-incident escalation (BUG 1–3, 5)."""
import time
import pytest
from backend.soc.models import AlertSeverity, IncidentSeverity, IncidentStatus
from backend.soc.store import SOCStore


@pytest.fixture
def store():
    """Fresh SOCStore without seed data interference — re-seeds automatically."""
    return SOCStore()


# ---------------------------------------------------------------------------
# BUG 1 — Escalation preserves alert security context
# ---------------------------------------------------------------------------

class TestEscalationContextPreservation:
    """Verify that escalating an alert captures a full evidence snapshot."""

    def test_escalation_evidence_snapshot_created(self, store):
        """Escalation must create an escalation_evidence dict on the incident."""
        alert = store.get_alert("ALT-0003")  # SSH alert, not yet escalated
        assert alert is not None
        assert alert.incident_id is None  # Not yet escalated

        inc = store.create_incident(
            title=f"{alert.title} — test",
            severity=IncidentSeverity.HIGH,
            summary="Test escalation",
            linked_alert_ids=["ALT-0003"],
            escalation_evidence={
                "source_alert_id": alert.id,
                "alert_title": alert.title,
                "detection_source": alert.detection_source,
                "rule_ref": alert.rule_ref,
                "trigger_reason": alert.trigger_reason,
                "risk_score": alert.risk_score,
                "evidence": alert.evidence,
            },
            detection_source=alert.detection_source,
        )
        assert inc.escalation_evidence is not None
        assert inc.escalation_evidence["source_alert_id"] == "ALT-0003"
        assert inc.escalation_evidence["alert_title"] == alert.title
        assert inc.escalation_evidence["detection_source"] == alert.detection_source
        assert inc.escalation_evidence["rule_ref"] == alert.rule_ref
        assert inc.escalation_evidence["trigger_reason"] == alert.trigger_reason
        assert inc.escalation_evidence["risk_score"] == alert.risk_score
        assert inc.escalation_evidence["evidence"] == alert.evidence

    def test_escalation_preserves_detection_source(self, store):
        inc = store.create_incident(
            title="Test",
            severity=IncidentSeverity.HIGH,
            summary="Test",
            detection_source="ML Anomaly Detector (Isolation Forest)",
        )
        assert inc.detection_source == "ML Anomaly Detector (Isolation Forest)"

    def test_escalation_preserves_mitre_technique(self, store):
        inc = store.create_incident(
            title="Test",
            severity=IncidentSeverity.HIGH,
            summary="Test",
            mitre_technique="MITRE T1530",
        )
        assert inc.mitre_technique == "MITRE T1530"

    def test_escalation_preserves_account_and_region(self, store):
        inc = store.create_incident(
            title="Test",
            severity=IncidentSeverity.HIGH,
            summary="Test",
            account_id="123456789012",
            region="us-east-1",
        )
        assert inc.account_id == "123456789012"
        assert inc.region == "us-east-1"

    def test_escalation_preserves_description(self, store):
        inc = store.create_incident(
            title="Test",
            severity=IncidentSeverity.HIGH,
            summary="Test summary",
            description="Detailed security description here",
        )
        assert inc.description == "Detailed security description here"

    def test_alert_linked_to_incident_after_escalation(self, store):
        """After escalation, the alert's incident_id must be set."""
        inc = store.create_incident(
            title="Test",
            severity=IncidentSeverity.HIGH,
            summary="Test",
            linked_alert_ids=["ALT-0003"],
        )
        alert = store.get_alert("ALT-0003")
        assert alert.incident_id == inc.id


# ---------------------------------------------------------------------------
# BUG 2 — Meaningful title generation (not generic)
# ---------------------------------------------------------------------------

class TestMeaningfulTitleGeneration:
    """Title/summary must be generated from actual alert data, not generic text."""

    def test_seeded_incident_has_meaningful_title(self, store):
        """INC-0001 (seeded) must not have a generic title."""
        inc = store.get_incident("INC-0001")
        assert inc is not None
        assert "Escalated:" not in inc.title
        assert inc.title == "Multi-Vector Cloud Perimeter & Credential Compromise"

    def test_new_incident_accepts_custom_title(self, store):
        inc = store.create_incident(
            title="Public S3 Bucket Exposure — student-records-demo",
            severity=IncidentSeverity.CRITICAL,
            summary="Custom meaningful summary",
        )
        assert inc.title == "Public S3 Bucket Exposure — student-records-demo"

    def test_incident_summary_not_generic(self, store):
        """Summary must contain actual security context, not just 'Escalated from alert X'."""
        inc = store.get_incident("INC-0001")
        assert len(inc.summary) > 50  # Must be substantive
        assert "Simultaneous detection" in inc.summary  # Contains real context


# ---------------------------------------------------------------------------
# BUG 5 — Duplicate escalation prevention
# ---------------------------------------------------------------------------

class TestDuplicateEscalationPrevention:
    """Escalating the same alert twice must not create duplicate incidents."""

    def test_duplicate_escalation_returns_existing_incident(self, store):
        """ALT-0001 is already linked to INC-0001. Re-escalating must return INC-0001."""
        alert = store.get_alert("ALT-0001")
        assert alert.incident_id == "INC-0001"  # Already escalated during seed

        # Attempt to create another incident for the same alert
        inc = store.create_incident(
            title="Duplicate attempt",
            severity=IncidentSeverity.CRITICAL,
            summary="Should not create a new incident",
            linked_alert_ids=["ALT-0001"],
        )
        assert inc.id == "INC-0001"  # Must return existing, not create new

    def test_unescalated_alert_creates_new_incident(self, store):
        """ALT-0003 has no incident — escalation must create a new one."""
        alert = store.get_alert("ALT-0003")
        assert alert.incident_id is None  # Not yet escalated

        inc = store.create_incident(
            title="New incident for SSH alert",
            severity=IncidentSeverity.HIGH,
            summary="SSH exposure incident",
            linked_alert_ids=["ALT-0003"],
        )
        assert inc.id != "INC-0001"  # Must be a new incident

    def test_missing_alert_id_does_not_crash(self, store):
        """Linking to a nonexistent alert ID must not crash."""
        inc = store.create_incident(
            title="Test",
            severity=IncidentSeverity.HIGH,
            summary="Test",
            linked_alert_ids=["ALT-9999"],
        )
        assert inc.id  # Must succeed (just won't link)


# ---------------------------------------------------------------------------
# BUG 5 — Persistence and timeline
# ---------------------------------------------------------------------------

class TestEscalationPersistence:
    """Incidents must persist and be retrievable after creation."""

    def test_incident_retrievable_after_creation(self, store):
        inc = store.create_incident(
            title="Persistence test",
            severity=IncidentSeverity.MEDIUM,
            summary="Test",
        )
        retrieved = store.get_incident(inc.id)
        assert retrieved is not None
        assert retrieved.title == "Persistence test"

    def test_incident_timeline_has_creation_entry(self, store):
        inc = store.create_incident(
            title="Timeline test",
            severity=IncidentSeverity.HIGH,
            summary="Test",
            lead_responder="Test Lead",
        )
        assert len(inc.timeline) >= 1
        assert "created" in inc.timeline[0]["event"].lower()

    def test_nonexistent_incident_returns_none(self, store):
        assert store.get_incident("INC-9999") is None


# ---------------------------------------------------------------------------
# API-level escalation tests
# ---------------------------------------------------------------------------

class TestEscalationAPI:
    """Test the escalation endpoint via Flask test client."""

    @pytest.fixture
    def client(self):
        from app import app as flask_app
        flask_app.config["TESTING"] = True
        with flask_app.test_client() as c:
            yield c

    @pytest.fixture
    def api_key(self):
        from backend.security import get_active_api_key
        return get_active_api_key()

    @pytest.fixture
    def fresh_alert(self):
        from backend.soc.store import soc_store
        from backend.soc.models import AlertSeverity
        return soc_store.create_alert(
            title=f"Unrestricted Inbound SSH Test {time.time()}",
            severity=AlertSeverity.HIGH,
            affected_resource=f"ec2/security-group/sg-test-{time.time()}",
            detection_source="Rule Engine (CIS 5.2)",
            category="Network Exposure",
            rule_ref="CIS 5.2 / MITRE T1133",
            trigger_reason="Security group permits TCP port 22 from CIDR 0.0.0.0/0 without restrictions.",
            risk_score=85,
            evidence={"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"},
        )

    def test_escalate_produces_meaningful_title(self, client, api_key, fresh_alert):
        """POST /api/alerts/<id>/escalate must produce a meaningful title."""
        resp = client.post(
            f"/api/alerts/{fresh_alert.id}/escalate",
            json={},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert "incident" in data
        inc = data["incident"]
        assert "Escalated:" not in inc["title"]
        assert "Unrestricted" in inc["title"] or "SSH" in inc["title"] or "sg-" in inc["title"]

    def test_escalate_includes_escalation_evidence(self, client, api_key, fresh_alert):
        """Escalation evidence must be captured in the incident."""
        resp = client.post(
            f"/api/alerts/{fresh_alert.id}/escalate",
            json={},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        inc = data["incident"]
        assert inc.get("escalation_evidence") is not None
        assert inc["escalation_evidence"]["source_alert_id"] == fresh_alert.id
        assert inc["escalation_evidence"]["detection_source"] != ""
        assert inc["escalation_evidence"]["rule_ref"] != ""
        assert inc["escalation_evidence"]["trigger_reason"] != ""
        assert "evidence" in inc["escalation_evidence"]

    def test_escalate_includes_mitre_technique(self, client, api_key, fresh_alert):
        """If rule_ref contains MITRE, it must be extracted to mitre_technique."""
        resp = client.post(
            f"/api/alerts/{fresh_alert.id}/escalate",
            json={},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        inc = data["incident"]
        assert inc.get("mitre_technique") == "MITRE T1133"

    def test_escalate_nonexistent_alert_returns_404(self, client, api_key):
        resp = client.post(
            "/api/alerts/ALT-9999/escalate",
            json={},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 404

    def test_escalate_without_auth_returns_401(self, client, fresh_alert):
        resp = client.post(
            f"/api/alerts/{fresh_alert.id}/escalate",
            json={},
        )
        assert resp.status_code == 401

    def test_duplicate_escalation_returns_existing(self, client, api_key):
        """Escalating ALT-0001 (already in INC-0001) must return the existing incident."""
        resp = client.post(
            "/api/alerts/ALT-0001/escalate",
            json={},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get("duplicate") is True
        assert data["incident"]["id"] == "INC-0001"

    def test_escalate_summary_contains_real_data(self, client, api_key, fresh_alert):
        """Summary must reference actual alert context, not just alert ID."""
        resp = client.post(
            f"/api/alerts/{fresh_alert.id}/escalate",
            json={},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        inc = data["incident"]
        assert "Risk Score" in inc["summary"] or "Root Cause" in inc["summary"]
        assert len(inc["summary"]) > 60  # Must be substantive
