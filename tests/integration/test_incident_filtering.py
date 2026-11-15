"""Tests for incident list Active/All filtering (BUG 4)."""
import pytest
from backend.soc.models import IncidentSeverity, IncidentStatus
from backend.soc.store import SOCStore


@pytest.fixture
def store():
    return SOCStore()


# ---------------------------------------------------------------------------
# BUG 4 — Active incidents exclude Closed
# ---------------------------------------------------------------------------

class TestIncidentFiltering:
    """Active Incidents must exclude Closed; All Incidents must include everything."""

    def test_active_view_excludes_closed(self, store):
        """list_incidents(exclude_closed=True) must not return Closed incidents."""
        # Close the seeded incident
        store.update_incident("INC-0001", new_status=IncidentStatus.CLOSED, closure_reason="Resolved")

        active = store.list_incidents(exclude_closed=True)
        all_inc = store.list_incidents(exclude_closed=False)

        assert len(active) < len(all_inc)
        for inc in active:
            assert inc["status"] != "Closed"

    def test_all_view_includes_closed(self, store):
        """list_incidents(exclude_closed=False) must include Closed incidents."""
        store.update_incident("INC-0001", new_status=IncidentStatus.CLOSED, closure_reason="Resolved")

        all_inc = store.list_incidents(exclude_closed=False)
        statuses = [i["status"] for i in all_inc]
        assert "Closed" in statuses

    def test_severity_filter(self, store):
        """Filtering by severity must return only matching incidents."""
        critical = store.list_incidents(severity="Critical")
        for inc in critical:
            assert inc["severity"] == "Critical"

    def test_status_filter(self, store):
        """Filtering by explicit status must work."""
        triage = store.list_incidents(status="Triage")
        for inc in triage:
            assert inc["status"] == "Triage"

    def test_closing_incident_updates_active_count(self, store):
        """After closing, the incident must disappear from active view."""
        before = store.list_incidents(exclude_closed=True)
        before_count = len(before)

        store.update_incident("INC-0001", new_status=IncidentStatus.CLOSED, closure_reason="Test")

        after = store.list_incidents(exclude_closed=True)
        assert len(after) == before_count - 1

    def test_default_list_returns_all(self, store):
        """Default list_incidents() without exclude_closed returns everything."""
        all_inc = store.list_incidents()
        assert len(all_inc) >= 1


# ---------------------------------------------------------------------------
# API-level filtering tests
# ---------------------------------------------------------------------------

class TestIncidentFilteringAPI:
    """Test /api/incidents endpoint with view parameter."""

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

    def test_active_view_default(self, client):
        """GET /api/incidents (default) should return active_count and total_count."""
        resp = client.get("/api/incidents")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "active_count" in data
        assert "total_count" in data
        assert data["active_count"] <= data["total_count"]

    def test_active_view_excludes_closed(self, client, api_key):
        """Close an incident, then verify active view excludes it."""
        # Close INC-0001
        client.post(
            "/api/incidents/INC-0001/action",
            json={"status": "Closed", "closure_reason": "Test"},
            headers={"X-API-Key": api_key},
        )
        # Active view
        resp = client.get("/api/incidents?view=active")
        data = resp.get_json()
        inc_ids = [i["id"] for i in data["incidents"]]
        assert "INC-0001" not in inc_ids

        # All view must still include it
        resp_all = client.get("/api/incidents?view=all")
        data_all = resp_all.get_json()
        inc_ids_all = [i["id"] for i in data_all["incidents"]]
        assert "INC-0001" in inc_ids_all

    def test_severity_filter_api(self, client):
        """GET /api/incidents?severity=Critical must return only Critical."""
        resp = client.get("/api/incidents?view=all&severity=Critical")
        data = resp.get_json()
        for inc in data["incidents"]:
            assert inc["severity"] == "Critical"

    def test_incident_detail_enriched(self, client):
        """GET /api/incidents/INC-0001 must include linked_alerts_detail."""
        resp = client.get("/api/incidents/INC-0001")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "linked_alerts_detail" in data
        assert "linked_remediations_detail" in data
        assert len(data["linked_alerts_detail"]) > 0
        # Each linked alert detail must have key fields
        ad = data["linked_alerts_detail"][0]
        assert "title" in ad
        assert "detection_source" in ad
        assert "risk_score" in ad

    def test_incident_detail_404(self, client):
        resp = client.get("/api/incidents/INC-9999")
        assert resp.status_code == 404

    def test_counts_match_filtered_results(self, client):
        """The 'total' field must match the actual number of returned incidents."""
        resp = client.get("/api/incidents?view=all")
        data = resp.get_json()
        assert data["total"] == len(data["incidents"])
