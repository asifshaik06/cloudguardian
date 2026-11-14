"""Integration tests for CloudGuardian IAM Capability Graph and Attack-Path API endpoints."""
import pytest
from app import app as flask_app, iam_graph
from backend.security import AUTH_HEADER, get_active_api_key


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers():
    return {AUTH_HEADER: get_active_api_key()}


def test_get_graph_echarts_format(client):
    resp = client.get("/api/graph")
    assert resp.status_code == 200
    data = resp.get_json()

    assert "nodes" in data
    assert "links" in data
    assert "categories" in data
    assert "stats" in data

    # Check categories
    cat_names = [c["name"] for c in data["categories"]]
    assert "IAM User" in cat_names
    assert "IAM Role" in cat_names
    assert "S3 Bucket" in cat_names

    # Check node structure
    assert len(data["nodes"]) >= 5
    for node in data["nodes"]:
        assert "id" in node
        assert "name" in node
        assert "category" in node
        assert "symbolSize" in node
        assert "itemStyle" in node

    # Check link structure
    assert len(data["links"]) >= 4
    for link in data["links"]:
        assert "source" in link
        assert "target" in link
        assert "relationship" in link
        assert "lineStyle" in link


def test_get_graph_with_highlight_path(client):
    hl = "user/intern-dev,role/dev-role"
    resp = client.get(f"/api/graph?highlight={hl}")
    assert resp.status_code == 200
    data = resp.get_json()

    highlighted_nodes = [n for n in data["nodes"] if n["in_attack_path"]]
    assert len(highlighted_nodes) == 2

    highlighted_links = [l for l in data["links"] if l["in_attack_path"]]
    assert len(highlighted_links) >= 1
    assert any(l["source"] == "user/intern-dev" and l["target"] == "role/dev-role" for l in highlighted_links)


def test_get_paths_for_intern_dev(client):
    resp = client.get("/api/graph/paths/user/intern-dev")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["principal_id"] == "user/intern-dev"
    assert data["total_paths"] > 0
    assert "paths" in data

    first_path = data["paths"][0]
    assert "source" in first_path
    assert "target" in first_path
    assert "hops" in first_path
    assert "risk_score" in first_path
    assert "severity" in first_path
    assert "steps" in first_path
    assert "narrative" in first_path
    assert len(first_path["narrative"]) > 0


def test_get_paths_admin_only_filter(client):
    resp = client.get("/api/graph/paths/user/intern-dev?admin_only=1")
    assert resp.status_code == 200
    data = resp.get_json()

    for path in data["paths"]:
        assert path["is_admin_escalation"] is True


def test_get_all_paths(client):
    resp = client.get("/api/graph/all-paths")
    assert resp.status_code == 200
    data = resp.get_json()

    assert "total_escalations" in data
    assert data["total_escalations"] > 0
    assert "escalations" in data
    assert "user/intern-dev" in data["escalations"]


def test_get_blast_radius(client):
    resp = client.get("/api/graph/blast-radius/user/intern-dev")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["target_id"] == "user/intern-dev"
    assert "score" in data
    assert "severity" in data
    assert "admin_reachable" in data
    assert "reachable_principals" in data
    assert "reachable_resources" in data
    assert "sensitive_resources_exposed" in data
    assert "recommendations" in data
    assert len(data["recommendations"]) > 0


def test_get_graph_stats(client):
    resp = client.get("/api/graph/stats")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["total_nodes"] >= 5
    assert data["total_edges"] >= 4
    assert data["users"] >= 1
    assert data["roles"] >= 1
    assert data["s3_buckets"] >= 1


def test_finding_detail_includes_graph_blast_radius(client, auth_headers):
    # First trigger finding for s3 or key in simulation mode
    resp = client.post("/api/attack/key", headers=auth_headers)
    assert resp.status_code == 200

    finding_resp = client.get("/api/finding/key")
    assert finding_resp.status_code == 200
    fdata = finding_resp.get_json()

    assert "risk" in fdata
    assert "blast_radius" in fdata
    assert fdata["blast_radius"] is not None
    assert fdata["blast_radius"]["target_id"] == "user/intern-dev"

    # Verify risk rows contain IAM blast radius
    risk_names = [r["name"] for r in fdata["risk"]["rows"]]
    assert "IAM blast radius" in risk_names
