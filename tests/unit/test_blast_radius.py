"""Unit tests for Dynamic Blast-Radius Engine."""
import pytest
from backend.graph.iam_graph import IAMCapabilityGraph, NodeType, EdgeType
from backend.graph.blast_radius import calculate_blast_radius


@pytest.fixture
def populated_graph() -> IAMCapabilityGraph:
    g = IAMCapabilityGraph()
    g.seed_default_topology()
    return g


def test_calculate_blast_radius_intern_dev(populated_graph: IAMCapabilityGraph):
    report = calculate_blast_radius(populated_graph, "user/intern-dev")
    data = report.to_dict()

    assert data["target_id"] == "user/intern-dev"
    assert data["admin_reachable"] is True
    assert data["score"] >= 75.0
    assert data["severity"] == "Critical"
    assert data["max_propagation_depth"] >= 2

    # Sensitive student records should be among exposed resources
    assert "s3/student-records-demo" in data["sensitive_resources_exposed"]
    assert "s3/main-trail-bucket" in data["sensitive_resources_exposed"]

    # Reachable principals should include dev-role, cicd-deployer, admin-role
    assert "role/dev-role" in data["reachable_principals"]
    assert "role/admin-role" in data["reachable_principals"]

    # Recommendations should address admin escalation and sensitive resources
    assert len(data["recommendations"]) >= 2
    assert any("AdministratorAccess" in r for r in data["recommendations"])


def test_calculate_blast_radius_isolated_node():
    g = IAMCapabilityGraph()
    g.add_resource("s3/isolated-bucket", "isolated-bucket", NodeType.S3, is_sensitive=False)

    report = calculate_blast_radius(g, "s3/isolated-bucket")
    data = report.to_dict()

    assert data["admin_reachable"] is False
    assert len(data["reachable_principals"]) == 0
    assert data["max_propagation_depth"] == 0
    assert data["score"] <= 25.0


def test_calculate_blast_radius_nonexistent_node(populated_graph: IAMCapabilityGraph):
    report = calculate_blast_radius(populated_graph, "user/nonexistent")
    data = report.to_dict()

    assert data["total_reachable_nodes"] == 0
    assert data["score"] == 0.0
    assert data["severity"] == "Low"
