"""Unit tests for Privilege Escalation Pathfinding Engine."""
import pytest
from backend.graph.iam_graph import IAMCapabilityGraph, NodeType, EdgeType
from backend.graph.escalation import (
    find_escalation_paths,
    find_all_escalation_paths,
    AttackPath,
)


@pytest.fixture
def populated_graph() -> IAMCapabilityGraph:
    g = IAMCapabilityGraph()
    g.seed_default_topology()
    return g


def test_find_escalation_paths_from_intern_dev(populated_graph: IAMCapabilityGraph):
    paths = find_escalation_paths(
        populated_graph,
        source_id="user/intern-dev",
        target_admin_only=False,
        cutoff=5,
    )

    assert len(paths) > 0

    # Ensure path to admin-role is discovered
    admin_paths = [p for p in paths if p["target"] == "role/admin-role"]
    assert len(admin_paths) > 0
    top_admin_path = admin_paths[0]

    assert top_admin_path["is_admin_escalation"] is True
    assert top_admin_path["source"] == "user/intern-dev"
    assert "user/intern-dev" in top_admin_path["nodes"]
    assert "role/admin-role" in top_admin_path["nodes"]

    # Verify steps contain relationships
    assert len(top_admin_path["steps"]) == top_admin_path["hops"]
    assert top_admin_path["steps"][0]["relationship"] == EdgeType.ASSUMES_ROLE.value

    # Verify plain-English narrative
    assert "Attack Path from user/intern-dev to role/admin-role" in top_admin_path["narrative"]
    assert "Impact:" in top_admin_path["narrative"]


def test_find_escalation_paths_to_sensitive_s3(populated_graph: IAMCapabilityGraph):
    paths = find_escalation_paths(
        populated_graph,
        source_id="user/intern-dev",
        target_id="s3/student-records-demo",
        cutoff=5,
    )

    assert len(paths) > 0
    p = paths[0]
    assert p["target"] == "s3/student-records-demo"
    assert p["reaches_sensitive_data"] is True
    assert p["severity"] == "Critical"


def test_target_admin_only(populated_graph: IAMCapabilityGraph):
    paths = find_escalation_paths(
        populated_graph,
        source_id="user/intern-dev",
        target_admin_only=True,
        cutoff=5,
    )

    # All returned paths must target an admin node
    for p in paths:
        assert p["is_admin_escalation"] is True


def test_find_all_escalation_paths(populated_graph: IAMCapabilityGraph):
    all_escalations = find_all_escalation_paths(populated_graph, cutoff=4)

    assert "user/intern-dev" in all_escalations
    assert len(all_escalations["user/intern-dev"]) > 0


def test_nonexistent_node_returns_empty(populated_graph: IAMCapabilityGraph):
    paths = find_escalation_paths(
        populated_graph,
        source_id="user/nonexistent",
        cutoff=3,
    )
    assert paths == []
