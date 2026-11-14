"""Unit tests for ScenarioSessionManager.

Verifies isolated graph instantiation, dynamic path discovery,
blast radius calculation, independent state tracking, and reset capabilities.
"""
import pytest

from backend.scenarios.models import (
    IdentitySpec,
    RelationshipSpec,
    ResourceSpec,
    RunStatus,
    ScenarioCategory,
    ScenarioDefinition,
    ScenarioDifficulty,
)
from backend.scenarios.session import ScenarioSessionManager


@pytest.fixture
def sample_scenario_definition() -> ScenarioDefinition:
    """Create a sample test scenario definition."""
    return ScenarioDefinition(
        id="test-privesc-01",
        name="Test Privilege Escalation",
        description="A test scenario for session isolation and path analysis.",
        category=ScenarioCategory.PRIVILEGE_ESCALATION,
        difficulty=ScenarioDifficulty.BEGINNER,
        learning_objective="Demonstrate session isolation.",
        identities=[
            IdentitySpec(
                id="user/test-dev",
                name="test-dev",
                type="user",
                arn="arn:aws:iam::123456789012:user/test-dev",
                is_admin=False,
            ),
            IdentitySpec(
                id="role/target-admin",
                name="target-admin",
                type="role",
                arn="arn:aws:iam::123456789012:role/target-admin",
                is_admin=True,
            ),
        ],
        resources=[
            ResourceSpec(
                id="s3/confidential-records",
                name="confidential-records",
                type="s3",
                arn="arn:aws:s3:::confidential-records",
                is_sensitive=True,
            ),
        ],
        relationships=[
            RelationshipSpec(
                source_id="user/test-dev",
                target_id="role/target-admin",
                relationship="AssumesRole",
                actions=["sts:AssumeRole"],
            ),
            RelationshipSpec(
                source_id="role/target-admin",
                target_id="s3/confidential-records",
                relationship="CanAccessResource",
                actions=["s3:*"],
            ),
        ],
        is_predefined=False,
    )


def test_create_and_analyze_run(sample_scenario_definition):
    """Verify run creation instantiates isolated graph, discovers paths, and computes blast radius."""
    manager = ScenarioSessionManager()
    run = manager.create_run(sample_scenario_definition)

    assert run.run_id.startswith("run-test-privesc-01-")
    assert run.status in (RunStatus.INITIALIZED, RunStatus.ANALYZED)
    assert len(run.paths) >= 1

    # Check path details
    p = run.paths[0]
    assert p["source_id"] == "user/test-dev"
    assert p["target_id"] in ("role/target-admin", "s3/confidential-records")
    assert p["classification"] == "Confirmed"

    # Check blast radius
    assert run.blast_radius.get("admin_reachable") is True
    assert run.blast_radius.get("score", 0) > 0

    # Check findings
    assert len(run.findings) >= 1
    assert any("Privilege Escalation" in f.title for f in run.findings)


def test_scenario_isolation(sample_scenario_definition):
    """Verify two runs created from same definition operate in strictly isolated graphs."""
    manager = ScenarioSessionManager()
    run_1 = manager.create_run(sample_scenario_definition)
    run_2 = manager.create_run(sample_scenario_definition)

    assert run_1.run_id != run_2.run_id

    g1 = manager.get_graph(run_1.run_id)
    g2 = manager.get_graph(run_2.run_id)

    assert g1 is not g2

    # Mutate g1 by removing an edge
    g1.graph.remove_edge("user/test-dev", "role/target-admin")

    # Verify g2 still possesses the edge intact
    assert not g1.graph.has_edge("user/test-dev", "role/target-admin")
    assert g2.graph.has_edge("user/test-dev", "role/target-admin")

    # Re-analyze run_1: should have 0 paths
    updated_run_1 = manager.analyze_run(run_1.run_id)
    assert len(updated_run_1.paths) == 0

    # Re-analyze run_2: still has attack path
    updated_run_2 = manager.analyze_run(run_2.run_id)
    assert len(updated_run_2.paths) >= 1


def test_reset_run(sample_scenario_definition):
    """Verify resetting a run restores the original topology and clears modifications."""
    manager = ScenarioSessionManager()
    run = manager.create_run(sample_scenario_definition)
    g = manager.get_graph(run.run_id)

    # Mutate graph
    g.graph.remove_edge("user/test-dev", "role/target-admin")
    analyzed_mutated = manager.analyze_run(run.run_id)
    assert len(analyzed_mutated.paths) == 0

    # Reset run
    reset_run = manager.reset_run(run.run_id)
    assert reset_run.status == RunStatus.RESET or reset_run.status == RunStatus.ANALYZED
    assert len(reset_run.paths) >= 1

    # Verify edge was restored
    restored_g = manager.get_graph(run.run_id)
    assert restored_g.graph.has_edge("user/test-dev", "role/target-admin")


def test_delete_run(sample_scenario_definition):
    """Verify run deletion removes state and frees graph."""
    manager = ScenarioSessionManager()
    run = manager.create_run(sample_scenario_definition)
    run_id = run.run_id

    assert manager.get_run(run_id) is not None
    assert manager.get_graph(run_id) is not None

    deleted = manager.delete_run(run_id)
    assert deleted is True

    assert manager.get_run(run_id) is None
    assert manager.get_graph(run_id) is None
    assert manager.delete_run(run_id) is False
