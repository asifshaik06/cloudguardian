"""Unit tests for Predefined Scenario Catalog (backend.scenarios.definitions).

Verifies that all 12 predefined scenarios are registered, have complete metadata,
can be instantiated into isolated runs, and yield findings via graph analysis.
"""
import pytest

from backend.scenarios.definitions import (
    get_scenario_by_id,
    get_scenario_catalog,
    list_scenario_summaries,
)
from backend.scenarios.models import ScenarioCategory, ScenarioDifficulty
from backend.scenarios.session import ScenarioSessionManager

EXPECTED_SCENARIO_IDS = [
    "privesc-excessive-iam",
    "privesc-risky-trust",
    "privesc-passrole-ec2",
    "privesc-policy-version",
    "resource-s3-public",
    "resource-s3-wildcard",
    "resource-kms-unrestricted",
    "resource-ec2-ingress-ssh",
    "lateral-compromised-dev",
    "lateral-role-chaining",
    "lateral-create-access-key",
    "defense-evasion-cloudtrail",
]


def test_scenario_catalog_count_and_ids():
    """Verify all 12 predefined scenarios exist in the catalog."""
    catalog = get_scenario_catalog()
    assert len(catalog) == 12
    for s_id in EXPECTED_SCENARIO_IDS:
        assert s_id in catalog, f"Missing scenario: {s_id}"


def test_scenario_summaries():
    """Verify list_scenario_summaries returns valid metadata for dashboard display."""
    summaries = list_scenario_summaries()
    assert len(summaries) == 12

    for summary in summaries:
        assert summary["id"] in EXPECTED_SCENARIO_IDS
        assert len(summary["name"]) > 5
        assert len(summary["description"]) > 10
        assert summary["category"] in [c.value for c in ScenarioCategory]
        assert summary["difficulty"] in [d.value for d in ScenarioDifficulty]
        assert len(summary["mitre_attack"]) >= 1


@pytest.mark.parametrize("scenario_id", EXPECTED_SCENARIO_IDS)
def test_scenario_instantiation_and_analysis(scenario_id):
    """Verify that every predefined scenario instantiates into an isolated run with findings or paths."""
    scenario_def = get_scenario_by_id(scenario_id)
    assert scenario_def is not None

    manager = ScenarioSessionManager()
    run = manager.create_run(scenario_def)

    assert run.run_id.startswith(f"run-{scenario_id}-")
    assert run.status.value in ("initialized", "analyzed")

    # Verify that the scenario produced either attack paths or direct security findings
    has_paths_or_findings = len(run.paths) > 0 or len(run.findings) > 0
    assert has_paths_or_findings, f"Scenario {scenario_id} yielded neither paths nor findings."

    # Verify graph was instantiated and contains nodes
    graph = manager.get_graph(run.run_id)
    assert graph is not None
    assert graph.node_count() >= 1
