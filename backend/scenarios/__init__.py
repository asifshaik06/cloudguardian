"""IAM Attack Simulation Lab Module for CloudGuardian 2.0.

Provides isolated attack scenario modeling, deterministic IAM policy evaluation,
predefined scenario catalog, dynamic scenario builder, and independent verification.
"""
from backend.scenarios.models import (
    IdentitySpec,
    PathClassification,
    PolicySpec,
    RelationshipSpec,
    ResourceSpec,
    RunStatus,
    ScenarioCategory,
    ScenarioDefinition,
    ScenarioDifficulty,
    ScenarioFinding,
    ScenarioRun,
    StatementSpec,
)
from backend.scenarios.session import (
    ScenarioSessionManager,
    scenario_session_manager,
)

__all__ = [
    "IdentitySpec",
    "PathClassification",
    "PolicySpec",
    "RelationshipSpec",
    "ResourceSpec",
    "RunStatus",
    "ScenarioCategory",
    "ScenarioDefinition",
    "ScenarioDifficulty",
    "ScenarioFinding",
    "ScenarioRun",
    "ScenarioSessionManager",
    "StatementSpec",
    "scenario_session_manager",
]
