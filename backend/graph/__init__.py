"""IAM Capability Graph and Attack-Path Intelligence package for ThreatGuard.

Provides:
- Directed graph representation of IAM principals, policies, and AWS resources.
- Privilege escalation pathfinding across AWS permission relationships.
- Dynamic blast radius computation.
- Force-directed ECharts graph serialization.
- REST API endpoints for graph and threat intelligence.
"""
from backend.graph.iam_graph import IAMCapabilityGraph, NodeType, EdgeType
from backend.graph.escalation import (
    find_escalation_paths,
    find_all_escalation_paths,
    AttackPath,
)
from backend.graph.blast_radius import calculate_blast_radius, BlastRadiusReport
from backend.graph.api import register_graph_api

__all__ = [
    "IAMCapabilityGraph",
    "NodeType",
    "EdgeType",
    "find_escalation_paths",
    "find_all_escalation_paths",
    "AttackPath",
    "calculate_blast_radius",
    "BlastRadiusReport",
    "register_graph_api",
]
