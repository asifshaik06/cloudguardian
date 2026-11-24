"""Dynamic Attack Blast-Radius Engine for ThreatGuard.

Calculates the lateral movement scope, accessible cloud assets, and potential
administrative exposure if an IAM identity or cloud resource is compromised.
"""
import logging
from typing import Any, Dict, List, Optional, Set
import networkx as nx

from backend.graph.iam_graph import IAMCapabilityGraph, NodeType, EdgeType

logger = logging.getLogger("threatguard.graph.blast_radius")


class BlastRadiusReport:
    """Encapsulates the blast radius assessment for a compromised identity or resource."""

    def __init__(
        self,
        target_id: str,
        total_reachable_nodes: int,
        reachable_principals: List[str],
        reachable_resources: List[str],
        sensitive_resources_exposed: List[str],
        admin_reachable: bool,
        max_propagation_depth: int,
        score: float,
        severity: str,
        recommendations: List[str],
    ) -> None:
        self.target_id = target_id
        self.total_reachable_nodes = total_reachable_nodes
        self.reachable_principals = reachable_principals
        self.reachable_resources = reachable_resources
        self.sensitive_resources_exposed = sensitive_resources_exposed
        self.admin_reachable = admin_reachable
        self.max_propagation_depth = max_propagation_depth
        self.score = score
        self.severity = severity
        self.recommendations = recommendations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "score": round(self.score, 1),
            "severity": self.severity,
            "admin_reachable": self.admin_reachable,
            "max_propagation_depth": self.max_propagation_depth,
            "total_reachable_nodes": self.total_reachable_nodes,
            "reachable_principals": self.reachable_principals,
            "reachable_resources": self.reachable_resources,
            "sensitive_resources_exposed": self.sensitive_resources_exposed,
            "recommendations": self.recommendations,
            "summary": (
                f"Compromise of {self.target_id} exposes {len(self.reachable_resources)} resources "
                f"({len(self.sensitive_resources_exposed)} sensitive) and "
                f"{len(self.reachable_principals)} identities with a max propagation depth of "
                f"{self.max_propagation_depth} hops. "
                f"{'Administrative control is reachable.' if self.admin_reachable else 'Administrative control is not directly reachable.'}"
            ),
        }


def calculate_blast_radius(
    graph_engine: IAMCapabilityGraph,
    principal_or_resource_id: str,
) -> BlastRadiusReport:
    """Compute the transitive attack blast radius from a specified node.

    Args:
        graph_engine: IAMCapabilityGraph instance.
        principal_or_resource_id: Identifier of the compromised node (e.g. 'user/intern-dev').

    Returns:
        BlastRadiusReport with metrics, risk score, and mitigation recommendations.
    """
    g = graph_engine.graph
    if not g.has_node(principal_or_resource_id):
        logger.warning("Node %s not in graph for blast radius calculation.", principal_or_resource_id)
        return BlastRadiusReport(
            target_id=principal_or_resource_id,
            total_reachable_nodes=0,
            reachable_principals=[],
            reachable_resources=[],
            sensitive_resources_exposed=[],
            admin_reachable=False,
            max_propagation_depth=0,
            score=0.0,
            severity="Low",
            recommendations=["Verify entity exists in IAM inventory."],
        )

    # Compute all reachable nodes via directed paths
    try:
        descendants = nx.descendants(g, principal_or_resource_id)
    except Exception as exc:
        logger.error("Error calculating descendants for %s: %s", principal_or_resource_id, exc)
        descendants = set()

    reachable_nodes = descendants | {principal_or_resource_id}

    reachable_principals: List[str] = []
    reachable_resources: List[str] = []
    sensitive_resources: List[str] = []
    admin_reachable: bool = False
    max_depth: int = 0

    for node_id in reachable_nodes:
        data = g.nodes[node_id]
        cat = data.get("category")
        is_adm = data.get("is_admin", False)
        is_sens = data.get("is_sensitive", False)

        if is_adm:
            admin_reachable = True

        if cat in (NodeType.USER, NodeType.ROLE, NodeType.GROUP):
            if node_id != principal_or_resource_id:
                reachable_principals.append(node_id)
        elif cat in (NodeType.S3, NodeType.EC2, NodeType.KMS):
            reachable_resources.append(node_id)
            if is_sens:
                sensitive_resources.append(node_id)

        # Calculate shortest path depth from source
        if node_id != principal_or_resource_id:
            try:
                path_len = nx.shortest_path_length(g, principal_or_resource_id, node_id)
                if path_len > max_depth:
                    max_depth = path_len
            except nx.NetworkXNoPath:
                pass

    # Score calculation (0 - 100)
    score: float = 0.0

    # 1. Admin escalation exposure: up to 45 points
    if admin_reachable:
        # Shorter distance to admin -> higher immediate threat
        score += 45.0
    elif any("admin" in p.lower() for p in reachable_principals):
        score += 30.0

    # 2. Sensitive resource exposure: up to 30 points
    sens_count = len(sensitive_resources)
    score += min(30.0, sens_count * 15.0)

    # 3. Lateral movement capability: up to 15 points
    princ_count = len(reachable_principals)
    score += min(15.0, princ_count * 5.0)

    # 4. Total reachable resources: up to 10 points
    res_count = len(reachable_resources)
    score += min(10.0, res_count * 3.0)

    score = min(100.0, max(5.0, score))

    # Severity classification
    if score >= 75.0 or admin_reachable:
        severity = "Critical"
    elif score >= 50.0:
        severity = "High"
    elif score >= 25.0:
        severity = "Medium"
    else:
        severity = "Low"

    # Actionable remediation recommendations
    recommendations: List[str] = []
    if admin_reachable:
        recommendations.append("Immediately revoke privilege-escalation trust policies leading to AdministratorAccess.")
    if sensitive_resources:
        recommendations.append(f"Restrict IAM permissions to sensitive resources: {', '.join(sensitive_resources)}.")
    if reachable_principals:
        recommendations.append("Apply Service Control Policies (SCPs) and permission boundaries to limit role assumption.")
    if max_depth > 1:
        recommendations.append(f"Break multi-hop lateral movement chains ({max_depth} hops identified).")

    return BlastRadiusReport(
        target_id=principal_or_resource_id,
        total_reachable_nodes=len(reachable_nodes),
        reachable_principals=sorted(reachable_principals),
        reachable_resources=sorted(reachable_resources),
        sensitive_resources_exposed=sorted(sensitive_resources),
        admin_reachable=admin_reachable,
        max_propagation_depth=max_depth,
        score=score,
        severity=severity,
        recommendations=recommendations,
    )
