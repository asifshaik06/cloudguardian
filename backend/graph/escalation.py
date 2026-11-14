"""Privilege Escalation Pathfinding Engine for CloudGuardian 2.0.

Analyzes the IAM capability graph to discover privilege escalation vectors,
role-assumption chains, and direct paths to administrative control or sensitive assets.
Implements detection for classic AWS privilege escalation primitives (MITRE ATT&CK T1548.005, T1098, T1078.004).
"""
import logging
from typing import Any, Dict, List, Optional, Set
import networkx as nx

from backend.graph.iam_graph import IAMCapabilityGraph, NodeType, EdgeType

logger = logging.getLogger("cloudguardian.graph.escalation")

# MITRE ATT&CK Mapping for privilege escalation primitives
ESCALATION_MITRE: Dict[str, Dict[str, str]] = {
    "AssumesRole": {
        "id": "T1078.004",
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Privilege Escalation, Defense Evasion",
        "description": "Principal assumes an existing IAM role with broader permissions.",
    },
    "PassRole": {
        "id": "T1548.005",
        "name": "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Privileges",
        "tactic": "Privilege Escalation",
        "description": "Principal passes an elevated role to a compute resource (EC2, Lambda) to execute code with that role's permissions.",
    },
    "CanEscalateTo": {
        "id": "T1098",
        "name": "Account Manipulation: Additional Cloud Credentials",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Principal modifies IAM policies or attaches administrative policies.",
    },
    "CanAccessResource": {
        "id": "T1530",
        "name": "Data from Cloud Storage Object",
        "tactic": "Collection",
        "description": "Principal accesses or modifies confidential cloud storage.",
    },
}


class AttackPath:
    """Represents a discovered multi-hop attack or privilege escalation path."""

    def __init__(
        self,
        source_id: str,
        target_id: str,
        nodes: List[str],
        edges: List[Dict[str, Any]],
        is_admin_escalation: bool = False,
        reaches_sensitive_data: bool = False,
    ) -> None:
        self.source_id = source_id
        self.target_id = target_id
        self.nodes = nodes
        self.edges = edges
        self.is_admin_escalation = is_admin_escalation
        self.reaches_sensitive_data = reaches_sensitive_data
        self.hop_count = max(0, len(nodes) - 1)

    def to_dict(self) -> Dict[str, Any]:
        """Convert attack path to dictionary for API serialization and dashboard display."""
        # Calculate risk score (0-100) based on severity and hop count
        # Shorter paths to admin/sensitive data are higher risk
        base_points = 90 if self.is_admin_escalation else (75 if self.reaches_sensitive_data else 50)
        hop_penalty = min(20, self.hop_count * 4)
        risk_score = max(10, base_points - hop_penalty)

        steps = []
        for i, edge in enumerate(self.edges):
            u = self.nodes[i]
            v = self.nodes[i + 1]
            rel = edge.get("relationship", "RelatesTo")
            mitre_info = ESCALATION_MITRE.get(rel, {
                "id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Privilege Escalation",
                "description": "Lateral or elevated capability transition.",
            })
            steps.append({
                "step": i + 1,
                "source": u,
                "target": v,
                "relationship": rel,
                "actions": edge.get("actions", []),
                "evidence": edge.get("evidence", {}),
                "mitre": mitre_info,
            })

        return {
            "source": self.source_id,
            "target": self.target_id,
            "hops": self.hop_count,
            "nodes": self.nodes,
            "is_admin_escalation": self.is_admin_escalation,
            "reaches_sensitive_data": self.reaches_sensitive_data,
            "risk_score": risk_score,
            "severity": "Critical" if (self.is_admin_escalation or self.reaches_sensitive_data) else "High",
            "steps": steps,
            "narrative": self.generate_narrative(),
        }

    def generate_narrative(self) -> str:
        """Produce an explainable, plain-English summary of how this escalation path works."""
        if not self.edges:
            return f"Identity {self.source_id} has direct access."

        parts = [f"Attack Path from {self.source_id} to {self.target_id} ({self.hop_count} hops):"]
        for i, edge in enumerate(self.edges):
            u = self.nodes[i]
            v = self.nodes[i + 1]
            rel = edge.get("relationship", "")
            actions = edge.get("actions", [])
            act_str = f" via {', '.join(actions[:3])}" if actions else ""

            if rel == EdgeType.ASSUMES_ROLE.value:
                parts.append(f"  Step {i+1}: {u} assumes role {v}{act_str}.")
            elif rel == EdgeType.PASS_ROLE.value:
                parts.append(f"  Step {i+1}: {u} passes role {v} to compute resources to execute with elevated rights.")
            elif rel == EdgeType.CAN_ESCALATE.value:
                parts.append(f"  Step {i+1}: {u} escalates privileges to {v}{act_str}.")
            elif rel == EdgeType.CAN_ACCESS.value:
                parts.append(f"  Step {i+1}: {u} accesses target resource {v}{act_str}.")
            elif rel == EdgeType.HAS_POLICY.value:
                parts.append(f"  Step {i+1}: {u} possesses attached policy {v}.")
            else:
                parts.append(f"  Step {i+1}: {u} transitions to {v} ({rel}).")

        if self.is_admin_escalation:
            parts.append("Impact: Grants full administrative control over the cloud environment.")
        elif self.reaches_sensitive_data:
            parts.append("Impact: Exposes confidential data or audit logs to unauthorized access.")

        return "\n".join(parts)


def find_escalation_paths(
    graph_engine: IAMCapabilityGraph,
    source_id: str,
    target_id: Optional[str] = None,
    target_admin_only: bool = False,
    cutoff: int = 5,
) -> List[Dict[str, Any]]:
    """Discover all reachable attack/escalation paths from a source principal.

    Args:
        graph_engine: IAMCapabilityGraph instance.
        source_id: Source node identifier (e.g. 'user/intern-dev').
        target_id: Specific target node identifier. If None, targets all Admin roles and sensitive resources.
        target_admin_only: If True, only search for paths leading to is_admin=True roles.
        cutoff: Maximum hops allowed in path search (prevents infinite traversal).

    Returns:
        List of AttackPath dictionaries sorted by severity and shortest hop count.
    """
    g = graph_engine.graph
    if not g.has_node(source_id):
        logger.warning("Source node %s not found in graph.", source_id)
        return []

    # Determine targets
    targets: Set[str] = set()
    if target_id:
        if g.has_node(target_id):
            targets.add(target_id)
    else:
        for n, data in g.nodes(data=True):
            if n == source_id:
                continue
            is_adm = data.get("is_admin", False)
            is_sens = data.get("is_sensitive", False)
            if target_admin_only:
                if is_adm:
                    targets.add(n)
            else:
                if is_adm or is_sens:
                    targets.add(n)

    discovered_paths: List[AttackPath] = []

    for tgt in targets:
        try:
            # Find all simple directed paths up to cutoff
            paths = list(nx.all_simple_paths(g, source=source_id, target=tgt, cutoff=cutoff))
            for p in paths:
                # Collect edge metadata along path
                edge_metadata: List[Dict[str, Any]] = []
                for i in range(len(p) - 1):
                    u = p[i]
                    v = p[i + 1]
                    e_data = dict(g[u][v]) if g.has_edge(u, v) else {}
                    edge_metadata.append(e_data)

                tgt_data = g.nodes[tgt]
                is_adm = tgt_data.get("is_admin", False) or any(
                    g.nodes[node].get("is_admin", False) for node in p
                )
                is_sens = tgt_data.get("is_sensitive", False) or any(
                    g.nodes[node].get("is_sensitive", False) for node in p
                )

                attack_path = AttackPath(
                    source_id=source_id,
                    target_id=tgt,
                    nodes=p,
                    edges=edge_metadata,
                    is_admin_escalation=is_adm,
                    reaches_sensitive_data=is_sens,
                )
                discovered_paths.append(attack_path)

        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue

    # Sort paths: admin escalations first, then sensitive data, then shortest hops
    discovered_paths.sort(
        key=lambda ap: (
            0 if ap.is_admin_escalation else 1,
            0 if ap.reaches_sensitive_data else 1,
            ap.hop_count,
        )
    )

    return [ap.to_dict() for ap in discovered_paths]


def find_all_escalation_paths(
    graph_engine: IAMCapabilityGraph,
    cutoff: int = 5,
) -> Dict[str, List[Dict[str, Any]]]:
    """Scan all IAM User and Role nodes in the graph for potential privilege escalations.

    Returns:
        Mapping of {principal_id: [AttackPath dict, ...]}
    """
    results: Dict[str, List[Dict[str, Any]]] = {}
    g = graph_engine.graph

    for n_id, data in g.nodes(data=True):
        cat = data.get("category")
        if cat in (NodeType.USER, NodeType.ROLE):
            paths = find_escalation_paths(
                graph_engine=graph_engine,
                source_id=n_id,
                target_admin_only=False,
                cutoff=cutoff,
            )
            if paths:
                results[n_id] = paths

    return results
