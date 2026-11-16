"""Scenario Session Manager for CloudGuardian 2.0 IAM Attack Simulation Lab.

Manages isolated scenario execution runs, runtime state tracking,
dynamic graph instantiation, path evaluation, and independent verification.
All executions run in memory/isolated Moto simulation without affecting other runs.
"""
import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from backend.graph.blast_radius import calculate_blast_radius
from backend.graph.escalation import find_escalation_paths
from backend.graph.iam_graph import EdgeType, IAMCapabilityGraph, NodeType
from backend.scenarios.models import (
    PathClassification,
    RunStatus,
    ScenarioDefinition,
    ScenarioFinding,
    ScenarioRun,
)

logger = logging.getLogger("cloudguardian.scenarios.session")


class ScenarioSessionManager:
    """Thread-safe manager for isolated attack scenario runs."""

    def __init__(self) -> None:
        self._runs: Dict[str, ScenarioRun] = {}
        self._graphs: Dict[str, IAMCapabilityGraph] = {}
        self._lock = threading.RLock()

    def create_run(self, definition: ScenarioDefinition) -> ScenarioRun:
        """Instantiate an isolated execution run for a scenario definition."""
        with self._lock:
            run_id = f"run-{definition.id}-{uuid.uuid4().hex[:8]}"

            # 1. Create isolated graph instance
            graph = IAMCapabilityGraph()
            self._populate_graph_from_definition(graph, definition)

            # 2. Track in registry
            self._graphs[run_id] = graph

            # 3. Create initial run model
            run = ScenarioRun(
                run_id=run_id,
                scenario_id=definition.id,
                scenario_name=definition.name,
                status=RunStatus.INITIALIZED,
                definition=definition,
            )
            self._runs[run_id] = run

            # 4. Perform initial analysis
            return self._analyze_run_internal(run_id)

    def get_run(self, run_id: str) -> Optional[ScenarioRun]:
        """Retrieve a scenario run by ID."""
        with self._lock:
            return self._runs.get(run_id)

    def get_graph(self, run_id: str) -> Optional[IAMCapabilityGraph]:
        """Retrieve the isolated IAM capability graph for a run."""
        with self._lock:
            return self._graphs.get(run_id)

    def list_runs(self) -> List[Dict[str, Any]]:
        """List summary of all active scenario runs."""
        with self._lock:
            return [
                {
                    "run_id": r.run_id,
                    "scenario_id": r.scenario_id,
                    "scenario_name": r.scenario_name,
                    "status": r.status.value,
                    "created_at": r.created_at,
                    "finding_count": len(r.findings),
                    "path_count": len(r.paths),
                    "remediated": r.remediation_applied is not None,
                }
                for r in self._runs.values()
            ]

    def analyze_run(self, run_id: str, context: Optional[Dict[str, Any]] = None) -> ScenarioRun:
        """Trigger re-analysis of a scenario run's current graph state."""
        with self._lock:
            if run_id not in self._runs:
                raise ValueError(f"Scenario run '{run_id}' not found.")
            return self._analyze_run_internal(run_id, context=context)

    def reset_run(self, run_id: str) -> ScenarioRun:
        """Reset an isolated scenario run back to its initial definition state."""
        with self._lock:
            run = self._runs.get(run_id)
            if not run:
                raise ValueError(f"Scenario run '{run_id}' not found.")

            # Rebuild clean isolated graph
            graph = IAMCapabilityGraph()
            self._populate_graph_from_definition(graph, run.definition)
            self._graphs[run_id] = graph

            # Reset run status and metadata
            run.status = RunStatus.RESET
            run.remediation_applied = None
            run.verification_result = None

            # Re-analyze initial state
            return self._analyze_run_internal(run_id)

    def delete_run(self, run_id: str) -> bool:
        """Remove a scenario run and free its isolated graph."""
        with self._lock:
            run_existed = run_id in self._runs
            self._runs.pop(run_id, None)
            self._graphs.pop(run_id, None)
            return run_existed

    # ---- Internal Execution Helpers ----

    def _populate_graph_from_definition(
        self,
        graph: IAMCapabilityGraph,
        definition: ScenarioDefinition,
    ) -> None:
        """Populate an IAMCapabilityGraph with nodes and edges from ScenarioDefinition."""
        graph.clear()

        # 1. Add identities (Users, Roles, Groups)
        for ident in definition.identities:
            evidence = dict(ident.metadata)
            if ident.trust_policy:
                evidence["trust_policy"] = [s.to_iam_dict() for s in ident.trust_policy]
            if ident.inline_policies:
                evidence["inline_policies"] = [p.to_iam_document() for p in ident.inline_policies]

            p_type = NodeType.USER
            if ident.type == "role":
                p_type = NodeType.ROLE
            elif ident.type == "group":
                p_type = NodeType.GROUP

            graph.add_principal(
                node_id=ident.id,
                name=ident.name,
                principal_type=p_type,
                is_admin=ident.is_admin,
                policies=ident.attached_policies,
                arn=ident.arn,
                evidence=evidence,
            )

        # 2. Add resources (S3, EC2, KMS)
        for res in definition.resources:
            r_type = NodeType.S3
            if res.type == "ec2":
                r_type = NodeType.EC2
            elif res.type == "kms":
                r_type = NodeType.KMS

            evidence = dict(res.configuration)
            if res.resource_policy:
                evidence["resource_policy"] = [s.to_iam_dict() for s in res.resource_policy]

            graph.add_resource(
                node_id=res.id,
                name=res.name,
                resource_type=r_type,
                is_sensitive=res.is_sensitive,
                arn=res.arn,
                evidence=evidence,
            )

        # 3. Add policies
        for pol in definition.policies:
            graph.add_policy(
                node_id=pol.id,
                name=pol.name,
                arn=pol.arn,
                statements=[s.to_iam_dict() for s in pol.statements],
                evidence={"is_managed": pol.is_managed},
            )

        # 4. Add relationships
        for rel in definition.relationships:
            graph.add_relationship(
                source_id=rel.source_id,
                target_id=rel.target_id,
                relationship=rel.relationship,
                actions=rel.actions,
                evidence=rel.evidence,
            )

    def _analyze_run_internal(
        self,
        run_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScenarioRun:
        """Internal helper to analyze paths, blast radius, and findings."""
        from backend.graph.policy_evaluator import PolicyEvaluator

        run = self._runs[run_id]
        graph = self._graphs[run_id]
        ctx = context or {}

        # 1. Discover attack paths from all non-admin identities
        discovered_paths: List[Dict[str, Any]] = []
        g = graph.graph

        # Collect source candidate identities
        source_candidates = [
            n for n, d in g.nodes(data=True)
            if d.get("category") in (NodeType.USER, NodeType.ROLE) and not d.get("is_admin", False)
        ]

        for src in source_candidates:
            paths = find_escalation_paths(graph, source_id=src, cutoff=5)
            for p in paths:
                nodes = p.get("nodes", [])
                classification, reason, hop_evals = PolicyEvaluator.classify_path(graph, nodes, ctx)
                p["source_id"] = p.get("source", src)
                p["target_id"] = p.get("target", nodes[-1] if nodes else "")
                p["classification"] = classification.value
                p["classification_reason"] = reason
                p["hop_evaluations"] = hop_evals
                discovered_paths.append(p)

        # Deduplicate paths by node sequence
        seen_seqs = set()
        unique_paths = []
        for p in discovered_paths:
            seq_key = tuple(p.get("nodes", []))
            if seq_key not in seen_seqs:
                seen_seqs.add(seq_key)
                unique_paths.append(p)

        # Sort paths: Confirmed first, then highest risk score
        def path_sort_key(p: Dict[str, Any]) -> Tuple[int, float]:
            cls_order = {
                "CONFIRMED": 0, "Confirmed": 0,
                "POTENTIAL": 1, "Potential": 1,
                "UNVERIFIED": 2, "Unverified": 2,
                "BLOCKED": 3, "THEORETICAL": 3, "Theoretical": 3,
            }
            cls_rank = cls_order.get(str(p.get("classification", "BLOCKED")), 4)
            return (cls_rank, -p.get("risk_score", 0))

        unique_paths.sort(key=path_sort_key)
        run.paths = unique_paths

        # 2. Calculate primary blast radius
        primary_source = source_candidates[0] if source_candidates else None
        if primary_source:
            br_report = calculate_blast_radius(graph, primary_source)
            run.blast_radius = br_report.to_dict()
        else:
            run.blast_radius = {}

        # 3. Dynamically derive findings
        findings: List[ScenarioFinding] = []
        finding_idx = 1

        for p in unique_paths:
            if str(p.get("classification", "")).upper() in ("BLOCKED", "THEORETICAL"):
                continue

            src = p.get("source_id", "")
            tgt = p.get("target_id", "")
            is_admin = p.get("is_admin_escalation", False)
            is_sens = p.get("reaches_sensitive_data", False)
            cls_val = p.get("classification", "")

            title = f"{cls_val} Privilege Escalation: {src} -> {tgt}" if is_admin else f"{cls_val} Asset Access: {src} -> {tgt}"
            severity = "Critical" if is_admin else ("High" if is_sens else "Medium")

            findings.append(
                ScenarioFinding(
                    finding_id=f"FIND-{run.scenario_id}-{finding_idx}",
                    title=title,
                    severity=severity,
                    category=run.definition.category.value,
                    description=p.get("narrative", f"Discovered attack path with {p.get('hop_count', 0)} hops."),
                    remediation_advice=(
                        f"Restrict IAM permissions or trust policies between {src} and {tgt} to eliminate this vector."
                    ),
                    affected_resources=[src, tgt],
                    attack_path_id=f"{src}->{tgt}",
                    mitre_attack="T1548.005" if is_admin else "T1530",
                )
            )
            finding_idx += 1

        # Check for exposed sensitive or public resources directly
        for n, d in g.nodes(data=True):
            ev = d.get("evidence", {})
            if ev.get("public_access", False) or ev.get("public_exposure", False):
                findings.append(
                    ScenarioFinding(
                        finding_id=f"FIND-{run.scenario_id}-{finding_idx}",
                        title=f"Public Resource Exposure: {d.get('name', n)}",
                        severity="Critical",
                        category="Resource Exposure",
                        description=f"Resource {n} is configured with public access, exposing data to unauthenticated callers.",
                        remediation_advice="Enable S3 Public Access Block and revoke unrestricted bucket policies.",
                        affected_resources=[n],
                        mitre_attack="T1530",
                    )
                )
                finding_idx += 1

        run.findings = findings
        if run.status not in (RunStatus.REMEDIATED, RunStatus.VERIFIED):
            run.status = RunStatus.ANALYZED

        return run


# Global singleton instance for the platform
scenario_session_manager = ScenarioSessionManager()
