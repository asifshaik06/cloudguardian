"""Graph REST API endpoints for CloudGuardian 2.0.

Provides:
- GET /api/graph: Force-directed capability graph in ECharts format.
- GET /api/graph/paths/<principal_id>: Discovered privilege escalation paths.
- GET /api/graph/blast-radius/<target_id>: Dynamic blast-radius assessment.
- GET /api/graph/stats: Graph entity and topology metrics.
"""
import logging
from typing import Any, Dict, Optional
from flask import Flask, jsonify, request

from backend.graph.iam_graph import IAMCapabilityGraph, NodeType
from backend.graph.escalation import find_escalation_paths, find_all_escalation_paths
from backend.graph.blast_radius import calculate_blast_radius

logger = logging.getLogger("cloudguardian.graph.api")


def register_graph_api(
    app: Flask,
    iam_graph: IAMCapabilityGraph,
    clients: Optional[Dict[str, Any]] = None,
) -> None:
    """Register all graph, attack-path, and blast-radius API routes."""

    cli = clients or {}
    iam_client = cli.get("iam")
    s3_client = cli.get("s3")
    ec2_client = cli.get("ec2")

    @app.get("/api/graph")
    def get_graph() -> Any:
        """Return the current IAM capability graph formatted for ECharts."""
        refresh = request.args.get("refresh", "0") == "1"
        if refresh:
            try:
                iam_graph.build_from_aws_or_moto(
                    iam_client=iam_client,
                    s3_client=s3_client,
                    ec2_client=ec2_client,
                    populate_defaults_if_empty=True,
                )
            except Exception as exc:
                logger.warning("Error refreshing graph from AWS clients: %s", exc)

        # Optional attack-path highlighting
        hl = request.args.get("highlight", "")
        highlight_path = [n.strip() for n in hl.split(",") if n.strip()] if hl else None

        data = iam_graph.export_echarts(highlight_path=highlight_path)
        return jsonify(data)

    @app.get("/api/graph/paths/<path:principal_id>")
    def get_paths(principal_id: str) -> Any:
        """Find attack and escalation paths originating from a principal."""
        # Normalize principal ID (e.g. 'intern-dev' -> 'user/intern-dev')
        p_id = principal_id
        if not iam_graph.graph.has_node(p_id):
            if iam_graph.graph.has_node(f"user/{p_id}"):
                p_id = f"user/{p_id}"
            elif iam_graph.graph.has_node(f"role/{p_id}"):
                p_id = f"role/{p_id}"

        target = request.args.get("target")
        admin_only = request.args.get("admin_only", "0") == "1"
        cutoff = int(request.args.get("cutoff", 5))

        paths = find_escalation_paths(
            graph_engine=iam_graph,
            source_id=p_id,
            target_id=target,
            target_admin_only=admin_only,
            cutoff=cutoff,
        )

        return jsonify(
            principal_id=p_id,
            total_paths=len(paths),
            paths=paths,
        )

    @app.get("/api/graph/all-paths")
    def get_all_paths() -> Any:
        """Return all discovered privilege escalation paths for all principals."""
        cutoff = int(request.args.get("cutoff", 4))
        all_paths = find_all_escalation_paths(iam_graph, cutoff=cutoff)
        total = sum(len(v) for v in all_paths.values())
        return jsonify(total_escalations=total, escalations=all_paths)

    @app.get("/api/graph/blast-radius/<path:target_id>")
    def get_blast_radius(target_id: str) -> Any:
        """Compute the lateral movement and blast radius of a compromised entity."""
        # Normalize target ID
        t_id = target_id
        if not iam_graph.graph.has_node(t_id):
            for prefix in ("user/", "role/", "s3/", "ec2/"):
                if iam_graph.graph.has_node(f"{prefix}{t_id}"):
                    t_id = f"{prefix}{t_id}"
                    break

        report = calculate_blast_radius(iam_graph, t_id)
        return jsonify(report.to_dict())

    @app.get("/api/graph/stats")
    def get_stats() -> Any:
        """Summary statistics of graph entities and high-privilege concentrations."""
        g = iam_graph.graph
        total_nodes = g.number_of_nodes()
        total_edges = g.number_of_edges()

        users = sum(1 for _, d in g.nodes(data=True) if d.get("category") == NodeType.USER)
        roles = sum(1 for _, d in g.nodes(data=True) if d.get("category") == NodeType.ROLE)
        admin_roles = sum(1 for _, d in g.nodes(data=True) if d.get("is_admin"))
        s3_buckets = sum(1 for _, d in g.nodes(data=True) if d.get("category") == NodeType.S3)
        sensitive_s3 = sum(
            1 for _, d in g.nodes(data=True) if d.get("category") == NodeType.S3 and d.get("is_sensitive")
        )
        ec2_instances = sum(1 for _, d in g.nodes(data=True) if d.get("category") == NodeType.EC2)

        return jsonify(
            total_nodes=total_nodes,
            total_edges=total_edges,
            users=users,
            roles=roles,
            admin_roles=admin_roles,
            s3_buckets=s3_buckets,
            sensitive_s3=sensitive_s3,
            ec2_instances=ec2_instances,
        )
