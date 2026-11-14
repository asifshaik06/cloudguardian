"""Remediation Playground & Independent Verification Engine for CloudGuardian 2.0.

Simulates remediation actions on isolated scenario graphs, re-evaluates
authorization semantics and path reachability, detects alternative residual vectors,
and logs verification attempts into the tamper-evident SQLite audit trail.
"""
import logging
import time
from typing import Any, Dict, List, Optional

from backend.scenarios.models import RunStatus, ScenarioRun
from backend.scenarios.session import ScenarioSessionManager

logger = logging.getLogger("cloudguardian.scenarios.remediation")


def apply_remediation(
    manager: ScenarioSessionManager,
    run_id: str,
    remediation_action: Dict[str, Any],
    state_store: Optional[Any] = None,
) -> Dict[str, Any]:
    """Apply a simulated remediation fix to an isolated scenario run.

    Re-evaluates the capability graph post-fix, compares pre vs post metrics,
    checks if secondary/alternative attack paths remain, and writes a tamper-evident audit log.

    Args:
        manager: ScenarioSessionManager holding the run.
        run_id: Target scenario run ID.
        remediation_action: Dictionary describing the fix (type, target, source, params).
        state_store: Optional CloudGuardian StateStore instance for hash-chained audit logging.

    Returns:
        Detailed remediation and verification result dictionary.
    """
    run = manager.get_run(run_id)
    if not run:
        raise ValueError(f"Scenario run '{run_id}' not found.")

    graph = manager.get_graph(run_id)
    if not graph:
        raise ValueError(f"Isolated graph for run '{run_id}' not found.")

    g = graph.graph

    # 1. Capture Pre-Remediation Baseline
    pre_paths = len(run.paths)
    pre_confirmed = sum(1 for p in run.paths if p.get("classification") == "Confirmed")
    pre_potential = sum(1 for p in run.paths if p.get("classification") == "Potential")
    pre_score = float(run.blast_radius.get("score", 0.0))
    pre_sensitive = len(run.blast_radius.get("sensitive_resources_exposed", []))
    pre_admin = bool(run.blast_radius.get("admin_reachable", False))
    pre_findings = len(run.findings)

    action_type = remediation_action.get("type", "generic_remediation")
    target = remediation_action.get("target")
    source = remediation_action.get("source")

    # 2. Mutate Isolated Graph based on Remediation Type
    applied_changes: List[str] = []

    if action_type in ("revoke_edge", "remove_relationship", "sever_cross_environment_trust", "break_role_chain"):
        src = source or remediation_action.get("intermediate_hop")
        tgt = target
        if src and tgt and g.has_edge(src, tgt):
            g.remove_edge(src, tgt)
            applied_changes.append(f"Removed transition edge {src} -> {tgt}.")
        elif src:
            # Sever all outbound edges from intermediate hop
            out_edges = list(g.out_edges(src))
            for u, v in out_edges:
                g.remove_edge(u, v)
                applied_changes.append(f"Severed outbound edge {u} -> {v}.")

    elif action_type in ("revoke_excessive_iam", "remove_policy_version_privilege", "revoke_credential_creation"):
        # Remove CanEscalateTo edges from target user
        tgt_user = target or source
        if tgt_user and g.has_node(tgt_user):
            out_edges = list(g.out_edges(tgt_user))
            for u, v in out_edges:
                edge_data = g[u][v]
                if edge_data.get("relationship") in ("CanEscalateTo", "HasPolicy", "PassRole"):
                    g.remove_edge(u, v)
                    applied_changes.append(f"Revoked privileged capability edge {u} -> {v}.")

    elif action_type == "restrict_trust_policy":
        # Restrict trust policy on target role
        if target and g.has_node(target):
            in_edges = list(g.in_edges(target))
            for u, v in in_edges:
                edge_data = g[u][v]
                if edge_data.get("relationship") == "AssumesRole":
                    g.remove_edge(u, v)
                    applied_changes.append(f"Revoked unverified AssumeRole trust edge {u} -> {v}.")
            # Update role node evidence
            g.nodes[target]["evidence"]["trust_restricted"] = True

    elif action_type == "restrict_passrole_resource":
        # Remove PassRole edges to administrative roles
        user_node = target or source
        if user_node and g.has_node(user_node):
            out_edges = list(g.out_edges(user_node))
            for u, v in out_edges:
                if g[u][v].get("relationship") == "PassRole":
                    g.remove_edge(u, v)
                    applied_changes.append(f"Revoked unrestricted PassRole edge {u} -> {v}.")

    elif action_type == "enable_s3_public_access_block":
        # Enable public access block on bucket and remove anonymous access
        if target and g.has_node(target):
            g.nodes[target]["evidence"]["public_access"] = False
            g.nodes[target]["evidence"]["public_exposure"] = False
            in_edges = list(g.in_edges(target))
            for u, v in in_edges:
                if "anonymous" in u.lower() or "public" in u.lower() or "external" in u.lower():
                    g.remove_edge(u, v)
                    applied_changes.append(f"Revoked public access edge from {u} to {target}.")

    elif action_type == "scope_s3_resource_arn":
        # Restrict access to authorized bucket only, remove unauthorized sensitive bucket edges
        user_node = target or source
        if user_node and g.has_node(user_node):
            out_edges = list(g.out_edges(user_node))
            for u, v in out_edges:
                if g.nodes[v].get("is_sensitive", False):
                    g.remove_edge(u, v)
                    applied_changes.append(f"Revoked wildcard S3 access edge {u} -> {v}.")

    elif action_type == "close_security_group_ingress":
        # Close SSH/RDP ingress
        if target and g.has_node(target):
            g.nodes[target]["evidence"]["public_exposure"] = False
            in_edges = list(g.in_edges(target))
            for u, v in in_edges:
                g.remove_edge(u, v)
                applied_changes.append(f"Revoked public ingress edge {u} -> {target}.")

    elif action_type == "restrict_kms_key_policy":
        # Restrict KMS key policy
        if target and g.has_node(target):
            in_edges = list(g.in_edges(target))
            for u, v in in_edges:
                g.remove_edge(u, v)
                applied_changes.append(f"Revoked unrestricted KMS access edge {u} -> {target}.")

    elif action_type == "enforce_s3_object_lock_and_deny_delete":
        # Deny deletion on audit trail
        if target and g.has_node(target):
            in_edges = list(g.in_edges(target))
            for u, v in in_edges:
                g.remove_edge(u, v)
                applied_changes.append(f"Enforced explicit Deny on destructive operations for {target}.")

    else:
        # Generic fallback: if source and target exist, remove connecting edge
        if source and target and g.has_edge(source, target):
            g.remove_edge(source, target)
            applied_changes.append(f"Removed edge {source} -> {target}.")

    # 3. Re-run Analysis on Isolated Graph
    manager.analyze_run(run_id)

    # 4. Capture Post-Remediation Metrics
    post_paths = len(run.paths)
    post_confirmed = sum(1 for p in run.paths if p.get("classification") == "Confirmed")
    post_potential = sum(1 for p in run.paths if p.get("classification") == "Potential")
    post_score = float(run.blast_radius.get("score", 0.0))
    post_sensitive = len(run.blast_radius.get("sensitive_resources_exposed", []))
    post_admin = bool(run.blast_radius.get("admin_reachable", False))
    post_findings = len(run.findings)

    # 5. Evaluate Verification Status
    is_verified = (
        (post_paths < pre_paths)
        or (post_score < pre_score)
        or (post_confirmed < pre_confirmed)
        or (post_findings < pre_findings)
        or (post_paths == 0 and pre_paths > 0)
    )

    status_str = "PASS" if is_verified else "FAIL"
    score_reduction = round(max(0.0, pre_score - post_score), 1)
    paths_eliminated = max(0, pre_paths - post_paths)

    summary_text = (
        f"Remediation verified ({status_str}). Eliminated {paths_eliminated} attack path(s), "
        f"reducing risk score by {score_reduction} points (from {pre_score} to {post_score}). "
        f"{'Administrative control is no longer reachable.' if not post_admin and pre_admin else ''} "
        f"{f'{post_paths} alternative vector(s) remain active.' if post_paths > 0 else 'All attack vectors successfully mitigated.'}"
    )

    verification_data: Dict[str, Any] = {
        "verified": is_verified,
        "status": status_str,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action_taken": action_type,
        "applied_changes": applied_changes,
        "summary": summary_text.strip(),
        "metrics": {
            "pre_remediation": {
                "paths": pre_paths,
                "confirmed_paths": pre_confirmed,
                "potential_paths": pre_potential,
                "blast_radius_score": pre_score,
                "sensitive_resources": pre_sensitive,
                "admin_reachable": pre_admin,
                "findings": pre_findings,
            },
            "post_remediation": {
                "paths": post_paths,
                "confirmed_paths": post_confirmed,
                "potential_paths": post_potential,
                "blast_radius_score": post_score,
                "sensitive_resources": post_sensitive,
                "admin_reachable": post_admin,
                "findings": post_findings,
            },
            "delta": {
                "paths_eliminated": paths_eliminated,
                "score_reduction": score_reduction,
            },
        },
        "remaining_paths": run.paths,
    }

    run.remediation_applied = remediation_action
    run.verification_result = verification_data
    run.status = RunStatus.VERIFIED if is_verified else RunStatus.REMEDIATED

    # 6. Log Tamper-Evident Audit Entry
    audit_text = (
        f"SCENARIO REMEDIATION [{run.scenario_id}] Action={action_type} "
        f"Status={status_str} EliminatedPaths={paths_eliminated} ScoreDelta=-{score_reduction}"
    )
    if state_store and hasattr(state_store, "append_audit_entry"):
        try:
            state_store.append_audit_entry(audit_text)
        except Exception as exc:
            logger.warning("Failed to record audit entry: %s", exc)

    return verification_data


def verify_remediation_state(
    manager: ScenarioSessionManager,
    run_id: str,
) -> Dict[str, Any]:
    """Inspect current verification status and residual risk of a scenario run."""
    run = manager.get_run(run_id)
    if not run:
        raise ValueError(f"Scenario run '{run_id}' not found.")

    if not run.verification_result:
        return {
            "run_id": run_id,
            "status": "UNREMEDIATED",
            "verified": False,
            "summary": "No remediation has been applied to this run yet.",
            "paths_count": len(run.paths),
        }

    return {
        "run_id": run_id,
        **run.verification_result,
    }
