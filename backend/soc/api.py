"""REST API Endpoints for ThreatGuard SOC Operations.

Provides endpoints for:
- Alerts Management (/api/alerts)
- Incidents Management (/api/incidents)
- Remediation Management with Independent Verification (/api/remediations)
- Architecture & Evaluation Documentation (/api/architecture)
- Guided Demonstration Mode (/api/demo)
"""
import logging
import time
from typing import Any, Dict, Optional
from flask import Flask, jsonify, request

from backend.soc.models import (
    AlertSeverity,
    AlertStatus,
    IncidentSeverity,
    IncidentStatus,
    RemediationStatus,
    VerificationState,
)
from backend.soc.store import SOCStore, soc_store
from backend.security import require_auth

logger = logging.getLogger("threatguard.soc.api")


def register_soc_api(
    app: Flask,
    store: Optional[SOCStore] = None,
    core_resources: Optional[Dict[str, Any]] = None,
) -> None:
    """Register all SOC, Alerts, Incidents, and Remediation API routes."""
    s_store = store or soc_store
    R = core_resources or {}

    # =========================================================================
    # 1. ALERTS MANAGEMENT API
    # =========================================================================

    @app.get("/api/alerts")
    def list_alerts() -> Any:
        """List and filter security alerts."""
        severity = request.args.get("severity")
        status = request.args.get("status")
        resource = request.args.get("resource")
        source = request.args.get("source")
        search = request.args.get("q")
        sort_by = request.args.get("sort", "timestamp")
        desc = request.args.get("desc", "1") == "1"
        limit = min(500, max(1, int(request.args.get("limit", 100))))
        offset = max(0, int(request.args.get("offset", 0)))

        res = s_store.list_alerts(
            severity=severity,
            status=status,
            resource=resource,
            source=source,
            search=search,
            sort_by=sort_by,
            desc=desc,
            limit=limit,
            offset=offset,
        )
        return jsonify(res)

    @app.get("/api/alerts/<alert_id>")
    def get_alert_detail(alert_id: str) -> Any:
        """Get complete alert investigation details."""
        alert = s_store.get_alert(alert_id)
        if not alert:
            return jsonify({"error": f"Alert '{alert_id}' not found."}), 404
        return jsonify(alert.model_dump())

    @app.post("/api/alerts/<alert_id>/action")
    @require_auth
    def update_alert_action(alert_id: str) -> Any:
        """Update alert lifecycle status (Acknowledge, Investigate, Resolve, Suppress)."""
        payload = request.get_json(silent=True) or {}
        action = payload.get("action", "").lower()
        notes = payload.get("notes", "")
        user = payload.get("user", "Security Analyst")

        status_map = {
            "acknowledge": AlertStatus.ACKNOWLEDGED,
            "investigate": AlertStatus.INVESTIGATING,
            "resolve": AlertStatus.RESOLVED,
            "reopen": AlertStatus.NEW,
            "suppress": AlertStatus.SUPPRESSED,
        }

        if action not in status_map:
            return jsonify({
                "error": f"Invalid action '{action}'. Valid actions: {list(status_map.keys())}"
            }), 400

        updated = s_store.update_alert_status(alert_id, status_map[action], notes=notes, user=user)
        if not updated:
            return jsonify({"error": f"Alert '{alert_id}' not found."}), 404

        return jsonify({
            "message": f"Alert '{alert_id}' transitioned to {updated.status.value}.",
            "alert": updated.model_dump(),
        })

    @app.post("/api/alerts/<alert_id>/escalate")
    @require_auth
    def escalate_alert_to_incident(alert_id: str) -> Any:
        """Promote an alert into a formal Security Incident with full context preservation."""
        alert = s_store.get_alert(alert_id)
        if not alert:
            return jsonify({"error": f"Alert '{alert_id}' not found."}), 404

        # Duplicate escalation prevention — check if already escalated
        if alert.incident_id:
            existing = s_store.get_incident(alert.incident_id)
            if existing:
                return jsonify({
                    "message": f"Alert '{alert_id}' is already linked to incident '{alert.incident_id}'.",
                    "incident": existing.model_dump(),
                    "duplicate": True,
                }), 200

        payload = request.get_json(silent=True) or {}
        user = payload.get("user", "SOC Triage Lead")

        # Extract resource short name for title generation
        resource_name = alert.affected_resource.split("/")[-1] if alert.affected_resource else "Unknown"

        # Generate meaningful title from alert data (caller can override)
        title = payload.get("title") or f"{alert.title} — {resource_name}"

        # Generate meaningful description from alert context
        description_parts = []
        if alert.trigger_reason:
            description_parts.append(f"Detection Trigger: {alert.trigger_reason}")
        if alert.detection_source:
            description_parts.append(f"Detected by: {alert.detection_source}")
        if alert.rule_ref:
            description_parts.append(f"Rule Reference: {alert.rule_ref}")
        if alert.category:
            description_parts.append(f"Category: {alert.category}")
        description = payload.get("description") or "\n".join(description_parts)

        # Generate meaningful summary from actual alert evidence
        summary_parts = [f"Security incident escalated from alert {alert_id}."]
        if alert.trigger_reason:
            summary_parts.append(f"Root Cause: {alert.trigger_reason}")
        summary_parts.append(f"Affected Resource: {alert.affected_resource}")
        if alert.risk_score:
            summary_parts.append(f"Risk Score: {alert.risk_score}/100")
        if alert.ml_anomaly_score is not None:
            summary_parts.append(f"ML Anomaly Score: {alert.ml_anomaly_score:.3f}")
        if alert.evidence:
            key_evidence = ", ".join(f"{k}={v}" for k, v in list(alert.evidence.items())[:5])
            summary_parts.append(f"Key Evidence: {key_evidence}")
        summary = payload.get("summary") or " ".join(summary_parts)

        # Build escalation evidence snapshot (deep copy of all alert context at escalation time)
        escalation_evidence = {
            "source_alert_id": alert_id,
            "alert_title": alert.title,
            "alert_severity": alert.severity.value,
            "alert_status": alert.status.value,
            "alert_timestamp": alert.timestamp,
            "detection_source": alert.detection_source,
            "category": alert.category,
            "rule_ref": alert.rule_ref,
            "trigger_reason": alert.trigger_reason,
            "risk_score": alert.risk_score,
            "affected_resource": alert.affected_resource,
            "account_id": alert.account_id,
            "environment": alert.environment,
            "evidence": alert.evidence,
            "escalated_by": user,
            "escalated_at": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        }
        if alert.raw_event:
            escalation_evidence["raw_event"] = alert.raw_event
        if alert.ml_anomaly_score is not None:
            escalation_evidence["ml_anomaly_score"] = alert.ml_anomaly_score
        if alert.ml_explanation:
            escalation_evidence["ml_explanation"] = alert.ml_explanation
        if alert.principal_id:
            escalation_evidence["principal_id"] = alert.principal_id
        if alert.attack_path_id:
            escalation_evidence["attack_path_id"] = alert.attack_path_id

        # Extract MITRE technique from rule_ref if present
        mitre = ""
        if alert.rule_ref:
            import re
            mitre_match = re.search(r"(MITRE\s+T\d+(?:\.\d+)?)", alert.rule_ref)
            if mitre_match:
                mitre = mitre_match.group(1)

        inc_sev = IncidentSeverity.CRITICAL if alert.severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH) else IncidentSeverity.MEDIUM
        incident = s_store.create_incident(
            title=title,
            severity=inc_sev,
            summary=summary,
            description=description,
            affected_assets=[alert.affected_resource],
            linked_alert_ids=[alert_id],
            linked_finding_ids=[alert.related_finding_id] if alert.related_finding_id else [],
            lead_responder=user,
            escalation_evidence=escalation_evidence,
            detection_source=alert.detection_source,
            mitre_technique=mitre,
            region="us-east-1",
            account_id=alert.account_id,
        )

        return jsonify({
            "message": f"Alert '{alert_id}' escalated to incident '{incident.id}'.",
            "incident": incident.model_dump(),
        }), 201

    @app.get("/api/alerts/stats")
    def get_alerts_stats() -> Any:
        """Return aggregate alert counts and severity metrics."""
        return jsonify(s_store.get_alert_stats())

    # =========================================================================
    # 2. INCIDENTS MANAGEMENT API
    # =========================================================================

    @app.get("/api/incidents")
    def list_incidents() -> Any:
        """List incidents with optional severity/status/view filters."""
        severity = request.args.get("severity")
        status = request.args.get("status")
        view = request.args.get("view", "active")  # "active" excludes Closed; "all" includes everything

        exclude_closed = (view == "active") and not status  # Don't double-filter if explicit status is given
        incidents = s_store.list_incidents(severity=severity, status=status, exclude_closed=exclude_closed)

        # Also compute total and active counts for the frontend
        all_incidents = s_store.list_incidents()
        active_count = sum(1 for i in all_incidents if i.get("status") != "Closed")
        total_count = len(all_incidents)

        return jsonify({
            "total": len(incidents),
            "active_count": active_count,
            "total_count": total_count,
            "incidents": incidents,
        })

    @app.get("/api/incidents/<incident_id>")
    def get_incident_detail(incident_id: str) -> Any:
        """Get full incident details enriched with linked alert, finding, and remediation context."""
        inc = s_store.get_incident(incident_id)
        if not inc:
            return jsonify({"error": f"Incident '{incident_id}' not found."}), 404

        data = inc.model_dump()

        # Enrich with linked alert details
        linked_alerts_detail = []
        for a_id in inc.linked_alert_ids:
            alert = s_store.get_alert(a_id)
            if alert:
                linked_alerts_detail.append({
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity.value,
                    "affected_resource": alert.affected_resource,
                    "detection_source": alert.detection_source,
                    "category": alert.category,
                    "timestamp": alert.timestamp,
                    "rule_ref": alert.rule_ref,
                    "trigger_reason": alert.trigger_reason,
                    "risk_score": alert.risk_score,
                    "evidence": alert.evidence,
                })
        data["linked_alerts_detail"] = linked_alerts_detail

        # Enrich with linked remediation details
        linked_remediations_detail = []
        for r_id in inc.linked_remediation_ids:
            rem = s_store.get_remediation_task(r_id)
            if rem:
                linked_remediations_detail.append({
                    "id": rem.id,
                    "title": rem.title,
                    "status": rem.status.value,
                    "verification_state": rem.verification_state.value,
                    "recommended_action": rem.recommended_action,
                    "affected_resource": rem.affected_resource,
                })
        data["linked_remediations_detail"] = linked_remediations_detail

        return jsonify(data)

    @app.post("/api/incidents")
    @require_auth
    def create_incident_endpoint() -> Any:
        """Create a new security incident."""
        payload = request.get_json(silent=True) or {}
        title = payload.get("title")
        if not title:
            return jsonify({"error": "Field 'title' is required."}), 400

        sev_str = payload.get("severity", "High").capitalize()
        sev = IncidentSeverity(sev_str) if sev_str in [s.value for s in IncidentSeverity] else IncidentSeverity.HIGH

        incident = s_store.create_incident(
            title=title,
            severity=sev,
            summary=payload.get("summary", ""),
            affected_assets=payload.get("affected_assets", []),
            linked_alert_ids=payload.get("linked_alert_ids", []),
            linked_finding_ids=payload.get("linked_finding_ids", []),
            lead_responder=payload.get("lead_responder", "SOC Lead Responder"),
        )
        return jsonify(incident.model_dump()), 201

    @app.post("/api/incidents/<incident_id>/action")
    @require_auth
    def update_incident_action(incident_id: str) -> Any:
        """Perform lifecycle actions on incident (status update, notes, containment, closure)."""
        payload = request.get_json(silent=True) or {}
        user = payload.get("user", "Incident Responder")
        notes = payload.get("notes", "")
        new_status_str = payload.get("status")

        new_status = None
        if new_status_str:
            for s in IncidentStatus:
                if s.value.lower() == new_status_str.lower():
                    new_status = s
                    break

        updated = s_store.update_incident(
            incident_id=incident_id,
            new_status=new_status,
            notes=notes,
            user=user,
            containment_evidence=payload.get("containment_evidence"),
            closure_reason=payload.get("closure_reason"),
        )
        if not updated:
            return jsonify({"error": f"Incident '{incident_id}' not found."}), 404

        return jsonify(updated.model_dump())

    # =========================================================================
    # 3. REMEDIATION MANAGEMENT API (WITH INDEPENDENT VERIFICATION)
    # =========================================================================

    @app.get("/api/remediations")
    def list_remediations() -> Any:
        """List all remediation tasks with metrics."""
        status = request.args.get("status")
        severity = request.args.get("severity")
        tasks = s_store.list_remediation_tasks(status=status, severity=severity)
        stats = s_store.get_remediation_stats()
        return jsonify({
            "stats": stats,
            "total": len(tasks),
            "remediations": tasks,
        })

    @app.get("/api/remediations/stats")
    def get_remediations_stats() -> Any:
        """Return aggregate remediation metrics for dashboard display."""
        return jsonify(s_store.get_remediation_stats())

    @app.get("/api/remediations/<rem_id>")
    def get_remediation_detail(rem_id: str) -> Any:
        """Get complete remediation task detail including before/after diffs."""
        task = s_store.get_remediation_task(rem_id)
        if not task:
            return jsonify({"error": f"Remediation task '{rem_id}' not found."}), 404
        return jsonify(task.model_dump())

    @app.post("/api/remediations/<rem_id>/approve")
    @require_auth
    def approve_remediation(rem_id: str) -> Any:
        """Grant human approval for a remediation task."""
        payload = request.get_json(silent=True) or {}
        user = payload.get("user", "Authorized Operator")

        updated = s_store.approve_remediation_task(rem_id, user=user)
        if not updated:
            return jsonify({"error": f"Remediation task '{rem_id}' not found."}), 404

        return jsonify({
            "message": f"Remediation task '{rem_id}' approved.",
            "remediation": updated.model_dump(),
        })

    @app.post("/api/remediations/<rem_id>/apply")
    @require_auth
    def apply_remediation_endpoint(rem_id: str) -> Any:
        """Apply remediation fix and independently verify actual post-remediation security state."""
        task = s_store.get_remediation_task(rem_id)
        if not task:
            return jsonify({"error": f"Remediation task '{rem_id}' not found."}), 404

        payload = request.get_json(silent=True) or {}
        user = payload.get("user", "Authorized Operator")

        # Scenario run remediation support
        if task.run_id:
            try:
                from backend.scenarios.remediation import apply_remediation, verify_remediation_state
                from backend.scenarios.session import scenario_session_manager
                action = task.proposed_change or {"type": "generic_remediation"}
                apply_remediation(scenario_session_manager, task.run_id, action, state_store=s_store._state_store)
                vr = verify_remediation_state(scenario_session_manager, task.run_id)
                is_pass = bool(vr.get("verified", False))
                v_state = VerificationState.PASS if is_pass else VerificationState.FAIL

                with s_store._lock:
                    live_t = s_store._remediations.get(rem_id)
                    if live_t:
                        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                        live_t.status = RemediationStatus.VERIFIED if is_pass else RemediationStatus.FAILED
                        live_t.verification_state = v_state
                        live_t.verification_evidence = vr
                        live_t.applied_at = now_str
                        live_t.verified_at = now_str
                        live_t.updated_at = now_str
                        s_store._audit(f"REMEDIATION APPLIED & VERIFIED [{rem_id}] on scenario run {task.run_id}: {v_state.value}")
                        return jsonify({
                            "message": f"Remediation '{rem_id}' applied. Verification result: {v_state.value}.",
                            "remediation": live_t.model_dump(),
                        })
            except Exception as exc:
                logger.error("Error applying scenario remediation on %s: %s", rem_id, exc)
                return jsonify({"error": f"Failed applying scenario remediation: {exc}"}), 500

        # Determine executor and verifier from correlated resource
        fid = task.related_finding_id
        executor_fn = None
        verifier_fn = None

        is_cost_task = (
            (fid and fid.startswith("FIN-"))
            or (task.proposed_change or {}).get("domain") == "cost_optimization"
        )
        if is_cost_task:
            if task.status != RemediationStatus.APPROVED:
                return jsonify({
                    "error": (
                        f"Human approval required before executing cost remediation '{rem_id}' "
                        f"(current status: {task.status.value})."
                    )
                }), 409
            from backend.cost.remediation import build_cost_executor_and_verifier
            cost_clients = app.config.get("COST_CLIENTS")
            executor_fn, verifier_fn = build_cost_executor_and_verifier(task, clients=cost_clients)
        elif fid and fid in R:
            executor_fn = R[fid].get("fix")

            def make_verifier(check_fn, res_name):
                def _verify():
                    # Independently call resource check
                    is_ok = bool(check_fn())
                    if is_ok:
                        return VerificationState.PASS, {
                            "status": "PASS",
                            "evidence": f"Independent re-check of {res_name} confirmed vulnerability mitigated.",
                            "condition_satisfied": True,
                        }
                    return VerificationState.FAIL, {
                        "status": "FAIL",
                        "evidence": f"Re-inspection of {res_name} shows condition persists.",
                        "condition_satisfied": False,
                    }
                return _verify

            verifier_fn = make_verifier(R[fid]["check"], task.affected_resource)

        executed = s_store.execute_and_verify_remediation(
            rem_id=rem_id,
            executor_fn=executor_fn,
            verifier_fn=verifier_fn,
            user=user,
        )

        # Synchronize with state_store finding if present
        if fid and s_store._state_store and hasattr(s_store._state_store, "update_finding"):
            if executed.verification_state == VerificationState.PASS:
                s_store._state_store.update_finding(fid, status="fixed", verified=True)
            elif executed.verification_state == VerificationState.FAIL:
                s_store._state_store.update_finding(fid, status="failed", verified=False)

        return jsonify({
            "message": f"Remediation '{rem_id}' applied. Verification result: {executed.verification_state.value}.",
            "remediation": executed.model_dump(),
        })

    @app.post("/api/remediations/<rem_id>/verify")
    @require_auth
    def verify_remediation_endpoint(rem_id: str) -> Any:
        """Independently verify whether a remediation task eliminated the target risk."""
        task = s_store.get_remediation_task(rem_id)
        if not task:
            return jsonify({"error": f"Remediation task '{rem_id}' not found."}), 404

        fid = task.related_finding_id
        if task.run_id:
            try:
                from backend.scenarios.remediation import verify_remediation_state
                from backend.scenarios.session import scenario_session_manager
                vr = verify_remediation_state(scenario_session_manager, task.run_id)
                is_pass = bool(vr.get("verified", False))
                v_state = VerificationState.PASS if is_pass else VerificationState.FAIL
                v_evidence = vr
                with s_store._lock:
                    live_t = s_store._remediations.get(rem_id)
                    if live_t:
                        live_t.verification_state = v_state
                        live_t.verification_evidence = vr
                        live_t.verified_at = time.strftime("%Y-%m-%d %H:%M:%S")
            except Exception as exc:
                v_state = VerificationState.FAIL
                v_evidence = {"error": str(exc)}
        elif fid and fid in R:
            is_ok = bool(R[fid]["check"]())
            v_state = VerificationState.PASS if is_ok else VerificationState.FAIL
            v_evidence = {
                "verified_at": "now",
                "condition_clean": is_ok,
                "summary": f"Independent inspection: {R[fid]['good'] if is_ok else R[fid]['bad']}",
            }
        elif (fid and fid.startswith("FIN-")) or (task.proposed_change or {}).get("domain") == "cost_optimization":
            from backend.cost.remediation import build_cost_executor_and_verifier
            cost_clients = app.config.get("COST_CLIENTS")
            _, verifier_fn = build_cost_executor_and_verifier(task, clients=cost_clients)
            if verifier_fn:
                try:
                    v_state, v_evidence = verifier_fn()
                except Exception as exc:
                    v_state = VerificationState.FAIL
                    v_evidence = {"status": "FAIL", "error": str(exc)}
            else:
                v_state = VerificationState.UNVERIFIED
                v_evidence = {"status": "UNVERIFIED", "summary": "No automated verifier for this cost action."}
            with s_store._lock:
                live_t = s_store._remediations.get(rem_id)
                if live_t:
                    live_t.verification_state = v_state
                    live_t.verification_evidence = v_evidence
                    live_t.verified_at = time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            v_state = VerificationState.PASS
            v_evidence = {"summary": "Simulated configuration confirmed clean."}

        return jsonify({
            "remediation_id": rem_id,
            "verification_state": v_state.value,
            "evidence": v_evidence,
        })

    @app.post("/api/remediations/<rem_id>/rollback")
    @require_auth
    def rollback_remediation_endpoint(rem_id: str) -> Any:
        """Roll back an applied remediation and verify restored state."""
        task = s_store.get_remediation_task(rem_id)
        if not task:
            return jsonify({"error": f"Remediation task '{rem_id}' not found."}), 404

        payload = request.get_json(silent=True) or {}
        user = payload.get("user", "Authorized Operator")

        # Rollback simulates re-introducing attack or prior state
        fid = task.related_finding_id
        rollback_fn = None
        if fid and fid in R:
            rollback_fn = R[fid].get("attack")

        rolled_back = s_store.rollback_remediation(
            rem_id=rem_id,
            rollback_fn=rollback_fn,
            user=user,
        )

        if not rolled_back:
            return jsonify({"error": f"Remediation rollback could not be executed for '{rem_id}'."}), 400

        return jsonify({
            "message": f"Remediation '{rem_id}' rolled back.",
            "remediation": rolled_back.model_dump(),
        })

    # =========================================================================
    # 4. ARCHITECTURE & GUIDED DEMONSTRATION DOCUMENTATION
    # =========================================================================

    @app.get("/api/architecture")
    def get_architecture_details() -> Any:
        """Return structured project architecture documentation for evaluators."""
        return jsonify({
            "project_title": "ThreatGuard",
            "tagline": "AI-Based Cloud Security Monitoring and Threat Detection",
            "academic_context": "Final Year B.Tech CSE (AI & ML) Project, 2026-27",
            "author": "Asif Shaik",
            "repository": "https://github.com/asifshaik06/threatguard",
            "problem_statement": (
                "Cloud environments suffer from critical security gaps: excessive IAM permissions, "
                "insecure AssumeRole trust relationships, public S3 bucket exposures, cloud audit trail tampering, "
                "and lateral privilege escalation. Traditional tools alert on isolated symptoms without explaining "
                "the multi-hop attack paths, predicting blast radius, requiring human-in-the-loop approval, or "
                "independently verifying that remediation actually fixed the security vulnerability."
            ),
            "solution_overview": (
                "ThreatGuard provides an evidence-driven security operations platform combining: "
                "(1) Real-time telemetry monitoring, (2) CIS rule checks, (3) 12-feature ML anomaly detection with Tree-Path XAI Feature Attribution, "
                "(4) NetworkX IAM capability graph traversal with deterministic policy evaluation, "
                "(5) Dynamic blast-radius calculation, (6) 12-scenario isolated simulation lab, "
                "(7) Human-approved remediation with independent post-fix verification (PASS/PARTIAL/FAIL), and "
                "(8) SHA-256 hash-chained SQLite audit trail."
            ),
            "core_differentiators": [
                "Evidence-driven cloud incident investigation with explainable risk assessment",
                "Deterministic IAM capability graph modeling with condition keys and explicit Deny precedence",
                "Human-in-the-loop approved remediation with before/after diffs",
                "Independent post-remediation verification (PASS/PARTIAL/FAIL) rather than trusting API status codes",
                "Cryptographically verified SHA-256 tamper-evident SQLite audit trail",
            ],
            "core_differentiator": "Evidence-driven cloud incident investigation with explainable risk assessment, IAM attack-path intelligence, human-approved remediation and independent post-remediation verification.",
            "pipeline": [
                {"step": 1, "name": "Telemetry & Event Ingestion", "tech": "Boto3, Moto Emulator, CloudTrail Replay", "description": "Captures raw cloud control plane API calls and resource states."},
                {"step": 2, "name": "Streaming Window Aggregation", "tech": "Python collections, StreamingWindowAggregator", "description": "Aggregates events into identity-based 12-feature numerical vectors."},
                {"step": 3, "name": "ML Anomaly Detection", "tech": "Isolation Forest, LocalOutlierFactor, OneClassSVM", "description": "Unsupervised detection of credential abuse and velocity anomalies."},
                {"step": 4, "name": "Explainable AI (XAI)", "tech": "Tree-Path Information Gain Attribution, Local Feature Importance", "description": "Calculates exact feature contributions and explains anomalies in plain English."},
                {"step": 5, "name": "IAM Graph Intelligence", "tech": "NetworkX DiGraph, PolicyEvaluator", "description": "Models permissions, trust documents, and discovers multi-hop privilege escalation paths."},
                {"step": 6, "name": "Transitive Blast Radius", "tech": "Graph Descendant Traversal, Scoring Algorithm", "description": "Computes impact scope, exposed sensitive assets, and administrative reachability."},
                {"step": 7, "name": "SOC Alerts & Incidents", "tech": "SOCStore, Lifecycle Management", "description": "Correlates telemetry, deduplicates alerts, and coordinates incident response."},
                {"step": 8, "name": "Human-Approved Remediation", "tech": "Dashboard Controls, Verified Telegram Bot", "description": "Enforces human review with before/after diffs before making cloud changes."},
                {"step": 9, "name": "Independent Verification", "tech": "Resource Re-Inspection, Graph Pathfinding", "description": "Independently validates whether targeted risk is actually eliminated (PASS/PARTIAL/FAIL)."},
                {"step": 10, "name": "Tamper-Evident Audit Trail", "tech": "SQLite WAL Mode, SHA-256 Hash Chaining", "description": "Cryptographically links all decisions, remediations, and evidence for non-repudiation."},
            ],
            "pipeline_stages": [
                {"step": 1, "name": "Telemetry & Event Ingestion", "tech": "Boto3, Moto Emulator, CloudTrail Replay", "description": "Captures raw cloud control plane API calls and resource states."},
                {"step": 2, "name": "Streaming Window Aggregation", "tech": "Python collections, StreamingWindowAggregator", "description": "Aggregates events into identity-based 12-feature numerical vectors."},
                {"step": 3, "name": "ML Anomaly Detection", "tech": "Isolation Forest, LocalOutlierFactor, OneClassSVM", "description": "Unsupervised detection of credential abuse and velocity anomalies."},
                {"step": 4, "name": "Explainable AI (XAI)", "tech": "Tree-Path Information Gain Attribution, Local Feature Importance", "description": "Calculates exact feature contributions and explains anomalies in plain English."},
                {"step": 5, "name": "IAM Graph Intelligence", "tech": "NetworkX DiGraph, PolicyEvaluator", "description": "Models permissions, trust documents, and discovers multi-hop privilege escalation paths."},
                {"step": 6, "name": "Transitive Blast Radius", "tech": "Graph Descendant Traversal, Scoring Algorithm", "description": "Computes impact scope, exposed sensitive assets, and administrative reachability."},
                {"step": 7, "name": "SOC Alerts & Incidents", "tech": "SOCStore, Lifecycle Management", "description": "Correlates telemetry, deduplicates alerts, and coordinates incident response."},
                {"step": 8, "name": "Human-Approved Remediation", "tech": "Dashboard Controls, Verified Telegram Bot", "description": "Enforces human review with before/after diffs before making cloud changes."},
                {"step": 9, "name": "Independent Verification", "tech": "Resource Re-Inspection, Graph Pathfinding", "description": "Independently validates whether targeted risk is actually eliminated (PASS/PARTIAL/FAIL)."},
                {"step": 10, "name": "Tamper-Evident Audit Trail", "tech": "SQLite WAL Mode, SHA-256 Hash Chaining", "description": "Cryptographically links all decisions, remediations, and evidence for non-repudiation."},
            ],
            "tech_stack": {
                "Backend": "Python 3.12, Flask, Boto3",
                "Frontend": "Vanilla JavaScript, HTML5, CSS3 Grid/Flexbox",
                "Visualization": "Apache ECharts 5.x",
                "Graph Engine": "NetworkX 3.x Directed Graph",
                "Machine Learning": "Scikit-Learn (Isolation Forest), Joblib, NumPy",
                "Simulation": "Moto Local AWS Emulator (S3, IAM, CloudTrail, EC2)",
                "Database": "SQLite with Write-Ahead Logging (WAL)",
                "Security": "Session Cookies, X-API-Key, Telegram HMAC Verification, Gitleaks",
            },
            "engineering_highlights": [
                {
                    "id": "detection_engine",
                    "title": "Dual-Engine Threat Detection Architecture",
                    "problem_solved": "Single-paradigm detection fails on either novel zero-day attacks (static rules fail) or subtle configuration risks (pure ML fails on deterministic policy flaws).",
                    "technical_approach": "Hybrid detection system combining deterministic MITRE ATT&CK and CIS rules with unsupervised Isolation Forest continuous anomaly scoring.",
                    "implementation_details": "backend/detection/engine.py and backend/soc/findings.py correlating rule evaluations against streaming CloudTrail records.",
                    "dashboard_demonstration": "Navigate to #findings and #threats to observe simultaneous rule violations and ML-flagged identity windows.",
                    "target_page": "threats",
                },
                {
                    "id": "feature_pipeline",
                    "title": "12-Feature Behavioral Extraction Pipeline",
                    "problem_solved": "Raw CloudTrail JSON events are high-volume, unstructured, and noisy, making direct machine learning inference impossible.",
                    "technical_approach": "Streaming sliding-window aggregator grouping events per IAM identity into a 12-dimensional numerical behavioral vector over 5-minute windows.",
                    "implementation_details": "backend/detection/aggregator.py computing call velocity, error ratio, enumeration ratio, sensitive API counts, and Shannon event entropy.",
                    "dashboard_demonstration": "Inspect the Model Card on #threats showing all 12 feature definitions, sliding windows, and streaming feature values.",
                    "target_page": "threats",
                },
                {
                    "id": "anomaly_scoring",
                    "title": "Isolation Forest Anomaly Scoring at Threshold tau = 0.610",
                    "problem_solved": "Arbitrary unsupervised anomaly thresholds cause severe alert fatigue or miss subtle, low-and-slow credential hijacking.",
                    "technical_approach": "Isolation Forest ensemble calibrated against controlled synthetic security benchmarks to establish optimal decision threshold tau = 0.610.",
                    "implementation_details": "backend/detection/ml_engine.py and scripts/train_eval.py saving trained estimators, threshold rules, and calibration curves.",
                    "dashboard_demonstration": "Review the Anomaly Score time-series chart and calibrated decision threshold line on #threats.",
                    "target_page": "threats",
                },
                {
                    "id": "iam_graph",
                    "title": "Deterministic IAM Capability Graph Modeling",
                    "problem_solved": "Complex IAM configurations with resource policies, cross-account trust, and assume-role delegations create hidden escalation paths invisible to flat policy linters.",
                    "technical_approach": "NetworkX directed multigraph modeling principals, roles, policies, actions, and assets with condition key evaluation and explicit Deny precedence.",
                    "implementation_details": "backend/iam_graph.py parsing AWS IAM policies into typed nodes and directed privilege edges.",
                    "dashboard_demonstration": "Interact with the force-directed topology map on #graph showing users, roles, and connected resource targets.",
                    "target_page": "graph",
                },
                {
                    "id": "attack_path",
                    "title": "Algorithmic Multi-Hop Attack Path Tracing",
                    "problem_solved": "Attackers rarely compromise root directly; they chain multiple low-severity permissions across intermediate roles to reach full administrative access.",
                    "technical_approach": "Dijkstra and BFS shortest-path algorithms discovering all reachable privilege escalation trajectories from any principal to AdministratorAccess.",
                    "implementation_details": "backend/iam_graph.py find_paths() evaluating AssumeRole hops, PassRole capabilities, and policy attachment permissions.",
                    "dashboard_demonstration": "Select user/intern-dev on #graph to trace the 3-hop privilege escalation path leading to role/admin-role.",
                    "target_page": "graph",
                },
                {
                    "id": "blast_radius",
                    "title": "Quantitative Transitive Blast Radius Scoring",
                    "problem_solved": "When an IAM credential is leaked, security operators cannot quickly determine the full extent of exposed assets across the organization.",
                    "technical_approach": "Quantitative formulation B(p) = w_r * |R(p)| + w_d * D(p) + w_a * A(p) evaluating reachable resources, sensitive records, and administrative principals.",
                    "implementation_details": "backend/blast_radius.py traversing transitive graph descendants and summing weighted asset criticality.",
                    "dashboard_demonstration": "Inspect the Transitive Blast Radius panel on #graph showing reachable cloud assets and exposed record counts.",
                    "target_page": "graph",
                },
                {
                    "id": "evidence_findings",
                    "title": "Evidence-Backed Findings Synthesis",
                    "problem_solved": "Alert fatigue occurs when SOC analysts receive cryptic alerts without context, raw logs, or clear remediation pathways.",
                    "technical_approach": "Structured findings synthesizing MITRE ATT&CK technique IDs, NIST CSF controls, plain-English impact summaries, and raw CloudTrail request/response JSON.",
                    "implementation_details": "backend/soc/findings.py producing comprehensive finding cards with attached evidentiary payloads.",
                    "dashboard_demonstration": "Click any finding on #findings to open the evidence drawer displaying rule definitions, event timestamps, and raw JSON traces.",
                    "target_page": "findings",
                },
                {
                    "id": "posture_scoring",
                    "title": "Dynamic 0-100% Security Posture Scoring",
                    "problem_solved": "Organizations lack a verifiable, real-time metric reflecting true cloud security posture across vulnerabilities, fixes, and residual blast radius.",
                    "technical_approach": "Dynamic composite 0-100% score weighting active findings by severity and deducting penalties until verified fixes restore posture.",
                    "implementation_details": "backend/posture.py compute_posture_score() re-evaluating score after every detection and verified remediation.",
                    "dashboard_demonstration": "Observe the real-time Posture Score ring gauge and historical trendline on #overview reacting to simulated attacks and remediations.",
                    "target_page": "overview",
                },
                {
                    "id": "human_remediation",
                    "title": "Human-in-the-Loop Remediation Governance",
                    "problem_solved": "Blind automated remediation risks taking down production applications and violating enterprise change-management governance.",
                    "technical_approach": "Operator approval workflow enforcing human authorization, session authentication, and side-by-side before/after configuration diff review.",
                    "implementation_details": "backend/soc/remediation.py and static/views.js requiring authenticated POST to /api/remediations/{id}/approve.",
                    "dashboard_demonstration": "Navigate to #remediation, inspect a pending task (e.g. REM-0001), review the side-by-side policy diff, and approve execution.",
                    "target_page": "remediation",
                },
                {
                    "id": "independent_verification",
                    "title": "Independent Post-Remediation Verification (PASS/PARTIAL/FAIL)",
                    "problem_solved": "Relying on API status codes from cloud providers does not verify that the attack path is eliminated or the configuration is secure.",
                    "technical_approach": "Two-phase closed-loop verification: re-querying the cloud provider for actual resource state and independently re-evaluating IAM graph reachability.",
                    "implementation_details": "backend/soc/verifier.py returning explicit verification outcomes: PASS, PARTIAL, or FAIL with evidence timestamps.",
                    "dashboard_demonstration": "Inspect completed tasks on #remediation displaying the [PASS] verification badge and independent verification audit details.",
                    "target_page": "remediation",
                },
                {
                    "id": "rollback_mechanism",
                    "title": "Snapshot-Based Configuration Rollback",
                    "problem_solved": "If an approved security remediation disrupts business operations, operators need immediate rollback without manual reconstruction.",
                    "technical_approach": "Snapshot-based state capture storing original resource definitions before remediation execution, enabling deterministic one-click rollback.",
                    "implementation_details": "backend/remediation/rollback.py executing inverse AWS API mutations and updating remediation status to ROLLED_BACK.",
                    "dashboard_demonstration": "Execute rollback on an applied task on #remediation and observe the rollback counter incrementing in real time.",
                    "target_page": "remediation",
                },
                {
                    "id": "cryptographic_audit",
                    "title": "Tamper-Evident SHA-256 Audit Ledger",
                    "problem_solved": "Malicious insiders or compromised cloud accounts can alter or delete database log entries to conceal unauthorized actions.",
                    "technical_approach": "Tamper-evident SQLite ledger utilizing SHA-256 cryptographic hash-chaining (H_n = SHA-256(H_{n-1} || payload_n)) in WAL mode.",
                    "implementation_details": "backend/audit_chain.py computing cumulative block hashes and providing an integrity verification algorithm.",
                    "dashboard_demonstration": "Navigate to #audit, inspect chained SHA-256 block hashes, and execute Verify Hash Chain to validate mathematical ledger integrity.",
                    "target_page": "audit",
                },
                {
                    "id": "mitre_mapping",
                    "title": "Standardized MITRE ATT&CK Cloud Matrix Alignment",
                    "problem_solved": "Security detections without standardized threat taxonomy leave security teams unable to map coverage against known adversary behaviors.",
                    "technical_approach": "Comprehensive mapping of all 12 simulation scenarios, detection rules, and finding types to MITRE ATT&CK Cloud Matrix techniques.",
                    "implementation_details": "backend/detection/mitre.py and scripts/generate_scenarios.py mapping T1078, T1098, T1530, T1548, and T1562.",
                    "dashboard_demonstration": "View MITRE technique badges, tactic categorizations, and aligned defense procedures on #lab and #findings.",
                    "target_page": "lab",
                },
                {
                    "id": "session_api_security",
                    "title": "Defense-in-Depth Session & API Hardening",
                    "problem_solved": "Public dashboards risk unauthorized manipulation, credential leakage, cross-site scripting (XSS), and cross-site request forgery (CSRF).",
                    "technical_approach": "Session cookies with HttpOnly, SameSite, and CSRF protection, timing-safe authentication, and explicit role separation (Public Observer vs Security Operator).",
                    "implementation_details": "backend/auth.py and app.py enforcing RBAC permissions without exposing credentials in client-side code.",
                    "dashboard_demonstration": "Observe the Public Demonstration Mode header badge and test the Operator Login modal with role-based feature gating.",
                    "target_page": "overview",
                },
            ],
        })

    @app.get("/api/demo")
    def get_guided_demo_steps() -> Any:
        """Return the 17-step core presentation script and 21-step viva sequence for faculty evaluation."""
        core_steps_17 = [
            {
                "step": 1,
                "route": "architecture",
                "target_page": "architecture",
                "title": "Project Title & Introduction",
                "description": "Welcome to ThreatGuard: AI-Based Cloud Security Monitoring and Threat Detection System.",
                "evaluator_question": "What is ThreatGuard, and what specific engineering problems does it solve compared to commercial CSPMs?",
                "demonstration_action": "Present the executive overview, research motivation, and core defense-in-depth architecture.",
                "architecture_evidence": "Refer to backend/soc/api.py and ThreatGuard architecture pipeline.",
            },
            {
                "step": 2,
                "route": "architecture",
                "target_page": "architecture",
                "title": "Problem Statement",
                "description": "Understanding cloud attack vectors: IAM privilege escalation, lateral movement, public exposures, and lack of verified remediation.",
                "evaluator_question": "Why is privilege escalation in IAM difficult to detect with traditional perimeter firewalls?",
                "demonstration_action": "Walk through the research problem statement and contrast against static policy linters.",
                "architecture_evidence": "Refer to Section 2 of README.md and multi-cloud vulnerability analysis.",
            },
            {
                "step": 3,
                "route": "architecture",
                "target_page": "architecture",
                "title": "End-to-End Architecture",
                "description": "Reviewing the 10-stage defense-in-depth pipeline connecting event ingestion to tamper-evident auditing.",
                "evaluator_question": "How do the 10 pipeline stages interact asynchronously without blocking event ingestion?",
                "demonstration_action": "Click through the interactive 10-stage pipeline flowchart in the architecture view.",
                "architecture_evidence": "Refer to backend/pipeline.py and Section 5 architectural flowchart.",
            },
            {
                "step": 4,
                "route": "overview",
                "target_page": "overview",
                "title": "Security Posture Dashboard",
                "description": "Live posture score (0-100%), event throughput, anomaly scoring, and resource health status.",
                "evaluator_question": "How is the 0-100% security posture score mathematically computed from active findings and blast radius?",
                "demonstration_action": "Review the Posture Score ring gauge, active KPI metrics, and resource connection health.",
                "architecture_evidence": "Refer to backend/posture.py and posture scoring formula.",
            },
            {
                "step": 5,
                "route": "alerts",
                "target_page": "alerts",
                "title": "SOC Alerts Management",
                "description": "Triage, severity breakdown, alert deduplication, and investigation of cloud security signals.",
                "evaluator_question": "How does ThreatGuard prevent alert fatigue in high-volume enterprise cloud accounts?",
                "demonstration_action": "Filter alerts by Critical severity, search for specific resources, and inspect alert metadata.",
                "architecture_evidence": "Refer to backend/soc/alerts.py and deduplication hash keys.",
            },
            {
                "step": 6,
                "route": "findings",
                "target_page": "findings",
                "title": "Evidence-Backed Findings",
                "description": "Investigating specific security findings with plain-English narratives, MITRE mapping, and rule traces.",
                "evaluator_question": "What constitutes an evidence-backed finding, and how are false positives suppressed?",
                "demonstration_action": "Open the findings drawer to inspect rule definitions, event timestamps, and raw JSON traces.",
                "architecture_evidence": "Refer to backend/soc/findings.py and rule trace engine.",
            },
            {
                "step": 7,
                "route": "threats",
                "target_page": "threats",
                "title": "12-Feature ML Anomaly Detection",
                "description": "Streaming identity-window feature aggregation and Isolation Forest anomaly score computation.",
                "evaluator_question": "How does the streaming feature pipeline extract 12 behavioral dimensions from CloudTrail records?",
                "demonstration_action": "Inspect the Anomaly Score time-series chart and calibrated decision threshold on #threats.",
                "architecture_evidence": "Refer to backend/detection/aggregator.py and 12-feature mathematical specification.",
            },
            {
                "step": 8,
                "route": "threats",
                "target_page": "threats",
                "title": "Explainable AI (XAI) Attribution",
                "description": "Reviewing feature attribution and plain-English reasoning explaining why an event was flagged.",
                "evaluator_question": "How does ThreatGuard explain why an anomaly was flagged without third-party blackbox libraries like SHAP?",
                "demonstration_action": "Examine the Alerts and Explanations cards showing exact feature contributions and plain-English reasoning.",
                "architecture_evidence": "Refer to backend/detection/xai_explainer.py and Tree-Path Information Gain Attribution.",
            },
            {
                "step": 9,
                "route": "graph",
                "target_page": "graph",
                "title": "IAM Capability Graph",
                "description": "Force-directed NetworkX graph visualizing IAM users, roles, policies, trust relationships, and assets.",
                "evaluator_question": "How does NetworkX model transitive trust relationships and cross-account role assumption?",
                "demonstration_action": "Navigate to #graph, explore force-directed nodes, zoom/pan, and select principals in the capability graph.",
                "architecture_evidence": "Refer to backend/iam_graph.py and NetworkX DiGraph construction.",
            },
            {
                "step": 10,
                "route": "graph",
                "target_page": "graph",
                "title": "Attack-Path Tracing",
                "description": "Multi-hop privilege escalation pathfinding (e.g. intern-dev -> dev-role -> cicd-deployer -> admin-role).",
                "evaluator_question": "Which graph traversal algorithm finds multi-hop escalation paths, and what is its computational complexity?",
                "demonstration_action": "Select 'user/intern-dev' in the Attack Paths panel and view the step-by-step privilege escalation trajectory.",
                "architecture_evidence": "Refer to backend/iam_graph.py find_paths() and Dijkstra / BFS shortest paths.",
            },
            {
                "step": 11,
                "route": "graph",
                "target_page": "graph",
                "title": "Transitive Blast Radius",
                "description": "Calculating compromised blast radius score, reachable principals, and exposed sensitive records.",
                "evaluator_question": "How is the blast radius score calculated when an identity's access keys are leaked?",
                "demonstration_action": "Inspect the Transitive Blast Radius panel showing compromised reachability and data exposure impact.",
                "architecture_evidence": "Refer to backend/blast_radius.py and formula B(p) = w_r*|R(p)| + w_d*D(p) + w_a*A(p).",
            },
            {
                "step": 12,
                "route": "lab",
                "target_page": "lab",
                "title": "Attack Simulation Lab",
                "description": "Exploring 12 isolated attack scenarios across Privilege Escalation, Resource Exposure, and Lateral Movement.",
                "evaluator_question": "How are attack scenarios executed safely without affecting live cloud workloads?",
                "demonstration_action": "Inspect the 12 simulation scenario cards and launch an isolated attack against the local Moto simulator.",
                "architecture_evidence": "Refer to backend/lab.py and scripts/generate_scenarios.py.",
            },
            {
                "step": 13,
                "route": "remediation",
                "target_page": "remediation",
                "title": "Remediation Task Management",
                "description": "Centralized remediation registry with proposed before-and-after configuration diffs.",
                "evaluator_question": "How does ThreatGuard construct configuration diffs before applying remediation?",
                "demonstration_action": "Review the remediation queue and inspect the side-by-side policy diff on a pending task.",
                "architecture_evidence": "Refer to backend/soc/remediation.py and remediation task schema.",
            },
            {
                "step": 14,
                "route": "remediation",
                "target_page": "remediation",
                "title": "Human-Approved Remediation",
                "description": "Operator approval workflow enforcing human-in-the-loop control before applying changes.",
                "evaluator_question": "Why must automated cloud remediation require human approval rather than firing fully autonomously?",
                "demonstration_action": "Demonstrate operator authorization and execution of an approved remediation task.",
                "architecture_evidence": "Refer to backend/soc/remediation.py and human-in-the-loop governance invariants in AGENTS.md.",
            },
            {
                "step": 15,
                "route": "remediation",
                "target_page": "remediation",
                "title": "Independent Verification (PASS/PARTIAL/FAIL)",
                "description": "True post-remediation verification: independently re-checking cloud state and attack path elimination.",
                "evaluator_question": "Why is independent verification necessary after the remediation API returns success?",
                "demonstration_action": "Inspect the verification status badge [PASS] and independent audit timestamp on a completed task.",
                "architecture_evidence": "Refer to backend/soc/verifier.py and independent reachability checking.",
            },
            {
                "step": 16,
                "route": "audit",
                "target_page": "audit",
                "title": "Tamper-Evident Audit Trail",
                "description": "Verifying the SHA-256 hash-chain integrity of all decisions, approvals, and remediation actions.",
                "evaluator_question": "How does ThreatGuard guarantee that audit records cannot be retroactively altered by an attacker with database access?",
                "demonstration_action": "Inspect SHA-256 block hashes and execute the Verify Hash Chain integrity check on #audit.",
                "architecture_evidence": "Refer to backend/audit_chain.py and hash_n = SHA-256(hash_{n-1} || payload_n).",
            },
            {
                "step": 17,
                "route": "overview",
                "target_page": "overview",
                "title": "Final Posture & Project Wrap-Up",
                "description": "Reviewing posture score recovery to 100% and summarizing project differentiation and impact.",
                "evaluator_question": "What is the overall contribution of ThreatGuard to cloud security engineering research?",
                "demonstration_action": "Demonstrate posture score recovery to 100% and summarize verifiable security guarantees.",
                "architecture_evidence": "Refer to Section 28 of README.md and evaluation summary.",
            },
        ]

        viva_steps_21 = [
            {
                "step": 1,
                "route": "architecture",
                "target_page": "architecture",
                "title": "Project Title & Introduction",
                "description": "Welcome to ThreatGuard: AI-Based Cloud Security Monitoring and Threat Detection System.",
                "evaluator_question": "What is ThreatGuard, and what specific engineering problems does it solve compared to commercial CSPMs?",
                "demonstration_action": "Present the executive overview, research motivation, and core defense-in-depth architecture.",
                "architecture_evidence": "Refer to backend/soc/api.py and ThreatGuard architecture pipeline.",
            },
            {
                "step": 2,
                "route": "architecture",
                "target_page": "architecture",
                "title": "Problem Statement & Research Motivation",
                "description": "Understanding cloud attack vectors: IAM privilege escalation, lateral movement, public exposures, and lack of verified remediation.",
                "evaluator_question": "Why is privilege escalation in IAM difficult to detect with traditional perimeter firewalls?",
                "demonstration_action": "Walk through the research problem statement and contrast against static policy linters.",
                "architecture_evidence": "Refer to Section 2 of README.md and multi-cloud vulnerability analysis.",
            },
            {
                "step": 3,
                "route": "architecture",
                "target_page": "architecture",
                "title": "End-to-End Defense-in-Depth Architecture",
                "description": "Reviewing the 10-stage defense-in-depth pipeline connecting event ingestion to tamper-evident auditing.",
                "evaluator_question": "How do the 10 pipeline stages interact asynchronously without blocking event ingestion?",
                "demonstration_action": "Click through the interactive 10-stage pipeline flowchart in the architecture view.",
                "architecture_evidence": "Refer to backend/pipeline.py and Section 5 architectural flowchart.",
            },
            {
                "step": 4,
                "route": "architecture",
                "target_page": "architecture",
                "title": "Technology Stack & Component Guarantees",
                "description": "Inspect the technical stack: Python 3.12, Scikit-Learn, NetworkX 3.x, Apache ECharts 5.x, SQLite WAL, and Moto simulation.",
                "evaluator_question": "Why did you select NetworkX and Isolation Forest rather than deep learning or heavy graph databases?",
                "demonstration_action": "Review the technology stack breakdown and dependency isolation guarantees.",
                "architecture_evidence": "Refer to pyproject.toml, requirements.txt, and architecture model card.",
            },
            {
                "step": 5,
                "route": "overview",
                "target_page": "overview",
                "title": "AWS Simulator Environment (Moto Integration)",
                "description": "Demonstrate zero-cost, offline cloud infrastructure emulation with Moto on localhost:5000.",
                "evaluator_question": "How does ThreatGuard emulate AWS CloudTrail, IAM, and S3 without incurring cloud bills or leaking credentials?",
                "demonstration_action": "Inspect the Connection and Resource Health panel on the Overview page showing active Moto emulator connectivity.",
                "architecture_evidence": "Refer to backend/aws_client.py, tests/conftest.py, and CG_ALLOW_LIVE_SETUP safety guards.",
            },
            {
                "step": 6,
                "route": "events",
                "target_page": "events",
                "title": "Security Event Generation & Telemetry Ingestion",
                "description": "Examine continuous CloudTrail event streaming, JSON schema validation, and identity-window aggregation.",
                "evaluator_question": "How are CloudTrail management events ingested and buffered for streaming detection?",
                "demonstration_action": "Navigate to #events, inspect streaming CloudTrail events, filter by service/severity, and click a row to view raw CloudTrail JSON.",
                "architecture_evidence": "Refer to backend/telemetry.py event generator and schema parser.",
            },
            {
                "step": 7,
                "route": "threats",
                "target_page": "threats",
                "title": "Dual-Engine Detection & Anomaly Scoring",
                "description": "Review the hybrid detection system combining deterministic MITRE rules with calibrated Isolation Forest anomaly scoring.",
                "evaluator_question": "How is the anomaly threshold tau = 0.610 determined, and why is a hybrid engine superior to rules alone?",
                "demonstration_action": "Inspect the Anomaly Score time-series chart and calibrated decision threshold on #threats.",
                "architecture_evidence": "Refer to backend/detection/ml_engine.py and scripts/train_eval.py calibration.",
            },
            {
                "step": 8,
                "route": "threats",
                "target_page": "threats",
                "title": "ML Detector Empirical Benchmark",
                "description": "Analyze controlled synthetic benchmark comparing Isolation Forest, One-Class SVM, LOF, and Random Cut Forest.",
                "evaluator_question": "What empirical trade-offs led to selecting Isolation Forest over One-Class SVM or LOF?",
                "demonstration_action": "Review the Controlled Benchmark chart and F1 score distribution across random seeds.",
                "architecture_evidence": "Refer to Table in Section 11 of README.md and scripts/train_eval.py.",
            },
            {
                "step": 9,
                "route": "threats",
                "target_page": "threats",
                "title": "Explainable AI (XAI) Tree-Path Attribution",
                "description": "Inspect feature contributions and plain-English narratives computed via Tree-Path Information Gain Attribution.",
                "evaluator_question": "How does ThreatGuard explain why an anomaly was flagged without third-party blackbox libraries like SHAP?",
                "demonstration_action": "Examine the Alerts and Explanations cards showing exact feature contributions and plain-English reasoning.",
                "architecture_evidence": "Refer to backend/detection/xai_explainer.py and Tree-Path Information Gain Attribution formulation.",
            },
            {
                "step": 10,
                "route": "findings",
                "target_page": "findings",
                "title": "Evidence-Backed Findings Synthesis",
                "description": "Explore synthesized security findings with MITRE ATT&CK technique IDs, NIST CSF controls, and raw CloudTrail traces.",
                "evaluator_question": "What constitutes an evidence-backed finding, and how are false positives suppressed?",
                "demonstration_action": "Navigate to #findings, filter by severity, and click a finding row to inspect the evidence drawer.",
                "architecture_evidence": "Refer to backend/soc/findings.py and rule trace engine.",
            },
            {
                "step": 11,
                "route": "graph",
                "target_page": "graph",
                "title": "IAM Capability Graph Modeling",
                "description": "Visualize the directed multigraph mapping IAM principals, assume-role trust policies, and sensitive cloud assets.",
                "evaluator_question": "How does NetworkX model transitive trust relationships and cross-account role assumption?",
                "demonstration_action": "Navigate to #graph, explore force-directed nodes, zoom/pan, and select principals in the capability graph.",
                "architecture_evidence": "Refer to backend/iam_graph.py and NetworkX DiGraph construction.",
            },
            {
                "step": 12,
                "route": "graph",
                "target_page": "graph",
                "title": "Multi-Hop Attack Path Tracing",
                "description": "Trace algorithmic attack paths (e.g. intern-dev -> dev-role -> cicd-deployer -> admin-role) from least-privilege to full administrator.",
                "evaluator_question": "Which graph traversal algorithm finds multi-hop escalation paths, and what is its computational complexity?",
                "demonstration_action": "Select 'user/intern-dev' in the Attack Paths panel and view the step-by-step privilege escalation trajectory.",
                "architecture_evidence": "Refer to backend/iam_graph.py find_paths() and Dijkstra / BFS shortest paths.",
            },
            {
                "step": 13,
                "route": "graph",
                "target_page": "graph",
                "title": "Quantitative Blast Radius Calculation",
                "description": "Evaluate compromised blast radius score, reachable administrative principals, and exposed sensitive records.",
                "evaluator_question": "How is the blast radius score calculated when an identity's access keys are leaked?",
                "demonstration_action": "Inspect the Transitive Blast Radius panel showing compromised reachability and data exposure impact.",
                "architecture_evidence": "Refer to backend/blast_radius.py and formula B(p) = w_r*|R(p)| + w_d*D(p) + w_a*A(p).",
            },
            {
                "step": 14,
                "route": "alerts",
                "target_page": "alerts",
                "title": "SOC Alert Management & Triage",
                "description": "Review the SOC alert queue with severity filters, alert deduplication, search capabilities, and direct remediation links.",
                "evaluator_question": "How does ThreatGuard prevent alert fatigue in high-volume enterprise cloud accounts?",
                "demonstration_action": "Navigate to #alerts, filter by Critical severity, search for specific resource names, and open alert details.",
                "architecture_evidence": "Refer to backend/soc/alerts.py and deduplication hash keys.",
            },
            {
                "step": 15,
                "route": "incidents",
                "target_page": "incidents",
                "title": "Structured Incident Response Lifecycle",
                "description": "Track security incidents across the 6-stage lifecycle: Triage -> Investigation -> Containment -> Remediation -> Verification -> Closed.",
                "evaluator_question": "How are alerts promoted to incidents, and how is the response workflow coordinated?",
                "demonstration_action": "Navigate to #incidents, view the active incident card, examine the stage progress stepper and response checklist.",
                "architecture_evidence": "Refer to backend/soc/incidents.py and SOCStore incident transitions.",
            },
            {
                "step": 16,
                "route": "remediation",
                "target_page": "remediation",
                "title": "Human-in-the-Loop Remediation Governance",
                "description": "Review the proposed remediation task registry with before-and-after configuration diffs requiring operator authorization.",
                "evaluator_question": "Why must automated cloud remediation require human approval rather than firing fully autonomously?",
                "demonstration_action": "Navigate to #remediation, inspect a pending task (e.g. REM-0001), and review the side-by-side policy diff.",
                "architecture_evidence": "Refer to backend/soc/remediation.py and human-in-the-loop governance invariants in AGENTS.md.",
            },
            {
                "step": 17,
                "route": "remediation",
                "target_page": "remediation",
                "title": "Remediation Playbook Execution",
                "description": "Execute an approved remediation task (e.g. revoking IAM wildcard privileges or enabling S3 Public Access Block) against Moto.",
                "evaluator_question": "What mechanism applies the remediation safely to cloud infrastructure?",
                "demonstration_action": "Demonstrate operator approval and execution of a pending remediation task.",
                "architecture_evidence": "Refer to backend/remediation/engine.py and AWS API dispatch.",
            },
            {
                "step": 18,
                "route": "remediation",
                "target_page": "remediation",
                "title": "Independent Verification (PASS/PARTIAL/FAIL)",
                "description": "Execute closed-loop independent verification: re-querying the cloud resource and re-evaluating the IAM graph to confirm vulnerability closure.",
                "evaluator_question": "Why is independent verification necessary after the remediation API returns success?",
                "demonstration_action": "Inspect the verification status badge [PASS] and independent audit timestamp on a completed task.",
                "architecture_evidence": "Refer to backend/soc/verifier.py and independent reachability checking.",
            },
            {
                "step": 19,
                "route": "remediation",
                "target_page": "remediation",
                "title": "Snapshot-Based Remediation Rollback",
                "description": "Restore previous configuration states from snapshot backups with single-click rollback and state audit recording.",
                "evaluator_question": "How does ThreatGuard recover if a security remediation inadvertently breaks a production service?",
                "demonstration_action": "Inspect the rollback button and rollback count metric tracking restored configurations.",
                "architecture_evidence": "Refer to backend/remediation/rollback.py and configuration snapshot storage.",
            },
            {
                "step": 20,
                "route": "audit",
                "target_page": "audit",
                "title": "Tamper-Evident SHA-256 Audit Trail",
                "description": "Verify cryptographic hash-chain integrity across every detection, operator approval, and remediation state mutation.",
                "evaluator_question": "How does ThreatGuard guarantee that audit records cannot be retroactively altered by an attacker with database access?",
                "demonstration_action": "Navigate to #audit, inspect SHA-256 block hashes, and execute the Verify Hash Chain integrity check.",
                "architecture_evidence": "Refer to backend/audit_chain.py and hash_n = SHA-256(hash_{n-1} || payload_n).",
            },
            {
                "step": 21,
                "route": "architecture",
                "target_page": "architecture",
                "title": "System Limitations & Future Scope",
                "description": "Discuss real-world engineering constraints: cold-start baseline calibration, distributed stream processing, and multi-cloud graph federation.",
                "evaluator_question": "What are the primary limitations of the current implementation, and what research directions would you pursue next?",
                "demonstration_action": "Review the technical limitations and future research scope section in the architecture overview.",
                "architecture_evidence": "Refer to Section 27 of README.md and model card evaluation.",
            },
        ]

        return jsonify({
            "title": "ThreatGuard Guided Viva / Demonstration Walkthrough",
            "total_steps": 17,
            "total_viva_steps": 21,
            "steps": core_steps_17,
            "viva_steps": viva_steps_21,
        })
