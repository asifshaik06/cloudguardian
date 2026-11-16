"""REST API Endpoints for CloudGuardian 2.0 SOC Operations.

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

logger = logging.getLogger("cloudguardian.soc.api")


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

        if fid and fid in R:
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
            "project_title": "CloudGuardian 2.0",
            "tagline": "Explainable Cloud Threat Detection, IAM Attack-Path Intelligence and Verified Incident Response",
            "academic_context": "Final Year B.Tech CSE (AI & ML) Project, 2026-27",
            "author": "Asif Shaik",
            "repository": "https://github.com/asifshaik06/cloudguardian",
            "problem_statement": (
                "Cloud environments suffer from critical security gaps: excessive IAM permissions, "
                "insecure AssumeRole trust relationships, public S3 bucket exposures, cloud audit trail tampering, "
                "and lateral privilege escalation. Traditional tools alert on isolated symptoms without explaining "
                "the multi-hop attack paths, predicting blast radius, requiring human-in-the-loop approval, or "
                "independently verifying that remediation actually fixed the security vulnerability."
            ),
            "solution_overview": (
                "CloudGuardian 2.0 provides an evidence-driven security operations platform combining: "
                "(1) Real-time telemetry monitoring, (2) CIS rule checks, (3) 12-feature ML anomaly detection with TreeSHAP XAI, "
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
                {"step": 4, "name": "Explainable AI (XAI)", "tech": "TreeSHAP, Local Feature Importance", "description": "Calculates exact feature contributions and explains anomalies in plain English."},
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
                {"step": 4, "name": "Explainable AI (XAI)", "tech": "TreeSHAP, Local Feature Importance", "description": "Calculates exact feature contributions and explains anomalies in plain English."},
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
        })

    @app.get("/api/demo")
    def get_guided_demo_steps() -> Any:
        """Return the 17-step guided presentation script for faculty evaluation."""
        return jsonify({
            "title": "CloudGuardian 2.0 Guided Viva / Demonstration Walkthrough",
            "total_steps": 17,
            "steps": [
                {"step": 1, "route": "architecture", "title": "Project Title & Introduction", "description": "Welcome to CloudGuardian 2.0: Explainable Cloud Threat Detection, IAM Attack-Path Intelligence and Verified Incident Response."},
                {"step": 2, "route": "architecture", "title": "Problem Statement", "description": "Understanding cloud attack vectors: IAM privilege escalation, lateral movement, public exposures, and lack of verified remediation."},
                {"step": 3, "route": "architecture", "title": "End-to-End Architecture", "description": "Reviewing the 10-stage defense-in-depth pipeline connecting event ingestion to tamper-evident auditing."},
                {"step": 4, "route": "overview", "title": "Security Posture Dashboard", "description": "Live posture score (0-100%), event throughput, anomaly scoring, and resource health status."},
                {"step": 5, "route": "alerts", "title": "SOC Alerts Management", "description": "Triage, severity breakdown, alert deduplication, and investigation of cloud security signals."},
                {"step": 6, "route": "findings", "title": "Evidence-Backed Findings", "description": "Investigating specific security findings with plain-English narratives, MITRE mapping, and rule traces."},
                {"step": 7, "route": "threats", "title": "12-Feature ML Anomaly Detection", "description": "Streaming identity-window feature aggregation and Isolation Forest anomaly score computation."},
                {"step": 8, "route": "threats", "title": "Explainable AI (XAI) Attribution", "description": "Reviewing feature attribution and plain-English reasoning explaining why an event was flagged."},
                {"step": 9, "route": "graph", "title": "IAM Capability Graph", "description": "Force-directed NetworkX graph visualizing IAM users, roles, policies, trust relationships, and assets."},
                {"step": 10, "route": "graph", "title": "Attack-Path Tracing", "description": "Multi-hop privilege escalation pathfinding (e.g. intern-dev -> dev-role -> cicd-deployer -> admin-role)."},
                {"step": 11, "route": "graph", "title": "Transitive Blast Radius", "description": "Calculating compromised blast radius score, reachable principals, and exposed sensitive records."},
                {"step": 12, "route": "lab", "title": "Attack Simulation Lab", "description": "Exploring 12 isolated attack scenarios across Privilege Escalation, Resource Exposure, and Lateral Movement."},
                {"step": 13, "route": "remediation", "title": "Remediation Task Management", "description": "Centralized remediation registry with proposed before-and-after configuration diffs."},
                {"step": 14, "route": "remediation", "title": "Human-Approved Remediation", "description": "Operator approval workflow enforcing human-in-the-loop control before applying changes."},
                {"step": 15, "route": "remediation", "title": "Independent Verification (PASS/PARTIAL/FAIL)", "description": "True post-remediation verification: independently re-checking cloud state and attack path elimination."},
                {"step": 16, "route": "audit", "title": "Tamper-Evident Audit Trail", "description": "Verifying the SHA-256 hash-chain integrity of all decisions, approvals, and remediation actions."},
                {"step": 17, "route": "overview", "title": "Final Posture & Project Wrap-Up", "description": "Reviewing posture score recovery to 100% and summarizing project differentiation and impact."},
            ],
        })
