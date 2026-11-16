"""REST API Endpoints for CloudGuardian 2.0 IAM Attack Simulation Lab.

Implements all Part H endpoints:
- GET /api/scenarios: Catalog summaries
- GET /api/scenarios/<id>: Scenario details
- POST /api/scenarios/<id>/launch: Launch isolated run
- GET /api/scenarios/runs/<run_id>: Execution state & ECharts graph
- POST /api/scenarios/runs/<run_id>/analyze: Re-analyze graph
- POST /api/scenarios/runs/<run_id>/remediate: Apply simulated remediation
- POST /api/scenarios/runs/<run_id>/verify: Verify post-remediation security state
- POST /api/scenarios/runs/<run_id>/reset: Reset run to initial state
- POST /api/scenarios/custom: Build & analyze dynamic custom scenario
- POST /api/scenarios/validate-policy: Real-time IAM policy statement validation
"""
import logging
from typing import Any, Dict, List, Optional
from flask import Flask, jsonify, request
from pydantic import ValidationError

from backend.scenarios.definitions import (
    get_scenario_by_id,
    list_scenario_summaries,
)
from backend.scenarios.models import (
    ScenarioCategory,
    ScenarioDefinition,
    ScenarioDifficulty,
    StatementSpec,
)
from backend.scenarios.remediation import (
    apply_remediation,
    verify_remediation_state,
)
from backend.scenarios.session import (
    ScenarioSessionManager,
    scenario_session_manager,
)
from backend.security import require_auth

logger = logging.getLogger("cloudguardian.scenarios.api")


def register_scenarios_api(
    app: Flask,
    manager: Optional[ScenarioSessionManager] = None,
    state_store: Optional[Any] = None,
) -> None:
    """Register all scenario lab REST API endpoints on the Flask application."""
    mgr = manager or scenario_session_manager

    # 1. GET /api/scenarios - Catalog summaries
    @app.get("/api/scenarios")
    def list_scenarios() -> Any:
        """List all predefined scenarios with summary metadata and filtering."""
        category_filter = request.args.get("category")
        difficulty_filter = request.args.get("difficulty")

        summaries = list_scenario_summaries()

        if category_filter:
            summaries = [s for s in summaries if s["category"].lower() == category_filter.lower()]
        if difficulty_filter:
            summaries = [s for s in summaries if s["difficulty"].lower() == difficulty_filter.lower()]

        return jsonify({
            "total": len(summaries),
            "scenarios": summaries,
        })

    # 2. GET /api/scenarios/<scenario_id> - Scenario details
    @app.get("/api/scenarios/<scenario_id>")
    def get_scenario_details(scenario_id: str) -> Any:
        """Retrieve full details of a predefined scenario definition."""
        scenario_def = get_scenario_by_id(scenario_id)
        if not scenario_def:
            return jsonify({"error": f"Scenario '{scenario_id}' not found."}), 404

        return jsonify(scenario_def.model_dump())

    # 3. POST /api/scenarios/<scenario_id>/launch - Launch isolated run
    @app.post("/api/scenarios/<scenario_id>/launch")
    @require_auth
    def launch_scenario(scenario_id: str) -> Any:
        """Launch an isolated scenario simulation run."""
        scenario_def = get_scenario_by_id(scenario_id)
        if not scenario_def:
            return jsonify({"error": f"Scenario '{scenario_id}' not found."}), 404

        run = mgr.create_run(scenario_def)

        # Register persistent remediation task in SOC layer
        try:
            from backend.soc.store import soc_store
            exp_rem = scenario_def.expected_remediation or {"type": "generic_remediation"}
            target_res = exp_rem.get("target") or exp_rem.get("intermediate_hop") or scenario_def.id
            diff_str = scenario_def.difficulty.value if hasattr(scenario_def.difficulty, "value") else str(scenario_def.difficulty)
            sev_map = {"beginner": "Low", "intermediate": "High", "advanced": "Critical", "expert": "Critical"}
            sev_val = sev_map.get(diff_str.lower(), "High")

            soc_store.create_remediation_task(
                title=f"Lab Scenario Remediation: {scenario_def.name}",
                affected_resource=target_res,
                recommended_action=f"Apply {exp_rem.get('type', 'generic_remediation')} to sever attack path.",
                technical_explanation=f"Scenario '{scenario_def.id}' identified {len(run.paths)} potential IAM escalation paths with blast radius score {run.blast_radius.get('score', 0.0)}.",
                why_it_matters=scenario_def.learning_objective,
                proposed_change=exp_rem,
                severity=sev_val,
                related_finding_id=f"lab-{scenario_def.id}",
                scenario_id=scenario_def.id,
                run_id=run.run_id,
                before_config={
                    "scenario_id": scenario_def.id,
                    "run_id": run.run_id,
                    "attack_paths": len(run.paths),
                    "blast_radius_score": run.blast_radius.get("score", 0.0),
                    "admin_reachable": run.blast_radius.get("admin_reachable", False),
                },
                rollback_plan=f"Reset scenario run {run.run_id} to initial baseline graph.",
            )
        except Exception as _sync_err:
            logger.warning("Failed creating SOC remediation task for scenario %s: %s", scenario_id, _sync_err)

        return jsonify({
            "message": f"Scenario '{scenario_def.name}' launched successfully in isolated state.",
            "run_id": run.run_id,
            "scenario_id": run.scenario_id,
            "status": run.status.value,
            "findings_count": len(run.findings),
            "paths_count": len(run.paths),
            "blast_radius_score": run.blast_radius.get("score", 0.0),
        }), 201

    # 4. GET /api/scenarios/runs/<run_id> - Run state & ECharts graph
    @app.get("/api/scenarios/runs/<run_id>")
    def get_run_state(run_id: str) -> Any:
        """Retrieve current execution state, graph topology, and analysis metrics."""
        run = mgr.get_run(run_id)
        if not run:
            return jsonify({"error": f"Scenario run '{run_id}' not found."}), 404

        graph = mgr.get_graph(run_id)
        hl = request.args.get("highlight", "")
        highlight_path = [n.strip() for n in hl.split(",") if n.strip()] if hl else None

        graph_echarts = graph.export_echarts(highlight_path=highlight_path) if graph else {}

        resp = run.model_dump()
        resp["graph"] = graph_echarts
        return jsonify(resp)

    # 5. POST /api/scenarios/runs/<run_id>/analyze - Re-analyze graph
    @app.post("/api/scenarios/runs/<run_id>/analyze")
    @require_auth
    def reanalyze_run(run_id: str) -> Any:
        """Trigger deep re-analysis of the isolated capability graph."""
        payload = request.get_json(silent=True) or {}
        context = payload.get("context", {})

        try:
            run = mgr.analyze_run(run_id, context=context)
            return jsonify({
                "run_id": run.run_id,
                "status": run.status.value,
                "findings": [f.model_dump() for f in run.findings],
                "paths": run.paths,
                "blast_radius": run.blast_radius,
            })
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    # 6. POST /api/scenarios/runs/<run_id>/remediate - Apply simulated fix
    @app.post("/api/scenarios/runs/<run_id>/remediate")
    @require_auth
    def remediate_run(run_id: str) -> Any:
        """Apply a simulated remediation action to an isolated scenario run."""
        payload = request.get_json(silent=True) or {}
        action = payload.get("action")
        if not action and isinstance(payload, dict) and ("type" in payload or "target" in payload or "source" in payload):
            action = payload
        if not action or not isinstance(action, dict):
            return jsonify({"error": "Request body must include an 'action' object."}), 400

        try:
            result = apply_remediation(mgr, run_id, action, state_store=state_store)
            try:
                import time
                from backend.soc.store import soc_store
                from backend.soc.models import RemediationStatus, VerificationState
                for t in soc_store._remediations.values():
                    if t.run_id == run_id:
                        is_v = bool(result.get("verified", False))
                        t.status = RemediationStatus.VERIFIED if is_v else RemediationStatus.FAILED
                        t.verification_state = VerificationState.PASS if is_v else VerificationState.FAIL
                        t.verification_evidence = result
                        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                        t.applied_at = now_str
                        t.verified_at = now_str
                        t.updated_at = now_str
            except Exception as _sync_err:
                logger.warning("Failed syncing SOC remediation on remediate_run %s: %s", run_id, _sync_err)
            return jsonify(result)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404
        except Exception as exc:
            logger.error("Error applying remediation on run %s: %s", run_id, exc)
            return jsonify({"error": f"Failed to apply remediation: {str(exc)}"}), 500

    # 7. POST /api/scenarios/runs/<run_id>/verify - Verify post-remediation security state
    @app.post("/api/scenarios/runs/<run_id>/verify")
    @require_auth
    def verify_run(run_id: str) -> Any:
        """Verify current remediation status, remaining attack vectors, and blast radius delta."""
        try:
            result = verify_remediation_state(mgr, run_id)
            return jsonify(result)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    # 8. POST /api/scenarios/runs/<run_id>/reset - Reset run to initial state
    @app.post("/api/scenarios/runs/<run_id>/reset")
    @require_auth
    def reset_run(run_id: str) -> Any:
        """Restore an isolated scenario run to its initial configuration."""
        try:
            run = mgr.reset_run(run_id)
            return jsonify({
                "message": f"Scenario run '{run_id}' has been reset to initial simulated state.",
                "run_id": run.run_id,
                "status": run.status.value,
                "paths_count": len(run.paths),
                "findings_count": len(run.findings),
            })
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    # 9. POST /api/scenarios/custom - Build & analyze dynamic custom scenario
    @app.post("/api/scenarios/custom")
    @require_auth
    def create_custom_scenario() -> Any:
        """Validate, build, and analyze a dynamic user-created scenario."""
        payload = request.get_json(silent=True)
        if not payload or not isinstance(payload, dict):
            return jsonify({"error": "Request body must be a valid JSON object."}), 400

        # Enforce defaults for custom scenario
        payload["id"] = payload.get("id") or f"custom-{int(request.date or 0)}"
        payload["category"] = payload.get("category", ScenarioCategory.CUSTOM.value)
        payload["difficulty"] = payload.get("difficulty", ScenarioDifficulty.INTERMEDIATE.value)
        payload["learning_objective"] = payload.get("learning_objective", "Custom simulated cloud scenario.")
        payload["is_predefined"] = False

        try:
            custom_def = ScenarioDefinition.model_validate(payload)
        except ValidationError as exc:
            return jsonify({"error": "Scenario schema validation failed.", "details": exc.errors()}), 422

        run = mgr.create_run(custom_def)
        graph = mgr.get_graph(run.run_id)

        return jsonify({
            "message": "Custom scenario built and analyzed successfully.",
            "run_id": run.run_id,
            "status": run.status.value,
            "findings": [f.model_dump() for f in run.findings],
            "paths": run.paths,
            "blast_radius": run.blast_radius,
            "graph": graph.export_echarts() if graph else {},
        }), 201

    # 10. POST /api/scenarios/validate-policy - Real-time policy validation
    @app.post("/api/scenarios/validate-policy")
    @require_auth
    def validate_policy() -> Any:
        """Real-time validation of user-defined IAM policy statements."""
        payload = request.get_json(silent=True)
        if not payload or not isinstance(payload, dict):
            return jsonify({"error": "Request body must be a valid JSON object."}), 400

        raw_statements = payload.get("statements", [])
        if isinstance(raw_statements, dict):
            raw_statements = [raw_statements]

        warnings: List[str] = []
        parsed_statements: List[Dict[str, Any]] = []
        has_wildcard_action = False
        has_wildcard_resource = False
        has_explicit_deny = False

        for idx, stmt in enumerate(raw_statements):
            try:
                spec = StatementSpec.model_validate(stmt)
                parsed_statements.append(spec.to_iam_dict())

                if spec.effect == "Deny":
                    has_explicit_deny = True

                for act in spec.actions:
                    if act == "*" or act == "*:*":
                        has_wildcard_action = True
                        warnings.append(f"Statement {idx+1} permits unrestricted wildcard actions ('*').")
                    elif act.lower().startswith("iam:*"):
                        warnings.append(f"Statement {idx+1} permits all IAM management operations ('iam:*').")

                for res in spec.resources:
                    if res == "*":
                        has_wildcard_resource = True
                        warnings.append(f"Statement {idx+1} permits all resources ('*').")

                # Validate condition structure
                if spec.conditions:
                    for op, c_dict in spec.conditions.items():
                        if not isinstance(c_dict, dict):
                            warnings.append(f"Condition operator '{op}' in statement {idx+1} must be an object.")
            except ValidationError as exc:
                return jsonify({
                    "valid": False,
                    "error": f"Invalid statement format at index {idx+1}.",
                    "details": exc.errors(),
                }), 422

        # Assess risk level
        risk_level = "Low"
        if has_wildcard_action and has_wildcard_resource and not has_explicit_deny:
            risk_level = "Critical"
        elif has_wildcard_action or has_wildcard_resource:
            risk_level = "High"
        elif warnings:
            risk_level = "Medium"

        return jsonify({
            "valid": True,
            "statement_count": len(parsed_statements),
            "warnings": warnings,
            "risk_level": risk_level,
            "has_explicit_deny": has_explicit_deny,
            "normalized_statements": parsed_statements,
        })
