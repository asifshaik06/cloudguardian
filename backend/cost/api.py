"""REST API Endpoints for ThreatGuard Cost Intelligence & Cost Optimization.

Provides:
- GET  /api/cost/overview             Live inventory, cost estimation, breakdown, findings & comparison
- GET  /api/cost/pricing              Configurable pricing dataset metadata & rates
- GET  /api/cost/reports              List generated Cost Optimization Reports
- GET  /api/cost/reports/<report_id>  Retrieve immutable historical report snapshot
- POST /api/cost/reports/generate     Generate & persist a new Cost Optimization Report
- POST /api/cost/findings/<id>/remediate  Propose HITL remediation task in SOCStore
"""
import logging
from typing import Any, Dict, List, Optional
from flask import Flask, jsonify, request

from backend.cost.demo_scenario import (
    inspect_finops_demo_scenario,
    load_finops_demo_scenario,
    reset_finops_demo_scenario,
)
from backend.cost.pricing import load_pricing_catalog
from backend.cost.remediation import create_cost_remediation_task
from backend.cost.reports import (
    REPORTING_PERIODS,
    build_cost_intelligence_snapshot,
    generate_cost_report,
)
from backend.security import require_auth

logger = logging.getLogger("threatguard.cost.api")

VALID_SERVICES = {"ec2", "ebs", "s3", "iam", "cloudtrail"}


def _parse_optional_hours(raw_hours: Any) -> Optional[float]:
    if raw_hours is None or raw_hours == "":
        return None
    val = float(raw_hours)
    if val < 0 or val > 744:
        raise ValueError("operating_hours must be between 0 and 744.")
    return val


def _parse_regions(raw_regions: Optional[str]) -> Optional[List[str]]:
    if not raw_regions:
        return None
    regs = [r.strip() for r in raw_regions.split(",") if r.strip()]
    return regs or None


def register_cost_api(app: Flask, context: Dict[str, Any]) -> None:
    """Register Cost Intelligence API routes on the Flask application."""

    def _deps() -> Dict[str, Any]:
        return {
            "clients": app.config.get("COST_CLIENTS") or context.get("cost_clients"),
            "state_store": context.get("state_store"),
            "iam_graph": context.get("iam_graph"),
            "soc_store": context.get("soc_store"),
            "catalog": app.config.get("COST_PRICING_CATALOG") or load_pricing_catalog(),
        }

    @app.get("/api/cost/overview")
    def get_cost_overview() -> Any:
        """Analyze Moto/AWS resources and return full Cost Intelligence overview."""
        service_filter = (request.args.get("service") or "").strip().lower() or None
        if service_filter and service_filter not in VALID_SERVICES:
            return jsonify({
                "error": f"Unsupported service filter '{service_filter}'. Supported: {sorted(VALID_SERVICES)}"
            }), 400

        region_filter = (request.args.get("region") or "").strip().lower() or None
        regions = _parse_regions(request.args.get("regions"))
        period = (request.args.get("period") or "monthly").strip().lower()
        if period not in REPORTING_PERIODS:
            return jsonify({
                "error": f"Invalid reporting period '{period}'. Valid: {sorted(REPORTING_PERIODS.keys())}"
            }), 400

        try:
            hours = _parse_optional_hours(request.args.get("hours"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        deps = _deps()
        snap = build_cost_intelligence_snapshot(
            clients=deps["clients"],
            state_store=deps["state_store"],
            iam_graph=deps["iam_graph"],
            soc_store=deps["soc_store"],
            catalog=deps["catalog"],
            operating_hours_per_month=hours,
            service_filter=service_filter,
            region_filter=region_filter,
            regions=regions,
            reporting_period=period,
        )

        est = snap["estimation"]
        opt = snap["optimization"]
        comp = snap["cost_comparison"]
        rem = snap["remediation_summary"]
        inv = snap["inventory"]

        period_months = float(snap["period_months"])
        monthly_cost = est["total_monthly_cost"]

        return jsonify({
            "environment": inv["environment"],
            "simulator_available": inv["simulator_available"],
            "account_id": inv["account_id"],
            "collected_at": inv["collected_at"],
            "regions_scanned": inv["regions_scanned"],
            "reporting_period": snap["reporting_period"],
            "reporting_period_label": snap["reporting_period_label"],
            "service_filter": service_filter or "all",
            "region_filter": region_filter or "all",
            "cost_overview": {
                "currency": est["currency"],
                "estimated_monthly_cost": monthly_cost,
                "estimated_annual_cost": est["total_annual_cost"],
                "period_estimated_cost": round(monthly_cost * period_months, 4),
                "potential_monthly_savings": comp["potential_monthly_savings"],
                "potential_annual_savings": comp["potential_annual_savings"],
                "optimized_monthly_cost": comp["optimized_estimated_monthly_cost"],
                "realized_monthly_savings": comp["realized_monthly_savings"],
                "percentage_reduction": comp["percentage_reduction"],
                "analyzed_resources": est["analyzed_resources_count"],
                "priced_resources": est["priced_resources_count"],
                "unpriced_resources": est["unpriced_resources_count"],
                "optimization_findings": opt["findings_count"],
                "confirmed_findings": opt["confirmed_findings_count"],
                "inferred_findings": opt["inferred_findings_count"],
            },
            "service_breakdown": est["service_breakdown"],
            "resources": est["resources"],
            "findings": opt["findings"],
            "cost_comparison": comp,
            "remediation_summary": rem,
            "service_availability": inv["service_availability"],
            "cloudtrail_summary": inv["cloudtrail_summary"],
            "pricing_metadata": snap["pricing_metadata"],
        })

    @app.get("/api/cost/pricing")
    def get_cost_pricing() -> Any:
        """Return configurable pricing dataset metadata and rate catalog."""
        deps = _deps()
        return jsonify(deps["catalog"].to_dict())

    @app.get("/api/cost/reports")
    def list_cost_reports() -> Any:
        """List stored historical Cost Optimization Reports."""
        service_filter = (request.args.get("service") or "").strip().lower() or None
        period = (request.args.get("period") or "").strip().lower() or None
        try:
            limit = min(200, max(1, int(request.args.get("limit", 50))))
        except ValueError:
            return jsonify({"error": "limit must be an integer."}), 400

        store = context.get("state_store")
        if store is None or not hasattr(store, "list_cost_reports"):
            return jsonify({"total": 0, "reports": []})

        reports = store.list_cost_reports(
            service_filter=service_filter,
            reporting_period=period,
            limit=limit,
        )
        return jsonify({"total": len(reports), "reports": reports})

    @app.get("/api/cost/reports/<report_id>")
    def get_cost_report_detail(report_id: str) -> Any:
        """Retrieve a specific historical Cost Optimization Report snapshot."""
        store = context.get("state_store")
        if store is None or not hasattr(store, "get_cost_report"):
            return jsonify({"error": "Report persistence unavailable."}), 503

        report = store.get_cost_report(report_id)
        if not report:
            return jsonify({"error": f"Cost report '{report_id}' not found."}), 404
        return jsonify(report)

    @app.post("/api/cost/reports/generate")
    @require_auth
    def generate_cost_report_endpoint() -> Any:
        """Generate and persist a dynamic Cost Optimization Report."""
        payload = request.get_json(silent=True) or {}
        service_filter = (payload.get("service") or "").strip().lower() or None
        if service_filter and service_filter not in VALID_SERVICES:
            return jsonify({
                "ok": False,
                "error": f"Unsupported service filter '{service_filter}'.",
            }), 400

        region_filter = (payload.get("region") or "").strip().lower() or None
        regions = _parse_regions(payload.get("regions")) if isinstance(payload.get("regions"), str) else payload.get("regions")
        period = (payload.get("reporting_period") or "monthly").strip().lower()
        if period not in REPORTING_PERIODS:
            return jsonify({
                "ok": False,
                "error": f"Invalid reporting_period '{period}'. Valid: {sorted(REPORTING_PERIODS.keys())}",
            }), 400

        try:
            hours = _parse_optional_hours(payload.get("operating_hours"))
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        deps = _deps()
        report = generate_cost_report(
            clients=deps["clients"],
            state_store=deps["state_store"],
            iam_graph=deps["iam_graph"],
            soc_store=deps["soc_store"],
            catalog=deps["catalog"],
            operating_hours_per_month=hours,
            service_filter=service_filter,
            region_filter=region_filter,
            regions=regions,
            reporting_period=period,
            persist=True,
        )
        return jsonify({
            "ok": True,
            "report_id": report["report_information"]["report_id"],
            "report": report,
        }), 201

    @app.post("/api/cost/findings/<finding_id>/remediate")
    @require_auth
    def propose_cost_remediation(finding_id: str) -> Any:
        """Stage a Cost Optimization finding into the SOC HITL remediation queue."""
        deps = _deps()
        soc_store = deps["soc_store"]
        if soc_store is None:
            return jsonify({"ok": False, "error": "SOC remediation store unavailable."}), 503

        payload = request.get_json(silent=True) or {}
        region_filter = (payload.get("region") or "").strip().lower() or None
        regions = payload.get("regions")

        snap = build_cost_intelligence_snapshot(
            clients=deps["clients"],
            state_store=deps["state_store"],
            iam_graph=deps["iam_graph"],
            soc_store=soc_store,
            catalog=deps["catalog"],
            region_filter=region_filter,
            regions=regions,
        )
        findings = snap["optimization"]["findings"]
        target = next((f for f in findings if f["id"] == finding_id), None)
        if not target:
            return jsonify({
                "ok": False,
                "error": f"Cost optimization finding '{finding_id}' not found in current inventory.",
            }), 404

        task = create_cost_remediation_task(
            finding=target,
            soc_store=soc_store,
            state_store=deps["state_store"],
        )
        return jsonify({
            "ok": True,
            "message": f"Remediation task '{task.id}' staged for human approval.",
            "remediation": task.model_dump(),
        }), 201

    @app.get("/api/cost/demo-scenario")
    def get_finops_demo_scenario() -> Any:
        """Inspect optional FinOps demo scenario resources in local Moto simulator."""
        deps = _deps()
        status = inspect_finops_demo_scenario(clients=deps["clients"])
        return jsonify(status)

    @app.post("/api/cost/demo-scenario/load")
    @require_auth
    def load_finops_demo_scenario_endpoint() -> Any:
        """Idempotently provision optional FinOps demo resources in Moto."""
        deps = _deps()
        try:
            status = load_finops_demo_scenario(
                clients=deps["clients"],
                state_store=deps["state_store"],
            )
            return jsonify({"ok": True, **status}), 201
        except PermissionError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 403
        except ConnectionError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 503
        except Exception as exc:
            logger.error("Failed loading FinOps demo scenario: %s", exc)
            return jsonify({"ok": False, "error": str(exc)}), 500

    @app.post("/api/cost/demo-scenario/reset")
    @require_auth
    def reset_finops_demo_scenario_endpoint() -> Any:
        """Reset only FinOps demo scenario resources in Moto."""
        deps = _deps()
        try:
            status = reset_finops_demo_scenario(
                clients=deps["clients"],
                state_store=deps["state_store"],
                soc_store=deps["soc_store"],
            )
            return jsonify({"ok": True, **status})
        except PermissionError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 403
        except ConnectionError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 503
        except Exception as exc:
            logger.error("Failed resetting FinOps demo scenario: %s", exc)
            return jsonify({"ok": False, "error": str(exc)}), 500
