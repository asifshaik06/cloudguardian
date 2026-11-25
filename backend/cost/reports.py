"""Text-Based AWS Cost Optimization Report Generator & History Manager.

Generates comprehensive, readable 11-section FinOps reports dynamically from
live inventory, pricing catalog, cost estimation, optimization findings, and
actual SOCStore remediation records. Persists immutable report snapshots in
ThreatGuard's existing SQLite StateStore without exposing filesystem paths.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from backend.cost.estimator import estimate_infrastructure_costs
from backend.cost.inventory import collect_resource_inventory
from backend.cost.optimizer import analyze_cost_optimizations
from backend.cost.pricing import PricingCatalog, load_pricing_catalog
from backend.cost.remediation import summarize_cost_remediations

REPORTING_PERIODS: Dict[str, Dict[str, Any]] = {
    "monthly": {"label": "Monthly (30-Day / 730h Baseline)", "months": 1.0},
    "quarterly": {"label": "Quarterly (90-Day Projection)", "months": 3.0},
    "annual": {"label": "Annual (365-Day Projection)", "months": 12.0},
}


def normalize_reporting_period(period: Optional[str]) -> str:
    p = (period or "monthly").strip().lower()
    if p in REPORTING_PERIODS:
        return p
    return "monthly"


def _build_narrative_text(report: Dict[str, Any]) -> str:
    """Render a structured, readable plain-text report body for in-dashboard reading."""
    info = report["report_information"]
    exec_sum = report["executive_summary"]
    ov = report["cost_overview"]
    services = report["service_wise_cost_analysis"]
    resources = report["resource_level_analysis"]
    findings = report["cost_optimization_findings"]
    recs = report["optimization_recommendations"]
    comp = report["before_after_cost_comparison"]
    rem = report["remediation_summary"]
    assess = report["final_assessment"]
    meth = report["methodology_and_limitations"]

    cur = info.get("currency", "USD")
    lines: List[str] = [
        f"1. REPORT INFORMATION",
        f"Title: {info['report_title']}",
        f"Report ID: {info['report_id']}",
        f"Generated At: {info['generated_at']}",
        f"Reporting Period: {info['reporting_period_label']}",
        f"Environment: {info['environment']} (Account: {info['account_id']})",
        f"Currency: {cur} | Pricing Dataset Version: {info['pricing_dataset_version']} | "
        f"Operating Hours Assumption: {info.get('operating_hours_per_month', 730):g}h/mo",
        "",
        "2. EXECUTIVE SUMMARY",
        exec_sum["overview_narrative"],
        f"Main Cost Drivers: {', '.join(exec_sum['main_cost_drivers']) or 'None observed'}",
        f"Major Optimization Opportunities: {', '.join(exec_sum['major_opportunities']) or 'None identified'}",
        f"Estimated Potential Savings: {cur} {exec_sum['potential_monthly_savings']:.2f}/month "
        f"({cur} {exec_sum['potential_annual_savings']:.2f}/year) | "
        f"Realized Verified Savings: {cur} {exec_sum['realized_monthly_savings']:.2f}/month",
        "",
        "3. COST OVERVIEW",
        f"- Estimated Monthly Cost: {cur} {ov['estimated_monthly_cost']:.2f}",
        f"- Estimated Annual Cost: {cur} {ov['estimated_annual_cost']:.2f}",
        f"- Period-Scaled Cost ({info['reporting_period_label']}): {cur} {ov['period_estimated_cost']:.2f}",
        f"- Optimized Monthly Cost: {cur} {ov['optimized_monthly_cost']:.2f}",
        f"- Potential Monthly Savings: {cur} {ov['potential_monthly_savings']:.2f} ({ov['percentage_reduction']:.2f}% reduction)",
        f"- Realized Verified Monthly Savings: {cur} {ov['realized_monthly_savings']:.2f}",
        "",
        "4. SERVICE-WISE COST ANALYSIS",
    ]

    if services:
        for s in services:
            m_val = s.get("estimated_monthly_cost")
            m_str = f"{cur} {m_val:.2f}/mo" if m_val is not None else "Unavailable"
            lines.append(
                f"- {s['service'].upper()}: {s['resource_count']} resource(s) | Status: {s.get('service_status', 'n/a')} | "
                f"{m_str} ({s['percentage_of_total']:.1f}%) | "
                f"Opportunities: {s['optimization_opportunities']}"
            )
    else:
        lines.append("- No resources observed for the selected scope.")

    lines.extend(["", "5. RESOURCE-LEVEL ANALYSIS"])
    if resources:
        for r in resources:
            cost_str = f"{cur} {r['estimated_monthly_cost']:.2f}/mo" if r["estimated_monthly_cost"] is not None else "Unavailable"
            lines.append(
                f"- [{r['service'].upper()}] {r['resource_id']} ({r['resource_type']}, {r['region']}, state={r['state']}, "
                f"status={r.get('cost_status', r['estimation_basis'])}): "
                f"{cost_str} | Potential Savings: {cur} {r['potential_monthly_savings']:.2f}/mo | {r['assumption_note']}"
            )
    else:
        lines.append("- No individual resources analyzed.")

    lines.extend(["", "6. COST OPTIMIZATION FINDINGS"])
    if findings:
        for f in findings:
            lines.append(
                f"- [{f['priority']} | {f['severity']} | {f['classification'].upper()}] {f['id']} - {f['title']} "
                f"(Resource: {f['affected_resource']})"
            )
    else:
        lines.append("- No cost optimization findings detected in current scope.")

    lines.extend(["", "7. OPTIMIZATION RECOMMENDATIONS"])
    if recs:
        for rec in recs:
            lines.append(
                f"- {rec['finding_id']}: {rec['recommended_action']} | "
                f"Est. Savings: {cur} {rec['estimated_monthly_savings']:.2f}/mo | Risk: {rec['risk_of_implementation']}"
            )
    else:
        lines.append("- No optimization recommendations pending.")

    lines.extend([
        "",
        "8. BEFORE-AND-AFTER COST COMPARISON",
        f"- Current Estimated Monthly Cost: {cur} {comp['current_estimated_monthly_cost']:.2f}",
        f"- Potential Monthly Savings: {cur} {comp['potential_monthly_savings']:.2f}",
        f"- Optimized Estimated Monthly Cost: {cur} {comp['optimized_estimated_monthly_cost']:.2f}",
        f"- Percentage Reduction: {comp['percentage_reduction']:.2f}%",
        f"- Realized Monthly Savings (Independently Verified): {cur} {comp['realized_monthly_savings']:.2f}",
        "",
        "9. REMEDIATION SUMMARY (ACTUAL WORKFLOW RECORDS)",
        f"- All SOC/FinOps Tasks -> Approved: {rem['all_tasks_summary']['approved']}, "
        f"Executed: {rem['all_tasks_summary']['executed']}, Failed: {rem['all_tasks_summary']['failed']}, "
        f"Independently Verified: {rem['all_tasks_summary']['independently_verified']}, "
        f"Pending: {rem['all_tasks_summary']['pending']}",
        f"- Cost Optimization Tasks -> Approved: {rem['cost_tasks_summary']['approved']}, "
        f"Executed: {rem['cost_tasks_summary']['executed']}, Failed: {rem['cost_tasks_summary']['failed']}, "
        f"Independently Verified: {rem['cost_tasks_summary']['independently_verified']}, "
        f"Pending: {rem['cost_tasks_summary']['pending']}",
        "",
        "10. FINAL ASSESSMENT",
        assess["summary"],
        f"Unresolved Risks: {'; '.join(assess['unresolved_risks']) or 'None'}",
        f"Recommended Next Steps: {'; '.join(assess['next_steps'])}",
        "",
        "11. METHODOLOGY AND LIMITATIONS",
        f"- Pricing Assumptions: {meth['pricing_assumptions']}",
        f"- Usage Assumptions: {meth['usage_assumptions']}",
        f"- Simulator Limitations: {'; '.join(meth['simulator_limitations'])}",
        f"- Billing Disclaimer: {meth['billing_disclaimer']}",
    ])
    return "\n".join(lines)


def build_cost_intelligence_snapshot(
    clients: Optional[Dict[str, Any]] = None,
    state_store: Optional[Any] = None,
    iam_graph: Optional[Any] = None,
    soc_store: Optional[Any] = None,
    catalog: Optional[PricingCatalog] = None,
    operating_hours_per_month: Optional[float] = None,
    service_filter: Optional[str] = None,
    region_filter: Optional[str] = None,
    regions: Optional[List[str]] = None,
    reporting_period: str = "monthly",
) -> Dict[str, Any]:
    """Run full inventory -> estimation -> optimization -> remediation summary pipeline."""
    cat = catalog or load_pricing_catalog()
    period_key = normalize_reporting_period(reporting_period)
    period_meta = REPORTING_PERIODS[period_key]

    inventory = collect_resource_inventory(
        clients=clients,
        state_store=state_store,
        iam_graph=iam_graph,
        regions=regions,
    )
    # Estimate full inventory first when service_filter is set so EC2<->EBS cross-resource evidence is preserved
    full_resources = None
    if service_filter:
        full_est = estimate_infrastructure_costs(
            inventory=inventory,
            catalog=cat,
            operating_hours_per_month=operating_hours_per_month,
            service_filter=None,
            region_filter=region_filter,
        )
        full_resources = full_est["resources"]

    estimation = estimate_infrastructure_costs(
        inventory=inventory,
        catalog=cat,
        operating_hours_per_month=operating_hours_per_month,
        service_filter=service_filter,
        region_filter=region_filter,
    )
    optimization = analyze_cost_optimizations(
        inventory=inventory,
        estimation=estimation,
        catalog=cat,
        all_estimated_resources=full_resources,
    )
    remediation_summary = summarize_cost_remediations(soc_store)

    comp = dict(optimization["cost_comparison"])
    comp["realized_monthly_savings"] = remediation_summary["realized_monthly_savings"]

    return {
        "inventory": inventory,
        "pricing_metadata": cat.to_metadata_dict(),
        "reporting_period": period_key,
        "reporting_period_label": period_meta["label"],
        "period_months": period_meta["months"],
        "estimation": estimation,
        "optimization": optimization,
        "cost_comparison": comp,
        "remediation_summary": remediation_summary,
    }


def generate_cost_report(
    clients: Optional[Dict[str, Any]] = None,
    state_store: Optional[Any] = None,
    iam_graph: Optional[Any] = None,
    soc_store: Optional[Any] = None,
    catalog: Optional[PricingCatalog] = None,
    operating_hours_per_month: Optional[float] = None,
    service_filter: Optional[str] = None,
    region_filter: Optional[str] = None,
    regions: Optional[List[str]] = None,
    reporting_period: str = "monthly",
    persist: bool = True,
) -> Dict[str, Any]:
    """Generate the complete 11-section Cost Optimization Report and optionally persist."""
    snapshot = build_cost_intelligence_snapshot(
        clients=clients,
        state_store=state_store,
        iam_graph=iam_graph,
        soc_store=soc_store,
        catalog=catalog,
        operating_hours_per_month=operating_hours_per_month,
        service_filter=service_filter,
        region_filter=region_filter,
        regions=regions,
        reporting_period=reporting_period,
    )

    inv = snapshot["inventory"]
    est = snapshot["estimation"]
    opt = snapshot["optimization"]
    comp = snapshot["cost_comparison"]
    rem = snapshot["remediation_summary"]
    pricing_meta = snapshot["pricing_metadata"]
    period_key = snapshot["reporting_period"]
    period_label = snapshot["reporting_period_label"]
    period_months = float(snapshot["period_months"])

    now_utc = datetime.now(timezone.utc)
    report_id = f"FINOPS-RPT-{now_utc.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
    generated_at = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    svc_breakdown = est["service_breakdown"]
    cost_drivers = [
        f"{s['service'].upper()} ({est['currency']} {s['estimated_monthly_cost']:.2f}/mo, {s['percentage_of_total']:.1f}%)"
        for s in svc_breakdown
        if s.get("estimated_monthly_cost") is not None and s["estimated_monthly_cost"] > 0
    ][:3]

    findings = opt["findings"]
    major_opps = [f"{f['title']} ({f['affected_resource']})" for f in findings[:4]]

    monthly_cost = est["total_monthly_cost"]
    annual_cost = est["total_annual_cost"]
    period_cost = round(monthly_cost * period_months, 4)
    potential_monthly = comp["potential_monthly_savings"]
    potential_annual = comp["potential_annual_savings"]
    optimized_monthly = comp["optimized_estimated_monthly_cost"]
    pct_reduction = comp["percentage_reduction"]
    realized_monthly = comp["realized_monthly_savings"]

    exec_narrative = (
        f"ThreatGuard analyzed {est['analyzed_resources_count']} cloud resource(s) in "
        f"{inv['environment']} (account {inv['account_id']}). "
        f"Estimated baseline spend is {est['currency']} {monthly_cost:.2f}/month "
        f"({est['currency']} {annual_cost:.2f}/year) based on pricing dataset {pricing_meta['dataset_version']}. "
        f"Identified {len(findings)} optimization finding(s) representing "
        f"{est['currency']} {potential_monthly:.2f}/month ({pct_reduction:.1f}%) in potential savings, "
        f"with {est['currency']} {realized_monthly:.2f}/month independently verified as realized."
    )

    recommendations = [
        {
            "finding_id": f["id"],
            "title": f["title"],
            "severity": f["severity"],
            "priority": f["priority"],
            "classification": f["classification"],
            "affected_resource": f["affected_resource"],
            "service": f["service"],
            "supporting_evidence": f["supporting_evidence"],
            "why_it_matters": f["why_it_matters"],
            "recommended_action": f["recommended_action"],
            "estimated_monthly_savings": f["estimated_monthly_savings"],
            "savings_status": f.get("savings_status", "Calculated"),
            "savings_basis": f["savings_basis"],
            "risk_of_implementation": f["risk_of_implementation"],
        }
        for f in findings
    ]

    unresolved_risks: List[str] = []
    if not inv.get("simulator_available"):
        unresolved_risks.append("Local Moto simulator was offline during collection; live simulated resources unavailable.")
    if est.get("unpriced_resources_count", 0) > 0:
        unresolved_risks.append(f"{est['unpriced_resources_count']} resource(s) could not be priced due to missing metadata or pricing rates.")
    if opt.get("inferred_findings_count", 0) > 0:
        unresolved_risks.append(f"{opt['inferred_findings_count']} finding(s) are inferred without CPU/memory utilization telemetry.")
    if rem["cost_tasks_summary"]["pending"] > 0:
        unresolved_risks.append(f"{rem['cost_tasks_summary']['pending']} cost remediation task(s) remain pending human approval.")

    next_steps: List[str] = []
    if findings:
        next_steps.append("Review confirmed optimization findings and submit high-savings actions for operator approval.")
        next_steps.append("Validate workload CPU/memory metrics before approving inferred EC2 rightsizing recommendations.")
    else:
        next_steps.append("Continue monitoring resource provisioning and re-generate report after infrastructure changes.")
    next_steps.append("Apply missing FinOps ownership tags to enable cost allocation across teams.")

    missing_fields_notes: List[str] = [
        "EC2 CPU/memory/network utilization metrics are unavailable in Moto simulator.",
        "S3 request counts (PUT/GET) and cross-region data transfer volumes are not simulated.",
        "CloudTrail LookupEvents is unsupported in Moto 5.2.5; event context uses ThreatGuard StateStore telemetry.",
        "AWS Cost Explorer / Cost and Usage Report (CUR) actual billing lines are unavailable offline.",
    ]

    report: Dict[str, Any] = {
        "report_information": {
            "report_title": "ThreatGuard AWS Cost Intelligence & Optimization Report",
            "report_id": report_id,
            "generated_at": generated_at,
            "reporting_period": period_key,
            "reporting_period_label": period_label,
            "service_filter": service_filter or "all",
            "region_filter": region_filter or "all",
            "environment": inv["environment"],
            "account_id": inv["account_id"],
            "simulator_available": inv["simulator_available"],
            "currency": est["currency"],
            "pricing_dataset_version": pricing_meta["dataset_version"],
            "pricing_effective_date": pricing_meta["effective_date"],
            "operating_hours_per_month": est["operating_hours_per_month"],
        },
        "executive_summary": {
            "overview_narrative": exec_narrative,
            "main_cost_drivers": cost_drivers,
            "major_opportunities": major_opps,
            "estimated_monthly_cost": monthly_cost,
            "potential_monthly_savings": potential_monthly,
            "potential_annual_savings": potential_annual,
            "realized_monthly_savings": realized_monthly,
            "analyzed_resources": est["analyzed_resources_count"],
            "findings_count": len(findings),
        },
        "cost_overview": {
            "estimated_monthly_cost": monthly_cost,
            "estimated_annual_cost": annual_cost,
            "period_estimated_cost": period_cost,
            "optimized_monthly_cost": optimized_monthly,
            "potential_monthly_savings": potential_monthly,
            "potential_annual_savings": potential_annual,
            "percentage_reduction": pct_reduction,
            "realized_monthly_savings": realized_monthly,
            "analyzed_resources": est["analyzed_resources_count"],
            "optimization_findings": len(findings),
        },
        "service_wise_cost_analysis": svc_breakdown,
        "resource_level_analysis": est["resources"],
        "cost_optimization_findings": findings,
        "optimization_recommendations": recommendations,
        "before_after_cost_comparison": comp,
        "cost_comparison": comp,
        "remediation_summary": rem,
        "final_assessment": {
            "summary": (
                f"Infrastructure baseline is {est['currency']} {monthly_cost:.2f}/month across "
                f"{est['analyzed_resources_count']} analyzed resource(s). "
                f"Applying verified recommendations can lower monthly spend to {est['currency']} {optimized_monthly:.2f}/month "
                f"(-{pct_reduction:.1f}%)."
            ),
            "unresolved_risks": unresolved_risks,
            "next_steps": next_steps,
        },
        "methodology_and_limitations": {
            "pricing_assumptions": (
                f"Rates loaded from {pricing_meta['pricing_source']} "
                f"(version {pricing_meta['dataset_version']}, effective {pricing_meta['effective_date']})."
            ),
            "usage_assumptions": (
                f"Running EC2 instances are estimated at {est['operating_hours_per_month']:g} operating hours/month; "
                "stopped instances incur $0.00 compute. EBS is priced by provisioned GB-month. "
                "S3 is priced strictly from observed ListObjectsV2 byte totals."
            ),
            "data_availability": inv["service_availability"],
            "missing_resource_fields": missing_fields_notes,
            "simulator_limitations": [
                "Local Moto simulator models AWS control-plane configuration state, not actual AWS metering or billing invoices.",
                "Missing CloudTrail events do not prove a resource is idle.",
                "Historical utilization time-series (CloudWatch) are unavailable in Moto.",
            ],
            "billing_disclaimer": (
                "All monetary figures are configuration- and assumption-based estimates using a configurable local pricing dataset, "
                "not actual AWS Cost and Usage Report (CUR) billing charges."
            ),
        },
        "dataset_snapshot": {
            "pricing_metadata": pricing_meta,
            "cloudtrail_summary": inv["cloudtrail_summary"],
            "regions_scanned": inv["regions_scanned"],
        },
    }

    report["narrative_text"] = _build_narrative_text(report)

    if persist and state_store is not None and hasattr(state_store, "save_cost_report"):
        state_store.save_cost_report(report)
        if hasattr(state_store, "append_audit_entry"):
            state_store.append_audit_entry(
                f"COST REPORT GENERATED [{report_id}] period={period_key} "
                f"monthly={est['currency']} {monthly_cost:.2f} savings={est['currency']} {potential_monthly:.2f}"
            )

    return report
