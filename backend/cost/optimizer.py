"""Cost Optimization Findings & Recommendations Engine for ThreatGuard.

Identifies optimization opportunities strictly backed by simulator resource
evidence and pricing catalog rates. Clearly separates confirmed resource
configurations from inferred opportunities and never assigns arbitrary savings.
"""
from typing import Any, Dict, List, Optional

from backend.cost.pricing import PricingCatalog, load_pricing_catalog

BYTES_PER_GB = 1024 ** 3
OWNERSHIP_TAG_KEYS = {"Owner", "CostCenter", "Environment", "Project"}


def _has_ownership_tag(tags: Dict[str, str]) -> bool:
    if not tags:
        return False
    lower_keys = {k.lower() for k in tags.keys()}
    return any(req.lower() in lower_keys for req in OWNERSHIP_TAG_KEYS)


def analyze_cost_optimizations(
    inventory: Dict[str, Any],
    estimation: Dict[str, Any],
    catalog: Optional[PricingCatalog] = None,
    all_estimated_resources: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Generate evidence-based cost optimization findings and savings summary."""
    cat = catalog or load_pricing_catalog()
    resources: List[Dict[str, Any]] = estimation.get("resources") or []
    lookup_pool = all_estimated_resources if all_estimated_resources is not None else resources
    hours = float(estimation.get("operating_hours_per_month") or 730.0)

    # Index EBS resources from full pool for cross-resource evidence (EC2 <-> EBS)
    ebs_by_id: Dict[str, Dict[str, Any]] = {
        r["resource_id"]: r for r in lookup_pool if r.get("service") == "ebs"
    }

    findings: List[Dict[str, Any]] = []

    for res in resources:
        svc = res.get("service")
        rid = str(res.get("resource_id") or "")
        region = res.get("region") or "us-east-1"
        state = str(res.get("state") or "").lower()
        rtype = str(res.get("resource_type") or "")
        meta = res.get("metadata") or {}
        tags = res.get("tags") or {}
        monthly_cost = res.get("estimated_monthly_cost")

        # 1. Unattached EBS volumes (Confirmed configuration)
        if svc == "ebs":
            attachments = meta.get("attachments") or []
            if state == "available" and len(attachments) == 0:
                size_gb = meta.get("size_gb")
                if monthly_cost is not None:
                    savings = float(monthly_cost)
                    savings_status = "Calculated"
                    savings_basis = (
                        f"100% of volume monthly EBS charge ({size_gb} GB {rtype} in {region})."
                    )
                else:
                    savings = 0.0
                    savings_status = "Pricing unavailable" if size_gb is not None else "Resource unavailable"
                    savings_basis = "Volume size or regional pricing unavailable; savings not calculated."
                findings.append({
                    "id": f"FIN-EBS-UNATTACHED-{rid}",
                    "title": "Unattached EBS Volume Incurring Storage Charges",
                    "severity": "High" if savings >= 5.0 else "Medium",
                    "priority": "P1" if savings >= 5.0 else "P2",
                    "classification": "confirmed",
                    "service": "ebs",
                    "region": region,
                    "affected_resource": rid,
                    "supporting_evidence": {
                        "volume_id": rid,
                        "state": state,
                        "attachments_count": 0,
                        "size_gb": size_gb,
                        "volume_type": rtype,
                        "availability_zone": res.get("availability_zone"),
                    },
                    "why_it_matters": (
                        "Unattached EBS volumes remain billed at full provisioned GB-month rates "
                        "even though no EC2 compute instance is using them."
                    ),
                    "recommended_action": (
                        f"Verify no active data retention is needed, create a snapshot if required, "
                        f"and delete unattached EBS volume '{rid}'."
                    ),
                    "remediation_action_type": "delete_unattached_ebs_volume",
                    "proposed_change": {
                        "domain": "cost_optimization",
                        "action_type": "delete_unattached_ebs_volume",
                        "resource_id": rid,
                        "service": "ebs",
                        "region": region,
                    },
                    "estimated_monthly_savings": round(savings, 4),
                    "savings_status": savings_status,
                    "savings_basis": savings_basis,
                    "risk_of_implementation": (
                        "Medium: Deleting a volume permanently removes stored blocks unless snapshotted first."
                    ),
                    "risk_level": "Medium",
                })

        # 2. Stopped EC2 instances with continuing EBS storage costs
        if svc == "ec2" and state == "stopped":
            attached_ids = meta.get("attached_volume_ids") or []
            attached_ebs_cost = 0.0
            attached_ebs_gb = 0
            known_vols = []
            missing_vol_pricing = False
            for vid in attached_ids:
                vol = ebs_by_id.get(vid)
                if vol:
                    known_vols.append(vid)
                    v_cost = vol.get("estimated_monthly_cost")
                    if v_cost is not None:
                        attached_ebs_cost += float(v_cost)
                    else:
                        missing_vol_pricing = True
                    v_sz = (vol.get("metadata") or {}).get("size_gb")
                    if v_sz is not None:
                        attached_ebs_gb += int(v_sz)

            if attached_ids:
                if attached_ebs_cost > 0:
                    s_status = "Calculated"
                    s_basis = (
                        f"Sum of monthly storage cost for attached EBS volumes ({', '.join(known_vols)})."
                    )
                elif missing_vol_pricing:
                    s_status = "Pricing unavailable"
                    s_basis = "Attached volume pricing or size unavailable; savings not calculated."
                else:
                    s_status = "Zero eligible spend"
                    s_basis = "No attached EBS storage cost observed."

                findings.append({
                    "id": f"FIN-EC2-STOPPED-EBS-{rid}",
                    "title": "Stopped EC2 Instance with Continuing Attached EBS Storage Costs",
                    "severity": "Medium",
                    "priority": "P2",
                    "classification": "inferred",
                    "service": "ec2",
                    "region": region,
                    "affected_resource": rid,
                    "supporting_evidence": {
                        "instance_id": rid,
                        "instance_state": "stopped",
                        "instance_type": rtype,
                        "attached_volume_ids": attached_ids,
                        "observed_attached_gb": attached_ebs_gb,
                        "attached_ebs_monthly_cost": round(attached_ebs_cost, 4),
                    },
                    "why_it_matters": (
                        "While stopped EC2 instances stop accruing hourly compute charges, "
                        "attached EBS root and data volumes continue accruing full monthly storage fees."
                    ),
                    "recommended_action": (
                        f"Confirm with workload owner whether stopped instance '{rid}' is still needed; "
                        "archive via AMI/snapshot and decommission if obsolete, or tag as intentional standby."
                    ),
                    "remediation_action_type": "apply_ownership_tags",
                    "proposed_change": {
                        "domain": "cost_optimization",
                        "action_type": "apply_ownership_tags",
                        "resource_id": rid,
                        "service": "ec2",
                        "region": region,
                        "tags": {"FinOpsReview": "StoppedInstanceEBSReviewed"},
                    },
                    "estimated_monthly_savings": round(attached_ebs_cost, 4),
                    "savings_status": s_status,
                    "savings_basis": s_basis,
                    "risk_of_implementation": (
                        "Low for review tagging; High if instance/volumes are terminated without owner sign-off."
                    ),
                    "risk_level": "Low",
                })

        # 3. Potentially oversized running EC2 instances (Inferred - utilization unavailable)
        if svc == "ec2" and state == "running":
            cur_entry = cat.lookup("ec2", rtype, region)
            if cur_entry and cur_entry.downsize_target:
                tgt_type = cur_entry.downsize_target
                tgt_entry = cat.lookup("ec2", tgt_type, region)
                if tgt_entry and tgt_entry.unit_price < cur_entry.unit_price:
                    savings = round((cur_entry.unit_price - tgt_entry.unit_price) * hours, 4)
                    findings.append({
                        "id": f"FIN-EC2-OVERSIZED-{rid}",
                        "title": f"Potentially Oversized EC2 Instance ({rtype} -> {tgt_type})",
                        "severity": "Medium",
                        "priority": "P2",
                        "classification": "inferred",
                        "service": "ec2",
                        "region": region,
                        "affected_resource": rid,
                        "supporting_evidence": {
                            "instance_id": rid,
                            "current_instance_type": rtype,
                            "candidate_instance_type": tgt_type,
                            "current_hourly_rate": cur_entry.unit_price,
                            "candidate_hourly_rate": tgt_entry.unit_price,
                            "assumed_monthly_hours": hours,
                            "utilization_metrics": "unavailable in Moto simulator",
                        },
                        "why_it_matters": (
                            "Larger instance families cost double per tier. Downsizing one size tier "
                            "when workload headroom permits reduces recurring monthly compute spend by ~50%."
                        ),
                        "recommended_action": (
                            f"Verify CPU and memory utilization outside Moto; if average load allows, "
                            f"right-size '{rid}' from '{rtype}' to '{tgt_type}'."
                        ),
                        "remediation_action_type": "rightsize_ec2_instance",
                        "proposed_change": {
                            "domain": "cost_optimization",
                            "action_type": "rightsize_ec2_instance",
                            "resource_id": rid,
                            "service": "ec2",
                            "region": region,
                            "target_instance_type": tgt_type,
                        },
                        "estimated_monthly_savings": savings,
                        "savings_status": "Estimate based on assumptions",
                        "savings_basis": (
                            f"Inferred tier reduction: (${cur_entry.unit_price:.4f} - ${tgt_entry.unit_price:.4f})/hr "
                            f"x {hours:g} hrs/month (pending real CPU/memory validation)."
                        ),
                        "risk_of_implementation": (
                            "Medium: Resizing requires instance stop/start downtime and may degrade performance if CPU/RAM bound."
                        ),
                        "risk_level": "Medium",
                    })

        # 4. S3 lifecycle policy opportunities & versioning retention
        if svc == "s3":
            has_lc = meta.get("has_lifecycle")
            lc_status = meta.get("lifecycle_status")
            total_bytes = meta.get("total_bytes")
            storage_unknown = bool(meta.get("storage_unknown")) or total_bytes is None
            sc_bytes = meta.get("storage_classes_bytes") or {}
            versioning = meta.get("versioning")

            if has_lc is False and lc_status != "Unavailable":
                std_bytes = int(sc_bytes.get("STANDARD", 0))
                std_entry = cat.lookup("s3", "STANDARD", region)
                ia_entry = cat.lookup("s3", "STANDARD_IA", region)
                lc_savings = 0.0
                if storage_unknown:
                    lc_status_label = "Resource unavailable"
                    lc_basis = (
                        "Confirmed missing lifecycle rule, but object storage consumption is unavailable; "
                        "savings cannot be calculated."
                    )
                elif std_bytes > 0 and (std_entry is None or ia_entry is None):
                    lc_status_label = "Pricing unavailable"
                    lc_basis = (
                        f"Confirmed missing lifecycle rule on {std_bytes} bytes, but regional STANDARD/STANDARD_IA "
                        f"pricing is unavailable for '{region}'."
                    )
                elif std_bytes > 0 and std_entry is not None and ia_entry is not None and ia_entry.unit_price < std_entry.unit_price:
                    lc_savings = round(
                        (float(std_bytes) / BYTES_PER_GB) * (std_entry.unit_price - ia_entry.unit_price),
                        4,
                    )
                    if lc_savings > 0:
                        lc_status_label = "Estimate based on assumptions"
                        lc_basis = (
                            f"Confirmed missing lifecycle rule; projected STANDARD -> STANDARD_IA tiering delta "
                            f"on {std_bytes} observed bytes in '{region}'."
                        )
                    else:
                        lc_status_label = "Zero eligible spend"
                        lc_basis = (
                            f"Confirmed missing lifecycle rule; observed {std_bytes} bytes is below $0.0001/mo threshold."
                        )
                else:
                    lc_status_label = "Zero eligible spend"
                    lc_basis = (
                        "Confirmed missing lifecycle configuration; $0.00 current savings because 0 objects / 0 bytes "
                        "are stored in STANDARD tier."
                    )

                findings.append({
                    "id": f"FIN-S3-LIFECYCLE-{rid}",
                    "title": "S3 Bucket Missing Lifecycle Transition / Expiration Policy",
                    "severity": "Medium" if lc_savings > 0 else "Low",
                    "priority": "P2" if lc_savings > 0 else "P3",
                    "classification": "confirmed" if lc_savings == 0 else "inferred",
                    "service": "s3",
                    "region": region,
                    "affected_resource": rid,
                    "supporting_evidence": {
                        "bucket_name": rid,
                        "lifecycle_status": lc_status,
                        "object_count": meta.get("object_count"),
                        "total_bytes": total_bytes,
                        "standard_class_bytes": std_bytes,
                    },
                    "why_it_matters": (
                        "Without an S3 lifecycle policy, objects remain indefinitely in S3 Standard "
                        "rather than transitioning to lower-cost tiers (Standard-IA / Glacier) or expiring."
                    ),
                    "recommended_action": (
                        f"Apply an S3 lifecycle policy on bucket '{rid}' to transition objects to "
                        "STANDARD_IA after 30 days and expire obsolete noncurrent versions."
                    ),
                    "remediation_action_type": "apply_s3_lifecycle_policy",
                    "proposed_change": {
                        "domain": "cost_optimization",
                        "action_type": "apply_s3_lifecycle_policy",
                        "resource_id": rid,
                        "service": "s3",
                        "region": region,
                        "transition_days": 30,
                        "storage_class": "STANDARD_IA",
                    },
                    "estimated_monthly_savings": lc_savings,
                    "savings_status": lc_status_label,
                    "savings_basis": lc_basis,
                    "risk_of_implementation": (
                        "Low: Transitioning to Standard-IA incurs minimum 30-day storage duration and retrieval fees for frequent reads."
                    ),
                    "risk_level": "Low",
                })

            if versioning == "Enabled" and has_lc is False:
                findings.append({
                    "id": f"FIN-S3-VERSION-RETENTION-{rid}",
                    "title": "Versioned S3 Bucket Lacks Noncurrent Version Expiration",
                    "severity": "Low",
                    "priority": "P3",
                    "classification": "confirmed",
                    "service": "s3",
                    "region": region,
                    "affected_resource": rid,
                    "supporting_evidence": {
                        "bucket_name": rid,
                        "versioning_status": versioning,
                        "lifecycle_status": lc_status,
                    },
                    "why_it_matters": (
                        "With versioning enabled and no lifecycle expiration rule, overwritten or deleted "
                        "objects accumulate hidden noncurrent versions that increase S3 storage spend."
                    ),
                    "recommended_action": (
                        f"Configure NoncurrentVersionExpiration (e.g., 90 days) in lifecycle rules for '{rid}'."
                    ),
                    "remediation_action_type": "apply_s3_lifecycle_policy",
                    "proposed_change": {
                        "domain": "cost_optimization",
                        "action_type": "apply_s3_lifecycle_policy",
                        "resource_id": rid,
                        "service": "s3",
                        "region": region,
                        "transition_days": 30,
                        "noncurrent_expiration_days": 90,
                    },
                    "estimated_monthly_savings": 0.0,
                    "savings_status": "Governance only",
                    "savings_basis": (
                        "Confirmed retention governance gap; noncurrent version byte counts are not separately "
                        "reported by ListObjectsV2, so direct dollar savings are not fabricated."
                    ),
                    "risk_of_implementation": (
                        "Low: Ensure recovery point objective (RPO) permits expiring noncurrent versions after 90 days."
                    ),
                    "risk_level": "Low",
                })

        # 5. Missing ownership tags (Confirmed governance metadata gap)
        if svc in ("ec2", "ebs", "s3") and not _has_ownership_tag(tags):
            findings.append({
                "id": f"FIN-TAG-MISSING-{svc.upper()}-{rid}",
                "title": f"Missing FinOps Ownership Tags on {svc.upper()} Resource",
                "severity": "Low",
                "priority": "P4",
                "classification": "confirmed",
                "service": svc,
                "region": region,
                "affected_resource": rid,
                "supporting_evidence": {
                    "resource_id": rid,
                    "service": svc,
                    "observed_tags": tags,
                    "expected_any_of": sorted(OWNERSHIP_TAG_KEYS),
                },
                "why_it_matters": (
                    "Resources without Owner, CostCenter, Environment, or Project tags cannot be "
                    "attributed to responsible engineering teams for FinOps chargeback or cleanup approval."
                ),
                "recommended_action": (
                    f"Apply standardized ownership tags (Owner, CostCenter, Environment) to '{rid}'."
                ),
                "remediation_action_type": "apply_ownership_tags",
                "proposed_change": {
                    "domain": "cost_optimization",
                    "action_type": "apply_ownership_tags",
                    "resource_id": rid,
                    "service": svc,
                    "region": region,
                    "tags": {
                        "Owner": "cloud-platform-team",
                        "Environment": "simulator",
                        "CostCenter": "finops-governance",
                    },
                },
                "estimated_monthly_savings": 0.0,
                "savings_status": "Governance only",
                "savings_basis": "Governance and cost-allocation improvement; tagging does not directly reduce AWS billing rates.",
                "risk_of_implementation": "Low: Metadata tag addition is non-disruptive to running workloads.",
                "risk_level": "Low",
            })

    # Attach findings and potential savings back onto resource rows and service breakdown
    savings_by_resource: Dict[str, float] = {}
    findings_by_resource: Dict[str, List[Dict[str, Any]]] = {}
    opps_by_service: Dict[str, int] = {}

    for f in findings:
        res_key = f"{f['service']}:{f['affected_resource']}"
        findings_by_resource.setdefault(res_key, []).append(f)
        opps_by_service[f["service"]] = opps_by_service.get(f["service"], 0) + 1
        cur_max = savings_by_resource.get(res_key, 0.0)
        if f["estimated_monthly_savings"] > cur_max:
            savings_by_resource[res_key] = float(f["estimated_monthly_savings"])

    for r in resources:
        res_key = f"{r['service']}:{r['resource_id']}"
        r_findings = findings_by_resource.get(res_key, [])
        r_savings = round(savings_by_resource.get(res_key, 0.0), 4)
        r_cost = r.get("estimated_monthly_cost")
        if r_cost is not None and r_savings > float(r_cost) and r.get("service") != "ec2":
            r_savings = float(r_cost)
        r["potential_monthly_savings"] = r_savings
        r["findings_count"] = len(r_findings)
        r["recommendation_summary"] = (
            r_findings[0]["recommended_action"] if r_findings else "No optimization action required."
        )

    for svc_row in estimation.get("service_breakdown") or []:
        svc_row["optimization_opportunities"] = opps_by_service.get(svc_row["service"], 0)

    current_monthly = float(estimation.get("total_monthly_cost") or 0.0)
    raw_potential_savings = sum(savings_by_resource.values())
    potential_monthly_savings = round(min(current_monthly, raw_potential_savings), 4)
    potential_annual_savings = round(potential_monthly_savings * 12.0, 4)
    optimized_monthly_cost = round(max(0.0, current_monthly - potential_monthly_savings), 4)
    percentage_reduction = (
        round((potential_monthly_savings / current_monthly) * 100.0, 2)
        if current_monthly > 0
        else 0.0
    )

    confirmed_count = sum(1 for f in findings if f["classification"] == "confirmed")
    inferred_count = sum(1 for f in findings if f["classification"] == "inferred")

    return {
        "findings": findings,
        "findings_count": len(findings),
        "confirmed_findings_count": confirmed_count,
        "inferred_findings_count": inferred_count,
        "cost_comparison": {
            "currency": estimation.get("currency", "USD"),
            "current_estimated_monthly_cost": current_monthly,
            "potential_monthly_savings": potential_monthly_savings,
            "potential_annual_savings": potential_annual_savings,
            "optimized_estimated_monthly_cost": optimized_monthly_cost,
            "percentage_reduction": percentage_reduction,
        },
        "cloudtrail_note": (
            (inventory.get("cloudtrail_summary") or {}).get("note")
            or "Missing CloudTrail events do not prove a resource is idle."
        ),
    }
