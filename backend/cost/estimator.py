"""AWS Cost Estimation Engine for ThreatGuard.

Calculates assumption-transparent monthly and annual AWS cost estimates from
collected Moto/AWS resource inventory and a decoupled PricingCatalog.

Separates observed resource properties from estimated usage and enforces explicit
status labeling without silently converting missing pricing into zero-cost figures.
"""
from typing import Any, Dict, List, Optional

from backend.cost.pricing import PricingCatalog, load_pricing_catalog

BYTES_PER_GB = 1024 ** 3
SUPPORTED_SERVICES = ("ec2", "ebs", "s3", "iam", "cloudtrail")

STATUS_CALCULATED = "Calculated"
STATUS_ZERO_USAGE = "Zero usage observed"
STATUS_PRICING_UNAVAILABLE = "Pricing unavailable"
STATUS_RESOURCE_UNAVAILABLE = "Resource unavailable"
STATUS_ASSUMPTION_ESTIMATE = "Estimate based on assumptions"


def estimate_resource_cost(
    resource: Dict[str, Any],
    catalog: PricingCatalog,
    operating_hours_per_month: float = 730.0,
) -> Dict[str, Any]:
    """Estimate monthly and annual cost for a single normalized AWS resource."""
    service = str(resource.get("service", "")).lower()
    rtype = resource.get("resource_type")
    region = resource.get("region") or "us-east-1"
    state = str(resource.get("state") or "unknown").lower()
    meta = resource.get("metadata") or {}

    base: Dict[str, Any] = {
        "resource_id": resource.get("resource_id"),
        "name": resource.get("name") or resource.get("resource_id"),
        "service": service,
        "resource_type": rtype or "unavailable",
        "region": region,
        "availability_zone": resource.get("availability_zone") or "unavailable",
        "state": state,
        "tags": dict(resource.get("tags") or {}),
        "metadata": dict(meta),
        "observed_properties": {
            "resource_type": rtype or "unavailable",
            "state": state,
            "region": region,
            "availability_zone": resource.get("availability_zone") or "unavailable",
        },
        "estimated_usage": {
            "utilization_telemetry_available": False,
        },
        "currency": catalog.currency,
        "pricing_available": False,
        "unit_price": None,
        "pricing_unit": None,
        "pricing_source": None,
        "effective_date": None,
        "estimated_monthly_cost": None,
        "estimated_annual_cost": None,
        "cost_status": STATUS_RESOURCE_UNAVAILABLE,
        "estimation_basis": "unavailable",
        "assumption_note": "",
        "is_assumption_based": True,
    }

    if service == "ec2":
        base["observed_properties"].update({
            "attached_volumes_count": len(meta.get("attached_volume_ids") or []),
            "utilization_metrics": "unavailable",
        })
        entry = catalog.lookup("ec2", rtype, region)
        if entry is None:
            base["cost_status"] = STATUS_PRICING_UNAVAILABLE
            base["estimation_basis"] = "missing_pricing"
            base["assumption_note"] = (
                f"No regional pricing entry found for EC2 '{rtype}' in '{region}'. Cost not estimated."
            )
            return base

        base["pricing_available"] = True
        base["unit_price"] = entry.unit_price
        base["pricing_unit"] = entry.pricing_unit
        base["pricing_source"] = entry.pricing_source
        base["effective_date"] = entry.effective_date

        if state == "running":
            hrs = max(0.0, float(operating_hours_per_month))
            monthly = round(entry.unit_price * hrs, 4)
            base["estimated_monthly_cost"] = monthly
            base["estimated_annual_cost"] = round(monthly * 12.0, 4)
            base["cost_status"] = STATUS_ASSUMPTION_ESTIMATE
            base["estimation_basis"] = "assumption_based_estimate"
            base["estimated_usage"] = {
                "assumed_operating_hours_per_month": hrs,
                "unit_price": entry.unit_price,
                "pricing_unit": entry.pricing_unit,
                "formula": f"{entry.unit_price:.4f} * {hrs:g} hrs",
                "utilization_telemetry_available": False,
            }
            base["assumption_note"] = (
                f"Estimated using {hrs:g} operating hrs/month x ${entry.unit_price:.4f}/hr "
                f"({entry.effective_date}); actual CPU/runtime uptime unavailable in simulator."
            )
        elif state in ("stopped", "terminated"):
            base["estimated_monthly_cost"] = 0.0
            base["estimated_annual_cost"] = 0.0
            base["cost_status"] = STATUS_ZERO_USAGE
            base["estimation_basis"] = "stopped_no_compute" if state == "stopped" else "terminated"
            base["is_assumption_based"] = False
            base["estimated_usage"] = {
                "assumed_operating_hours_per_month": 0.0,
                "unit_price": entry.unit_price,
                "pricing_unit": entry.pricing_unit,
                "formula": "0 hrs compute while " + state,
                "utilization_telemetry_available": False,
            }
            base["assumption_note"] = (
                "Stopped EC2 instance incurs $0.00 compute cost; attached EBS volumes are estimated separately."
                if state == "stopped"
                else "Terminated instance incurs $0.00 compute cost."
            )
        else:
            base["cost_status"] = STATUS_RESOURCE_UNAVAILABLE
            base["estimation_basis"] = "unknown_or_transient_state"
            base["assumption_note"] = (
                f"Instance state '{state}' is transient or unknown; compute cost not estimated."
            )
        return base

    if service == "ebs":
        size_gb = meta.get("size_gb")
        attachments = meta.get("attachments") or []
        base["observed_properties"].update({
            "size_gb": size_gb,
            "volume_type": rtype,
            "attachments_count": len(attachments),
            "encrypted": meta.get("encrypted"),
        })
        if size_gb is None:
            base["cost_status"] = STATUS_RESOURCE_UNAVAILABLE
            base["estimation_basis"] = "missing_metadata"
            base["assumption_note"] = "EBS volume size_gb unavailable; cannot calculate storage cost."
            return base

        entry = catalog.lookup("ebs", rtype, region)
        if entry is None:
            base["cost_status"] = STATUS_PRICING_UNAVAILABLE
            base["estimation_basis"] = "missing_pricing"
            base["assumption_note"] = (
                f"No regional pricing entry found for EBS volume type '{rtype}' in '{region}'."
            )
            return base

        size_val = float(size_gb)
        monthly = round(size_val * entry.unit_price, 4)
        base["pricing_available"] = True
        base["unit_price"] = entry.unit_price
        base["pricing_unit"] = entry.pricing_unit
        base["pricing_source"] = entry.pricing_source
        base["effective_date"] = entry.effective_date
        base["estimated_monthly_cost"] = monthly
        base["estimated_annual_cost"] = round(monthly * 12.0, 4)
        base["cost_status"] = STATUS_ZERO_USAGE if size_val <= 0 else STATUS_CALCULATED
        base["estimation_basis"] = "configuration_based_estimate"
        base["is_assumption_based"] = False
        base["estimated_usage"] = {
            "provisioned_gb": size_val,
            "unit_price": entry.unit_price,
            "pricing_unit": entry.pricing_unit,
            "formula": f"{size_val:g} GB * ${entry.unit_price:.4f}/GB-mo",
            "utilization_telemetry_available": False,
        }
        base["assumption_note"] = (
            f"Provisioned {size_val:g} GB ({rtype}) x ${entry.unit_price:.4f}/GB-month "
            "(excludes extra provisioned IOPS and snapshots)."
        )
        return base

    if service == "s3":
        base["observed_properties"].update({
            "object_count": meta.get("object_count"),
            "total_bytes": meta.get("total_bytes"),
            "storage_gb": meta.get("storage_gb"),
            "versioning": meta.get("versioning"),
            "has_lifecycle": meta.get("has_lifecycle"),
        })
        if meta.get("storage_unknown") or meta.get("total_bytes") is None:
            base["cost_status"] = STATUS_RESOURCE_UNAVAILABLE
            base["estimation_basis"] = "storage_unknown"
            base["assumption_note"] = (
                "S3 object size metadata is unavailable; storage cost not calculated."
            )
            return base

        total_bytes = int(meta.get("total_bytes") or 0)
        sc_bytes: Dict[str, int] = dict(meta.get("storage_classes_bytes") or {})

        if total_bytes == 0:
            entry = catalog.lookup("s3", "STANDARD", region)
            if entry is None:
                base["cost_status"] = STATUS_PRICING_UNAVAILABLE
                base["estimation_basis"] = "missing_pricing"
                base["assumption_note"] = f"No S3 pricing entry for region '{region}'."
                return base
            base["pricing_available"] = True
            base["unit_price"] = entry.unit_price
            base["pricing_unit"] = entry.pricing_unit
            base["pricing_source"] = entry.pricing_source
            base["effective_date"] = entry.effective_date
            base["estimated_monthly_cost"] = 0.0
            base["estimated_annual_cost"] = 0.0
            base["cost_status"] = STATUS_ZERO_USAGE
            base["estimation_basis"] = "zero_observed_storage"
            base["is_assumption_based"] = False
            base["estimated_usage"] = {
                "observed_gb": 0.0,
                "unit_price": entry.unit_price,
                "pricing_unit": entry.pricing_unit,
                "formula": "0 objects (0 B) observed",
                "utilization_telemetry_available": True,
            }
            base["assumption_note"] = (
                "0 objects / 0 bytes observed via s3:ListObjectsV2; storage estimate is $0.00 "
                "(no request or data-transfer charges fabricated)."
            )
            return base

        total_cost = 0.0
        used_entry = None
        for sc_name, b_count in sc_bytes.items():
            entry = catalog.lookup("s3", sc_name, region)
            if entry is None:
                base["cost_status"] = STATUS_PRICING_UNAVAILABLE
                base["estimation_basis"] = "missing_pricing"
                base["assumption_note"] = (
                    f"No S3 pricing entry for storage class '{sc_name}' in '{region}'."
                )
                return base
            used_entry = entry
            total_cost += (float(b_count) / BYTES_PER_GB) * entry.unit_price

        monthly = round(total_cost, 6)
        observed_gb = total_bytes / BYTES_PER_GB
        base["pricing_available"] = True
        if used_entry:
            base["unit_price"] = used_entry.unit_price
            base["pricing_unit"] = used_entry.pricing_unit
            base["pricing_source"] = used_entry.pricing_source
            base["effective_date"] = used_entry.effective_date
        base["estimated_monthly_cost"] = round(monthly, 4)
        base["estimated_annual_cost"] = round(monthly * 12.0, 4)
        base["cost_status"] = STATUS_CALCULATED
        base["estimation_basis"] = "observed_object_storage"
        base["is_assumption_based"] = False
        base["estimated_usage"] = {
            "observed_gb": round(observed_gb, 6),
            "storage_classes_bytes": sc_bytes,
            "unit_price": used_entry.unit_price if used_entry else None,
            "pricing_unit": used_entry.pricing_unit if used_entry else "GB-month",
            "formula": f"{observed_gb:.6f} GB observed",
            "utilization_telemetry_available": True,
        }
        base["assumption_note"] = (
            f"Calculated from {total_bytes} observed bytes ({observed_gb:.6f} GB); "
            "excludes unsimulated API request fees and data transfer."
        )
        return base

    if service == "iam":
        base["observed_properties"].update({
            "iam_kind": meta.get("iam_kind"),
            "attached_policies_count": len(meta.get("attached_policies") or []),
        })
        entry = catalog.lookup("iam", "identity", "global")
        if entry is None:
            base["cost_status"] = STATUS_PRICING_UNAVAILABLE
            base["estimation_basis"] = "missing_pricing"
            base["assumption_note"] = "No IAM pricing rule configured in dataset."
            return base
        base["pricing_available"] = True
        base["unit_price"] = entry.unit_price
        base["pricing_unit"] = entry.pricing_unit
        base["pricing_source"] = entry.pricing_source
        base["effective_date"] = entry.effective_date
        base["estimated_monthly_cost"] = 0.0
        base["estimated_annual_cost"] = 0.0
        base["cost_status"] = STATUS_CALCULATED
        base["estimation_basis"] = "no_direct_service_charge"
        base["is_assumption_based"] = False
        base["estimated_usage"] = {
            "billed_units": 0,
            "unit_price": entry.unit_price,
            "pricing_unit": entry.pricing_unit,
            "formula": "AWS IAM carries $0.00 direct charge",
            "utilization_telemetry_available": True,
        }
        base["assumption_note"] = "IAM identities and policies carry no direct AWS monthly infrastructure charge."
        return base

    if service == "cloudtrail":
        base["observed_properties"].update({
            "is_logging": meta.get("is_logging"),
            "is_multi_region": meta.get("is_multi_region"),
            "s3_bucket_name": meta.get("s3_bucket_name"),
        })
        entry = catalog.lookup("cloudtrail", "management-trail", region)
        if entry is None:
            base["cost_status"] = STATUS_PRICING_UNAVAILABLE
            base["estimation_basis"] = "missing_pricing"
            base["assumption_note"] = f"No CloudTrail pricing entry found for region '{region}'."
            return base
        base["pricing_available"] = True
        base["unit_price"] = entry.unit_price
        base["pricing_unit"] = entry.pricing_unit
        base["pricing_source"] = entry.pricing_source
        base["effective_date"] = entry.effective_date
        base["estimated_monthly_cost"] = 0.0
        base["estimated_annual_cost"] = 0.0
        base["cost_status"] = STATUS_CALCULATED if meta.get("is_logging") else STATUS_ZERO_USAGE
        base["estimation_basis"] = "no_direct_service_charge"
        base["is_assumption_based"] = False
        base["estimated_usage"] = {
            "trail_active": bool(meta.get("is_logging")),
            "unit_price": entry.unit_price,
            "pricing_unit": entry.pricing_unit,
            "formula": "First management-event trail copy is $0.00",
            "utilization_telemetry_available": True,
        }
        base["assumption_note"] = (
            "First management-event trail copy incurs $0.00 trail fee; log delivery storage is billed separately under S3."
        )
        return base

    base["cost_status"] = STATUS_RESOURCE_UNAVAILABLE
    base["estimation_basis"] = "unsupported_service"
    base["assumption_note"] = f"Service '{service}' is not supported by the cost estimator."
    return base


def estimate_infrastructure_costs(
    inventory: Dict[str, Any],
    catalog: Optional[PricingCatalog] = None,
    operating_hours_per_month: Optional[float] = None,
    service_filter: Optional[str] = None,
    region_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """Estimate costs across an entire inventory snapshot and aggregate by service."""
    cat = catalog or load_pricing_catalog()
    default_hours = float(cat.default_assumptions.get("monthly_hours_continuous", 730))
    hours = float(operating_hours_per_month) if operating_hours_per_month is not None else default_hours

    svc_flt = service_filter.strip().lower() if service_filter else None
    reg_flt = region_filter.strip().lower() if region_filter else None

    raw_resources = inventory.get("resources") or []
    filtered_resources = [
        r for r in raw_resources
        if (not svc_flt or str(r.get("service", "")).lower() == svc_flt)
        and (not reg_flt or str(r.get("region", "")).lower() == reg_flt)
    ]

    estimated_resources: List[Dict[str, Any]] = [
        estimate_resource_cost(res, cat, operating_hours_per_month=hours)
        for res in filtered_resources
    ]

    svc_availability = inventory.get("service_availability") or {}
    services_to_include = [svc_flt] if svc_flt else list(SUPPORTED_SERVICES)

    # Service-level aggregation across all supported services in scope
    svc_buckets: Dict[str, Dict[str, Any]] = {}
    for svc in services_to_include:
        av_status = (svc_availability.get(svc) or {}).get("status", "unavailable")
        svc_buckets[svc] = {
            "service": svc,
            "resource_count": 0,
            "priced_count": 0,
            "unpriced_count": 0,
            "estimated_monthly_cost": None if av_status == "unavailable" else 0.0,
            "percentage_of_total": 0.0,
            "optimization_opportunities": 0,
            "service_status": STATUS_RESOURCE_UNAVAILABLE if av_status == "unavailable" else STATUS_ZERO_USAGE,
            "statuses": [],
        }

    total_monthly = 0.0
    priced_count = 0
    unpriced_count = 0

    for item in estimated_resources:
        svc = item["service"]
        if svc not in svc_buckets:
            svc_buckets[svc] = {
                "service": svc,
                "resource_count": 0,
                "priced_count": 0,
                "unpriced_count": 0,
                "estimated_monthly_cost": 0.0,
                "percentage_of_total": 0.0,
                "optimization_opportunities": 0,
                "service_status": item["cost_status"],
                "statuses": [],
            }
        bucket = svc_buckets[svc]
        bucket["resource_count"] += 1
        bucket["statuses"].append(item["cost_status"])
        cost = item.get("estimated_monthly_cost")
        if cost is not None:
            bucket["priced_count"] += 1
            prev_cost = bucket["estimated_monthly_cost"] or 0.0
            bucket["estimated_monthly_cost"] = round(prev_cost + float(cost), 4)
            total_monthly += float(cost)
            priced_count += 1
        else:
            bucket["unpriced_count"] += 1
            unpriced_count += 1

    total_monthly = round(total_monthly, 4)
    total_annual = round(total_monthly * 12.0, 4)

    service_breakdown: List[Dict[str, Any]] = []
    for svc_key, b in svc_buckets.items():
        statuses = set(b.pop("statuses"))
        if b["resource_count"] == 0:
            av_status = (svc_availability.get(svc_key) or {}).get("status", "unavailable")
            if av_status == "unavailable":
                b["service_status"] = STATUS_RESOURCE_UNAVAILABLE
                b["estimated_monthly_cost"] = None
            else:
                b["service_status"] = STATUS_ZERO_USAGE
                b["estimated_monthly_cost"] = 0.0
        elif b["priced_count"] == 0 and b["unpriced_count"] > 0:
            b["estimated_monthly_cost"] = None
            b["service_status"] = (
                STATUS_PRICING_UNAVAILABLE
                if STATUS_PRICING_UNAVAILABLE in statuses
                else STATUS_RESOURCE_UNAVAILABLE
            )
        elif STATUS_ASSUMPTION_ESTIMATE in statuses:
            b["service_status"] = STATUS_ASSUMPTION_ESTIMATE
        elif STATUS_PRICING_UNAVAILABLE in statuses:
            b["service_status"] = STATUS_PRICING_UNAVAILABLE
        elif statuses == {STATUS_ZERO_USAGE}:
            b["service_status"] = STATUS_ZERO_USAGE
        else:
            b["service_status"] = STATUS_CALCULATED

        svc_cost = b["estimated_monthly_cost"]
        b["percentage_of_total"] = (
            round((svc_cost / total_monthly) * 100.0, 2)
            if total_monthly > 0 and svc_cost is not None
            else 0.0
        )
        service_breakdown.append(b)

    service_breakdown.sort(
        key=lambda x: (
            -(x["estimated_monthly_cost"] if x["estimated_monthly_cost"] is not None else -1.0),
            -x["resource_count"],
            x["service"],
        )
    )

    return {
        "currency": cat.currency,
        "pricing_version": cat.dataset_version,
        "pricing_effective_date": cat.effective_date,
        "pricing_source": cat.pricing_source,
        "operating_hours_per_month": hours,
        "total_monthly_cost": total_monthly,
        "total_annual_cost": total_annual,
        "analyzed_resources_count": len(estimated_resources),
        "priced_resources_count": priced_count,
        "unpriced_resources_count": unpriced_count,
        "service_breakdown": service_breakdown,
        "resources": estimated_resources,
    }
