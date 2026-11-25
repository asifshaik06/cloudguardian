"""Cost Optimization Remediation Integration with ThreatGuard HITL Workflow.

Connects Cost Intelligence findings to SOCStore remediation tasks, enforcing
human approval before execution in the local Moto simulator, independent
post-fix verification, and tamper-evident audit logging.
"""
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.aws_guard import get_aws_client, is_dry_run, is_live_aws, safe_execute_remediation
from backend.soc.models import RemediationStatus, RemediationTask, VerificationState

logger = logging.getLogger("threatguard.cost.remediation")


def create_cost_remediation_task(
    finding: Dict[str, Any],
    soc_store: Any,
    state_store: Optional[Any] = None,
) -> RemediationTask:
    """Create (or return existing active) SOCStore remediation task for a cost finding."""
    fid = str(finding["id"])
    svc = str(finding.get("service", "")).lower()
    rid = str(finding.get("affected_resource", ""))
    proposed = dict(finding.get("proposed_change") or {})
    proposed.setdefault("domain", "cost_optimization")
    proposed.setdefault("action_type", finding.get("remediation_action_type"))
    proposed.setdefault("resource_id", rid)
    proposed.setdefault("service", svc)
    proposed.setdefault("region", finding.get("region", "us-east-1"))
    proposed["estimated_monthly_savings"] = float(finding.get("estimated_monthly_savings") or 0.0)

    before_cfg = dict(finding.get("supporting_evidence") or {})
    after_cfg = {
        "recommended_action": finding.get("recommended_action"),
        "expected_monthly_savings": float(finding.get("estimated_monthly_savings") or 0.0),
        "target_change": proposed,
    }

    task = soc_store.create_remediation_task(
        title=f"FinOps Optimization: {finding.get('title', fid)}",
        affected_resource=f"{svc}/{rid}" if svc and not rid.startswith(f"{svc}/") else rid,
        recommended_action=str(finding.get("recommended_action") or ""),
        technical_explanation=str(finding.get("savings_basis") or ""),
        why_it_matters=str(finding.get("why_it_matters") or ""),
        proposed_change=proposed,
        severity=str(finding.get("severity") or "Medium"),
        related_finding_id=fid,
        before_config=before_cfg,
        after_config=after_cfg,
        rollback_plan=(
            f"Restore prior configuration on {rid} if operational validation fails "
            "(note: deleted volumes require snapshot restore)."
        ),
    )
    # Persist operational risk metadata cleanly on task
    task.operational_impact = str(
        finding.get("risk_of_implementation") or "Low operational impact in simulator."
    )
    if state_store and hasattr(state_store, "append_audit_entry"):
        try:
            state_store.append_audit_entry(
                f"COST REMEDIATION PROPOSED [{task.id}] for {fid} "
                f"(Est. Savings: ${float(finding.get('estimated_monthly_savings') or 0.0):.2f}/mo)"
            )
        except Exception:
            pass
    return task


def _resolve_client(service: str, region: str, clients: Optional[Dict[str, Any]] = None) -> Any:
    if clients:
        if (service, region) in clients:
            return clients[(service, region)]
        if service in clients:
            return clients[service]
    return get_aws_client(service, region_name=region)


def build_cost_executor_and_verifier(
    task: RemediationTask,
    clients: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Callable[[], Any]], Optional[Callable[[], Tuple[VerificationState, Dict[str, Any]]]]]:
    """Build concrete Moto/AWS executor and independent verifier for a cost task."""
    proposed = task.proposed_change or {}
    action_type = str(proposed.get("action_type") or "")
    resource_id = str(proposed.get("resource_id") or "")
    service = str(proposed.get("service") or "").lower()
    region = str(proposed.get("region") or "us-east-1")

    if not resource_id and "/" in task.affected_resource:
        resource_id = task.affected_resource.split("/", 1)[1]

    if action_type == "apply_s3_lifecycle_policy":
        transition_days = int(proposed.get("transition_days", 30))
        storage_class = str(proposed.get("storage_class", "STANDARD_IA"))
        noncurrent_days = proposed.get("noncurrent_expiration_days")

        def _exec_s3_lifecycle() -> None:
            if is_live_aws():
                raise RuntimeError("Cost remediation execution in Live AWS mode is blocked by safety guard.")
            s3 = _resolve_client("s3", region, clients)
            rule: Dict[str, Any] = {
                "ID": f"threatguard-finops-{resource_id[:24]}",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Transitions": [{"Days": transition_days, "StorageClass": storage_class}],
            }
            if noncurrent_days:
                rule["NoncurrentVersionExpiration"] = {"NoncurrentDays": int(noncurrent_days)}

            def _apply() -> None:
                s3.put_bucket_lifecycle_configuration(
                    Bucket=resource_id,
                    LifecycleConfiguration={"Rules": [rule]},
                )

            ok, msg = safe_execute_remediation(f"apply_s3_lifecycle_policy:{resource_id}", _apply)
            if not ok:
                raise RuntimeError(msg)

        def _verify_s3_lifecycle() -> Tuple[VerificationState, Dict[str, Any]]:
            if is_dry_run():
                return VerificationState.PARTIAL, {
                    "status": "PARTIAL",
                    "dry_run": True,
                    "evidence": "Dry-run mode enabled; lifecycle policy was not persisted in simulator.",
                }
            s3 = _resolve_client("s3", region, clients)
            resp = s3.get_bucket_lifecycle_configuration(Bucket=resource_id)
            rules = resp.get("Rules", [])
            active = [r for r in rules if r.get("Status") == "Enabled"]
            if active:
                return VerificationState.PASS, {
                    "status": "PASS",
                    "bucket": resource_id,
                    "active_rules_count": len(active),
                    "evidence": f"Independent check confirmed {len(active)} enabled lifecycle rule(s) on '{resource_id}'.",
                }
            return VerificationState.FAIL, {
                "status": "FAIL",
                "bucket": resource_id,
                "evidence": f"No enabled lifecycle rules found on '{resource_id}'.",
            }

        return _exec_s3_lifecycle, _verify_s3_lifecycle

    if action_type == "apply_ownership_tags":
        tags_map: Dict[str, str] = dict(proposed.get("tags") or {
            "Owner": "cloud-platform-team",
            "Environment": "simulator",
            "CostCenter": "finops-governance",
        })

        def _exec_tags() -> None:
            if is_live_aws():
                raise RuntimeError("Cost remediation execution in Live AWS mode is blocked by safety guard.")

            def _apply() -> None:
                if service == "s3":
                    s3 = _resolve_client("s3", region, clients)
                    existing = []
                    try:
                        existing = s3.get_bucket_tagging(Bucket=resource_id).get("TagSet", [])
                    except Exception:
                        existing = []
                    merged = {t["Key"]: t["Value"] for t in existing if "Key" in t}
                    merged.update(tags_map)
                    s3.put_bucket_tagging(
                        Bucket=resource_id,
                        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in merged.items()]},
                    )
                else:
                    ec2 = _resolve_client("ec2", region, clients)
                    ec2.create_tags(
                        Resources=[resource_id],
                        Tags=[{"Key": k, "Value": v} for k, v in tags_map.items()],
                    )

            ok, msg = safe_execute_remediation(f"apply_ownership_tags:{resource_id}", _apply)
            if not ok:
                raise RuntimeError(msg)

        def _verify_tags() -> Tuple[VerificationState, Dict[str, Any]]:
            if is_dry_run():
                return VerificationState.PARTIAL, {
                    "status": "PARTIAL",
                    "dry_run": True,
                    "evidence": "Dry-run mode enabled; ownership tags were not applied.",
                }
            if service == "s3":
                s3 = _resolve_client("s3", region, clients)
                tag_set = s3.get_bucket_tagging(Bucket=resource_id).get("TagSet", [])
                observed = {t["Key"]: t["Value"] for t in tag_set if "Key" in t}
            else:
                ec2 = _resolve_client("ec2", region, clients)
                resp = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [resource_id]}])
                observed = {t["Key"]: t["Value"] for t in resp.get("Tags", []) if "Key" in t}

            missing = [k for k in tags_map if k not in observed]
            if not missing:
                return VerificationState.PASS, {
                    "status": "PASS",
                    "resource_id": resource_id,
                    "observed_tags": observed,
                    "evidence": f"Independent check confirmed ownership tags on '{resource_id}'.",
                }
            return VerificationState.FAIL, {
                "status": "FAIL",
                "resource_id": resource_id,
                "missing_tags": missing,
                "evidence": f"Missing expected tags on '{resource_id}': {missing}.",
            }

        return _exec_tags, _verify_tags

    if action_type == "delete_unattached_ebs_volume":
        def _exec_delete_ebs() -> None:
            if is_live_aws():
                raise RuntimeError("Cost remediation execution in Live AWS mode is blocked by safety guard.")
            ec2 = _resolve_client("ec2", region, clients)

            def _apply() -> None:
                vols = ec2.describe_volumes(VolumeIds=[resource_id]).get("Volumes", [])
                if not vols:
                    raise RuntimeError(f"EBS volume '{resource_id}' not found.")
                vol = vols[0]
                if vol.get("State") != "available" or vol.get("Attachments"):
                    raise RuntimeError(
                        f"Refusing deletion: EBS volume '{resource_id}' is not unattached "
                        f"(state={vol.get('State')})."
                    )
                ec2.delete_volume(VolumeId=resource_id)

            ok, msg = safe_execute_remediation(f"delete_unattached_ebs_volume:{resource_id}", _apply)
            if not ok:
                raise RuntimeError(msg)

        def _verify_delete_ebs() -> Tuple[VerificationState, Dict[str, Any]]:
            if is_dry_run():
                return VerificationState.PARTIAL, {
                    "status": "PARTIAL",
                    "dry_run": True,
                    "evidence": "Dry-run mode enabled; EBS volume was not deleted.",
                }
            ec2 = _resolve_client("ec2", region, clients)
            try:
                vols = ec2.describe_volumes(VolumeIds=[resource_id]).get("Volumes", [])
                if not vols or vols[0].get("State") == "deleted":
                    return VerificationState.PASS, {
                        "status": "PASS",
                        "volume_id": resource_id,
                        "evidence": f"Independent check confirmed unattached EBS volume '{resource_id}' is deleted.",
                    }
                return VerificationState.FAIL, {
                    "status": "FAIL",
                    "volume_id": resource_id,
                    "observed_state": vols[0].get("State"),
                    "evidence": f"EBS volume '{resource_id}' still exists.",
                }
            except Exception as exc:
                if "InvalidVolume.NotFound" in str(exc):
                    return VerificationState.PASS, {
                        "status": "PASS",
                        "volume_id": resource_id,
                        "evidence": f"Independent check confirmed EBS volume '{resource_id}' no longer exists.",
                    }
                return VerificationState.FAIL, {"status": "FAIL", "error": str(exc)}

        return _exec_delete_ebs, _verify_delete_ebs

    if action_type == "rightsize_ec2_instance":
        target_type = str(proposed.get("target_instance_type") or "")

        def _exec_rightsize() -> None:
            if is_live_aws():
                raise RuntimeError("Cost remediation execution in Live AWS mode is blocked by safety guard.")
            if not target_type:
                raise RuntimeError("target_instance_type is required for EC2 rightsizing.")
            ec2 = _resolve_client("ec2", region, clients)

            def _apply() -> None:
                res = ec2.describe_instances(InstanceIds=[resource_id]).get("Reservations", [])
                inst = res[0]["Instances"][0] if res and res[0].get("Instances") else None
                if not inst:
                    raise RuntimeError(f"EC2 instance '{resource_id}' not found.")
                was_running = (inst.get("State") or {}).get("Name") == "running"
                if was_running:
                    ec2.stop_instances(InstanceIds=[resource_id])
                ec2.modify_instance_attribute(
                    InstanceId=resource_id,
                    InstanceType={"Value": target_type},
                )
                if was_running:
                    ec2.start_instances(InstanceIds=[resource_id])

            ok, msg = safe_execute_remediation(f"rightsize_ec2_instance:{resource_id}", _apply)
            if not ok:
                raise RuntimeError(msg)

        def _verify_rightsize() -> Tuple[VerificationState, Dict[str, Any]]:
            if is_dry_run():
                return VerificationState.PARTIAL, {
                    "status": "PARTIAL",
                    "dry_run": True,
                    "evidence": "Dry-run mode enabled; EC2 instance type was not modified.",
                }
            ec2 = _resolve_client("ec2", region, clients)
            res = ec2.describe_instances(InstanceIds=[resource_id]).get("Reservations", [])
            inst = res[0]["Instances"][0] if res and res[0].get("Instances") else None
            observed_type = inst.get("InstanceType") if inst else None
            if observed_type == target_type:
                return VerificationState.PASS, {
                    "status": "PASS",
                    "instance_id": resource_id,
                    "instance_type": observed_type,
                    "evidence": f"Independent check confirmed '{resource_id}' is now '{observed_type}'.",
                }
            return VerificationState.FAIL, {
                "status": "FAIL",
                "instance_id": resource_id,
                "observed_instance_type": observed_type,
                "expected_instance_type": target_type,
                "evidence": f"Instance '{resource_id}' remains '{observed_type}'.",
            }

        return _exec_rightsize, _verify_rightsize

    return None, None


def summarize_cost_remediations(soc_store: Any) -> Dict[str, Any]:
    """Summarize actual workflow remediation records from SOCStore without fabrication."""
    if soc_store is None or not hasattr(soc_store, "list_remediation_tasks"):
        return {
            "all_tasks_summary": {
                "total": 0,
                "approved": 0,
                "executed": 0,
                "failed": 0,
                "independently_verified": 0,
                "pending": 0,
                "rolled_back": 0,
            },
            "cost_tasks_summary": {
                "total": 0,
                "approved": 0,
                "executed": 0,
                "failed": 0,
                "independently_verified": 0,
                "pending": 0,
                "rolled_back": 0,
            },
            "realized_monthly_savings": 0.0,
            "cost_tasks": [],
        }

    all_tasks: List[Dict[str, Any]] = soc_store.list_remediation_tasks()

    def _summarize(subset: List[Dict[str, Any]]) -> Dict[str, int]:
        approved_statuses = {
            RemediationStatus.APPROVED.value,
            RemediationStatus.IN_PROGRESS.value,
            RemediationStatus.APPLIED.value,
            RemediationStatus.VERIFIED.value,
        }
        executed_statuses = {
            RemediationStatus.APPLIED.value,
            RemediationStatus.VERIFIED.value,
            RemediationStatus.FAILED.value,
        }
        return {
            "total": len(subset),
            "approved": sum(1 for t in subset if t.get("status") in approved_statuses or t.get("approved_at")),
            "executed": sum(1 for t in subset if t.get("status") in executed_statuses or t.get("applied_at")),
            "failed": sum(1 for t in subset if t.get("status") == RemediationStatus.FAILED.value),
            "independently_verified": sum(
                1 for t in subset
                if t.get("status") == RemediationStatus.VERIFIED.value
                and t.get("verification_state") == VerificationState.PASS.value
            ),
            "pending": sum(1 for t in subset if t.get("status") == RemediationStatus.PENDING.value),
            "rolled_back": sum(1 for t in subset if t.get("status") == RemediationStatus.ROLLED_BACK.value),
        }

    cost_tasks = [
        t for t in all_tasks
        if str(t.get("related_finding_id") or "").startswith("FIN-")
        or (t.get("proposed_change") or {}).get("domain") == "cost_optimization"
    ]

    realized_savings = 0.0
    for t in cost_tasks:
        if (
            t.get("status") == RemediationStatus.VERIFIED.value
            and t.get("verification_state") == VerificationState.PASS.value
        ):
            est = (t.get("proposed_change") or {}).get("estimated_monthly_savings")
            if est is not None:
                realized_savings += float(est)

    return {
        "all_tasks_summary": _summarize(all_tasks),
        "cost_tasks_summary": _summarize(cost_tasks),
        "realized_monthly_savings": round(realized_savings, 4),
        "cost_tasks": cost_tasks,
    }
