"""Guarded Moto / AWS Resource Inventory Collector for Cost Intelligence.

Collects real resource metadata strictly from the configured local Moto simulator
(via `backend.aws_guard.get_aws_client`) or explicitly injected test clients,
combined with ThreatGuard's existing CloudTrail telemetry and IAM capability graph.

Never fabricates resource records or pricing inputs when fields or services are unavailable.
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from backend.aws_guard import (
    get_aws_client,
    is_live_aws,
    is_simulator_available,
    resolve_account_id,
)

logger = logging.getLogger("threatguard.cost.inventory")

DEFAULT_REGIONS = ["us-east-1"]


def _tags_to_dict(raw_tags: Any) -> Dict[str, str]:
    """Convert AWS Tag list [{'Key': ..., 'Value': ...}] to normalized dict."""
    out: Dict[str, str] = {}
    if isinstance(raw_tags, list):
        for t in raw_tags:
            if isinstance(t, dict) and t.get("Key"):
                out[str(t["Key"])] = str(t.get("Value", ""))
    elif isinstance(raw_tags, dict):
        for k, v in raw_tags.items():
            out[str(k)] = str(v)
    return out


def _iso_or_none(val: Any) -> Optional[str]:
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        try:
            return val.isoformat()
        except Exception:
            return str(val)
    return str(val)


def _region_from_az(az: Optional[str], fallback: str = "us-east-1") -> str:
    if az and len(az) >= 2 and az[-1].isalpha():
        return az[:-1]
    return fallback


def collect_resource_inventory(
    clients: Optional[Dict[str, Any]] = None,
    state_store: Optional[Any] = None,
    iam_graph: Optional[Any] = None,
    regions: Optional[List[str]] = None,
    check_simulator_socket: bool = True,
) -> Dict[str, Any]:
    """Collect normalized inventory across supported Moto/AWS services.

    Args:
        clients: Optional dict of pre-built boto3 clients (e.g. for @mock_aws tests).
        state_store: ThreatGuard StateStore for CloudTrail telemetry events.
        iam_graph: Optional IAMCapabilityGraph for IAM ownership/escalation context.
        regions: List of AWS regions to scan for regional services (EC2/EBS/CloudTrail).
        check_simulator_socket: When True and no explicit clients are injected, probe
            localhost simulator availability before making boto3 calls.

    Returns:
        Structured inventory snapshot dictionary.
    """
    live = is_live_aws()
    environment = "Live AWS" if live else "Moto Simulated Cloud"
    target_regions = [r.strip() for r in (regions or DEFAULT_REGIONS) if r and r.strip()]
    if not target_regions:
        target_regions = list(DEFAULT_REGIONS)

    clients_injected = clients is not None
    simulator_online = True
    if not clients_injected and not live and check_simulator_socket:
        simulator_online = is_simulator_available()

    resources: List[Dict[str, Any]] = []
    service_availability: Dict[str, Dict[str, Any]] = {
        "sts": {"status": "unavailable", "operations": [], "notes": []},
        "ec2": {"status": "unavailable", "operations": [], "notes": []},
        "ebs": {"status": "unavailable", "operations": [], "notes": []},
        "s3": {"status": "unavailable", "operations": [], "notes": []},
        "iam": {"status": "unavailable", "operations": [], "notes": []},
        "cloudtrail": {"status": "unavailable", "operations": [], "notes": []},
    }

    account_id = "unavailable"
    caller_identity: Dict[str, Any] = {"available": False}

    def _get_client(svc: str, region: str = "us-east-1") -> Optional[Any]:
        if clients_injected:
            # Support either flat {'ec2': client} or regional {('ec2', 'us-east-1'): client}
            if (svc, region) in clients:
                return clients[(svc, region)]
            return clients.get(svc)
        if not live and not simulator_online:
            return None
        return get_aws_client(svc, region_name=region)

    # 1. STS Caller Identity (Account & Identity Metadata)
    sts_client = _get_client("sts", target_regions[0])
    if sts_client is not None:
        try:
            ident = sts_client.get_caller_identity()
            account_id = resolve_account_id(sts_client)
            caller_identity = {
                "available": True,
                "account_id": account_id,
                "arn": ident.get("Arn") if not live else "masked-in-live-mode",
                "user_id": ident.get("UserId") if not live else "masked-in-live-mode",
            }
            service_availability["sts"] = {
                "status": "available",
                "operations": ["sts:GetCallerIdentity"],
                "notes": [],
            }
        except Exception as exc:
            logger.debug("STS get_caller_identity unavailable: %s", exc)
            service_availability["sts"]["notes"].append(f"sts:GetCallerIdentity failed: {type(exc).__name__}")
    else:
        service_availability["sts"]["notes"].append("Simulator endpoint offline; STS identity unavailable.")

    # 2. EC2 Instances & 3. EBS Volumes (per region)
    ec2_ops_used: set = set()
    ebs_ops_used: set = set()
    ec2_errors: List[str] = []
    ebs_errors: List[str] = []
    ec2_succeeded_any_region = False
    ebs_succeeded_any_region = False
    seen_instance_ids: set = set()
    seen_volume_ids: set = set()

    for reg in target_regions:
        ec2_client = _get_client("ec2", reg)
        if ec2_client is None:
            continue

        # EC2 Instances
        try:
            resp = ec2_client.describe_instances()
            ec2_ops_used.add("ec2:DescribeInstances")
            ec2_succeeded_any_region = True
            for reservation in resp.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    iid = inst.get("InstanceId")
                    if not iid or iid in seen_instance_ids:
                        continue
                    seen_instance_ids.add(iid)
                    placement = inst.get("Placement") or {}
                    az = placement.get("AvailabilityZone")
                    inst_region = _region_from_az(az, fallback=reg)
                    tags = _tags_to_dict(inst.get("Tags"))
                    state_name = (inst.get("State") or {}).get("Name") or "unknown"
                    if state_name == "terminated":
                        continue
                    attached_vols = [
                        bdm.get("Ebs", {}).get("VolumeId")
                        for bdm in inst.get("BlockDeviceMappings", [])
                        if isinstance(bdm, dict) and bdm.get("Ebs", {}).get("VolumeId")
                    ]
                    resources.append({
                        "resource_id": iid,
                        "name": tags.get("Name") or iid,
                        "service": "ec2",
                        "resource_type": inst.get("InstanceType") or "unavailable",
                        "region": inst_region,
                        "availability_zone": az or "unavailable",
                        "state": state_name,
                        "tags": tags,
                        "metadata": {
                            "launch_time": _iso_or_none(inst.get("LaunchTime")),
                            "vpc_id": inst.get("VpcId"),
                            "subnet_id": inst.get("SubnetId"),
                            "attached_volume_ids": attached_vols,
                            "iam_instance_profile": (inst.get("IamInstanceProfile") or {}).get("Arn"),
                            "utilization_metrics": "unavailable",
                        },
                    })
        except Exception as exc:
            ec2_errors.append(f"{reg}: {type(exc).__name__}")

        # EBS Volumes
        try:
            vol_resp = ec2_client.describe_volumes()
            ebs_ops_used.add("ec2:DescribeVolumes")
            ebs_succeeded_any_region = True
            for vol in vol_resp.get("Volumes", []):
                vid = vol.get("VolumeId")
                if not vid or vid in seen_volume_ids:
                    continue
                seen_volume_ids.add(vid)
                if vol.get("State") == "deleted":
                    continue
                az = vol.get("AvailabilityZone")
                vol_region = _region_from_az(az, fallback=reg)
                tags = _tags_to_dict(vol.get("Tags"))
                attachments = vol.get("Attachments") or []
                attached_instance_ids = [
                    att.get("InstanceId") for att in attachments if isinstance(att, dict) and att.get("InstanceId")
                ]
                resources.append({
                    "resource_id": vid,
                    "name": tags.get("Name") or vid,
                    "service": "ebs",
                    "resource_type": vol.get("VolumeType") or "unavailable",
                    "region": vol_region,
                    "availability_zone": az or "unavailable",
                    "state": vol.get("State") or "unknown",
                    "tags": tags,
                    "metadata": {
                        "size_gb": vol.get("Size"),
                        "iops": vol.get("Iops"),
                        "encrypted": vol.get("Encrypted"),
                        "attachments": [
                            {
                                "instance_id": att.get("InstanceId"),
                                "device": att.get("Device"),
                                "state": att.get("State"),
                            }
                            for att in attachments
                            if isinstance(att, dict)
                        ],
                        "attached_instance_ids": attached_instance_ids,
                        "create_time": _iso_or_none(vol.get("CreateTime")),
                    },
                })
        except Exception as exc:
            ebs_errors.append(f"{reg}: {type(exc).__name__}")

    if ec2_succeeded_any_region:
        service_availability["ec2"] = {
            "status": "available",
            "operations": sorted(ec2_ops_used),
            "notes": ec2_errors + ["CloudWatch CPU/memory utilization metrics are unavailable in Moto simulator."],
        }
    else:
        service_availability["ec2"]["notes"].extend(ec2_errors or ["Simulator endpoint offline; EC2 unavailable."])

    if ebs_succeeded_any_region:
        service_availability["ebs"] = {
            "status": "available",
            "operations": sorted(ebs_ops_used),
            "notes": ebs_errors,
        }
    else:
        service_availability["ebs"]["notes"].extend(ebs_errors or ["Simulator endpoint offline; EBS unavailable."])

    # 4. S3 Buckets (Global listing, per-bucket region/objects/versioning/lifecycle/tags)
    s3_client = _get_client("s3", target_regions[0])
    s3_ops_used: set = set()
    s3_notes: List[str] = []
    if s3_client is not None:
        try:
            buckets_resp = s3_client.list_buckets()
            s3_ops_used.add("s3:ListBuckets")
            for b in buckets_resp.get("Buckets", []):
                bname = b.get("Name")
                if not bname:
                    continue

                # Region
                bucket_region = target_regions[0]
                try:
                    loc = s3_client.get_bucket_location(Bucket=bname).get("LocationConstraint")
                    s3_ops_used.add("s3:GetBucketLocation")
                    bucket_region = loc if loc else "us-east-1"
                except Exception:
                    pass

                # Object metadata (size & storage class breakdown)
                total_bytes: Optional[int] = 0
                object_count: Optional[int] = 0
                storage_classes: Dict[str, int] = {}
                storage_unknown = False
                try:
                    token: Optional[str] = None
                    while True:
                        kwargs: Dict[str, Any] = {"Bucket": bname}
                        if token:
                            kwargs["ContinuationToken"] = token
                        obj_resp = s3_client.list_objects_v2(**kwargs)
                        s3_ops_used.add("s3:ListObjectsV2")
                        for obj in obj_resp.get("Contents", []):
                            sz = int(obj.get("Size", 0))
                            sc = str(obj.get("StorageClass") or "STANDARD")
                            total_bytes += sz
                            object_count += 1
                            storage_classes[sc] = storage_classes.get(sc, 0) + sz
                        if obj_resp.get("IsTruncated"):
                            token = obj_resp.get("NextContinuationToken")
                        else:
                            break
                except Exception as exc:
                    storage_unknown = True
                    total_bytes = None
                    object_count = None
                    s3_notes.append(f"s3:ListObjectsV2 failed for {bname}: {type(exc).__name__}")

                # Versioning
                versioning_status = "Unavailable"
                try:
                    ver_resp = s3_client.get_bucket_versioning(Bucket=bname)
                    s3_ops_used.add("s3:GetBucketVersioning")
                    versioning_status = ver_resp.get("Status") or "Disabled"
                except Exception:
                    versioning_status = "Unavailable"

                # Lifecycle configuration
                has_lifecycle = False
                lifecycle_rules: List[Dict[str, Any]] = []
                lifecycle_status = "None"
                try:
                    lc_resp = s3_client.get_bucket_lifecycle_configuration(Bucket=bname)
                    s3_ops_used.add("s3:GetBucketLifecycleConfiguration")
                    rules_list = lc_resp.get("Rules", [])
                    has_lifecycle = len(rules_list) > 0
                    lifecycle_status = "Configured" if has_lifecycle else "None"
                    for r in rules_list:
                        lifecycle_rules.append({
                            "id": r.get("ID"),
                            "status": r.get("Status"),
                            "transitions": r.get("Transitions", []),
                            "expiration": r.get("Expiration"),
                            "noncurrent_version_expiration": r.get("NoncurrentVersionExpiration"),
                        })
                except Exception as exc:
                    if "NoSuchLifecycleConfiguration" in str(exc):
                        has_lifecycle = False
                        lifecycle_status = "None"
                        s3_ops_used.add("s3:GetBucketLifecycleConfiguration")
                    else:
                        lifecycle_status = "Unavailable"

                # Tags
                bucket_tags: Dict[str, str] = {}
                try:
                    tag_resp = s3_client.get_bucket_tagging(Bucket=bname)
                    s3_ops_used.add("s3:GetBucketTagging")
                    bucket_tags = _tags_to_dict(tag_resp.get("TagSet"))
                except Exception:
                    bucket_tags = {}

                # Public Access Block
                pab_cfg: Optional[Dict[str, Any]] = None
                try:
                    pab_resp = s3_client.get_public_access_block(Bucket=bname)
                    s3_ops_used.add("s3:GetPublicAccessBlock")
                    pab_cfg = pab_resp.get("PublicAccessBlockConfiguration")
                except Exception:
                    pab_cfg = None

                # Dominant storage class if objects exist, else STANDARD
                dominant_sc = (
                    max(storage_classes.items(), key=lambda kv: kv[1])[0]
                    if storage_classes
                    else "STANDARD"
                )
                resources.append({
                    "resource_id": bname,
                    "name": bname,
                    "service": "s3",
                    "resource_type": dominant_sc,
                    "region": bucket_region,
                    "availability_zone": "regional",
                    "state": "active",
                    "tags": bucket_tags,
                    "metadata": {
                        "creation_date": _iso_or_none(b.get("CreationDate")),
                        "object_count": object_count,
                        "total_bytes": total_bytes,
                        "storage_gb": round(total_bytes / (1024 ** 3), 6) if total_bytes is not None else None,
                        "storage_unknown": storage_unknown,
                        "storage_classes_bytes": storage_classes,
                        "versioning": versioning_status,
                        "has_lifecycle": has_lifecycle,
                        "lifecycle_status": lifecycle_status,
                        "lifecycle_rules": lifecycle_rules,
                        "public_access_block": pab_cfg,
                    },
                })

            service_availability["s3"] = {
                "status": "available",
                "operations": sorted(s3_ops_used),
                "notes": s3_notes,
            }
        except Exception as exc:
            service_availability["s3"]["notes"].append(f"s3:ListBuckets failed: {type(exc).__name__}")
    else:
        service_availability["s3"]["notes"].append("Simulator endpoint offline; S3 unavailable.")

    # 5. IAM Users, Roles, Policies & Ownership Relationships
    iam_client = _get_client("iam", target_regions[0])
    iam_ops_used: set = set()
    iam_notes: List[str] = []
    if iam_client is not None:
        try:
            users_resp = iam_client.list_users()
            iam_ops_used.add("iam:ListUsers")
            for u in users_resp.get("Users", []):
                uname = u.get("UserName")
                if not uname:
                    continue
                attached_policies: List[str] = []
                try:
                    ap = iam_client.list_attached_user_policies(UserName=uname)
                    iam_ops_used.add("iam:ListAttachedUserPolicies")
                    attached_policies = [p.get("PolicyName", "") for p in ap.get("AttachedPolicies", [])]
                except Exception:
                    pass
                u_tags: Dict[str, str] = {}
                try:
                    ut = iam_client.list_user_tags(UserName=uname)
                    iam_ops_used.add("iam:ListUserTags")
                    u_tags = _tags_to_dict(ut.get("Tags"))
                except Exception:
                    pass
                resources.append({
                    "resource_id": f"user/{uname}",
                    "name": uname,
                    "service": "iam",
                    "resource_type": "identity",
                    "region": "global",
                    "availability_zone": "global",
                    "state": "active",
                    "tags": u_tags,
                    "metadata": {
                        "iam_kind": "IAMUser",
                        "arn": u.get("Arn"),
                        "create_date": _iso_or_none(u.get("CreateDate")),
                        "attached_policies": attached_policies,
                    },
                })

            roles_resp = iam_client.list_roles()
            iam_ops_used.add("iam:ListRoles")
            for r in roles_resp.get("Roles", []):
                rname = r.get("RoleName")
                if not rname:
                    continue
                attached_role_policies: List[str] = []
                try:
                    arp = iam_client.list_attached_role_policies(RoleName=rname)
                    iam_ops_used.add("iam:ListAttachedRolePolicies")
                    attached_role_policies = [p.get("PolicyName", "") for p in arp.get("AttachedPolicies", [])]
                except Exception:
                    pass
                resources.append({
                    "resource_id": f"role/{rname}",
                    "name": rname,
                    "service": "iam",
                    "resource_type": "identity",
                    "region": "global",
                    "availability_zone": "global",
                    "state": "active",
                    "tags": {},
                    "metadata": {
                        "iam_kind": "IAMRole",
                        "arn": r.get("Arn"),
                        "create_date": _iso_or_none(r.get("CreateDate")),
                        "attached_policies": attached_role_policies,
                    },
                })

            try:
                pol_resp = iam_client.list_policies(Scope="Local")
                iam_ops_used.add("iam:ListPolicies")
                for p in pol_resp.get("Policies", []):
                    pname = p.get("PolicyName")
                    if not pname:
                        continue
                    resources.append({
                        "resource_id": f"policy/{pname}",
                        "name": pname,
                        "service": "iam",
                        "resource_type": "identity",
                        "region": "global",
                        "availability_zone": "global",
                        "state": "active",
                        "tags": {},
                        "metadata": {
                            "iam_kind": "IAMPolicy",
                            "arn": p.get("Arn"),
                            "attachment_count": p.get("AttachmentCount", 0),
                        },
                    })
            except Exception:
                pass

            service_availability["iam"] = {
                "status": "available",
                "operations": sorted(iam_ops_used),
                "notes": iam_notes,
            }
        except Exception as exc:
            service_availability["iam"]["notes"].append(f"iam query failed: {type(exc).__name__}")
    else:
        service_availability["iam"]["notes"].append("Simulator endpoint offline; IAM API unavailable.")

    # IAM capability graph ownership / relationship context (read-only enrichment)
    iam_relationships_count = 0
    if iam_graph is not None and hasattr(iam_graph, "graph"):
        try:
            iam_relationships_count = iam_graph.graph.number_of_edges()
        except Exception:
            iam_relationships_count = 0

    # 6. CloudTrail Trails + Telemetry Events
    ct_ops_used: set = set()
    ct_notes: List[str] = ["cloudtrail:LookupEvents is not implemented in Moto 5.2.5; event telemetry comes from ThreatGuard StateStore."]
    ct_client = _get_client("cloudtrail", target_regions[0])
    if ct_client is not None:
        try:
            trails_resp = ct_client.describe_trails()
            ct_ops_used.add("cloudtrail:DescribeTrails")
            for tr in trails_resp.get("trailList", []):
                tname = tr.get("Name")
                if not tname:
                    continue
                is_logging: Optional[bool] = None
                try:
                    st = ct_client.get_trail_status(Name=tname)
                    ct_ops_used.add("cloudtrail:GetTrailStatus")
                    is_logging = bool(st.get("IsLogging", False))
                except Exception:
                    is_logging = None
                resources.append({
                    "resource_id": tname,
                    "name": tname,
                    "service": "cloudtrail",
                    "resource_type": "management-trail",
                    "region": tr.get("HomeRegion") or target_regions[0],
                    "availability_zone": "regional",
                    "state": "logging" if is_logging is True else ("stopped" if is_logging is False else "unknown"),
                    "tags": {},
                    "metadata": {
                        "s3_bucket_name": tr.get("S3BucketName"),
                        "is_multi_region": tr.get("IsMultiRegionTrail"),
                        "trail_arn": tr.get("TrailARN"),
                        "is_logging": is_logging,
                    },
                })
            service_availability["cloudtrail"] = {
                "status": "partial",
                "operations": sorted(ct_ops_used),
                "notes": ct_notes,
            }
        except Exception as exc:
            service_availability["cloudtrail"]["notes"].append(f"cloudtrail:DescribeTrails failed: {type(exc).__name__}")
    else:
        service_availability["cloudtrail"]["notes"].append("Simulator endpoint offline; CloudTrail API unavailable.")

    # Collect CloudTrail telemetry events recorded in ThreatGuard StateStore
    telemetry_events: List[Dict[str, Any]] = []
    if state_store is not None and hasattr(state_store, "get_telemetry_events"):
        try:
            telemetry_events = state_store.get_telemetry_events(limit=300)
        except Exception:
            telemetry_events = []

    events_by_service: Dict[str, int] = {}
    principals_seen: set = set()
    for ev in telemetry_events:
        svc_name = str(ev.get("src") or "unknown")
        events_by_service[svc_name] = events_by_service.get(svc_name, 0) + 1
        if ev.get("user"):
            principals_seen.add(str(ev["user"]))

    for svc_key, meta_av in service_availability.items():
        svc_count = sum(1 for r in resources if r.get("service") == svc_key)
        meta_av["resource_count"] = svc_count
        if meta_av["status"] in ("available", "partial") and svc_count == 0:
            meta_av.setdefault("notes", []).append(
                f"API reachable; 0 {svc_key.upper()} resources observed in scanned region(s)."
            )

    return {
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "environment": environment,
        "simulator_available": simulator_online if not clients_injected else True,
        "account_id": account_id,
        "caller_identity": caller_identity,
        "regions_scanned": target_regions,
        "resources": resources,
        "resource_count": len(resources),
        "service_availability": service_availability,
        "iam_graph_relationships": iam_relationships_count,
        "cloudtrail_summary": {
            "telemetry_event_count": len(telemetry_events),
            "events_by_service": events_by_service,
            "unique_principals": sorted(principals_seen),
            "recent_events": telemetry_events[:25],
            "note": "Missing CloudTrail events do not prove a resource is idle.",
        },
    }
