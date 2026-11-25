"""Optional Operator-Controlled FinOps Demonstration Scenario for Moto.

Provisions a deterministic, idempotent set of realistic billable resources
(EC2 instances, attached & unattached EBS volumes, and populated S3 buckets)
tagged with ThreatGuardScenario=finops-demo, reusing existing IAM and CloudTrail
identities without altering default safe_setup() behavior or unrelated resources.
"""
import logging
from typing import Any, Dict, List, Optional

from backend.aws_guard import get_aws_client, is_live_aws, is_simulator_available

logger = logging.getLogger("threatguard.cost.demo_scenario")

SCENARIO_TAG_KEY = "ThreatGuardScenario"
SCENARIO_TAG_VALUE = "finops-demo"
DEMO_BUCKET_ANALYTICS = "finops-demo-analytics-data"
DEMO_BUCKET_ARCHIVE = "finops-demo-archive-logs"
DEMO_BUCKETS = (DEMO_BUCKET_ANALYTICS, DEMO_BUCKET_ARCHIVE)


def _tags_dict(raw_tags: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(raw_tags, list):
        for t in raw_tags:
            if isinstance(t, dict) and t.get("Key"):
                out[str(t["Key"])] = str(t.get("Value", ""))
    return out


def _resolve_clients(clients: Optional[Dict[str, Any]], region: str) -> Dict[str, Any]:
    if clients is not None:
        return clients
    return {
        "ec2": get_aws_client("ec2", region_name=region),
        "s3": get_aws_client("s3", region_name=region),
        "iam": get_aws_client("iam", region_name=region),
        "cloudtrail": get_aws_client("cloudtrail", region_name=region),
    }


def _find_scenario_instances(ec2_client: Any) -> List[Dict[str, Any]]:
    resp = ec2_client.describe_instances(
        Filters=[{"Name": f"tag:{SCENARIO_TAG_KEY}", "Values": [SCENARIO_TAG_VALUE]}]
    )
    out: List[Dict[str, Any]] = []
    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            state = (inst.get("State") or {}).get("Name")
            if state != "terminated":
                out.append(inst)
    return out


def _find_scenario_volumes(ec2_client: Any) -> List[Dict[str, Any]]:
    resp = ec2_client.describe_volumes(
        Filters=[{"Name": f"tag:{SCENARIO_TAG_KEY}", "Values": [SCENARIO_TAG_VALUE]}]
    )
    return [v for v in resp.get("Volumes", []) if v.get("State") != "deleted"]


def _inspect_s3_bucket(s3_client: Any, bucket_name: str) -> Optional[Dict[str, Any]]:
    existing = {b.get("Name") for b in s3_client.list_buckets().get("Buckets", [])}
    if bucket_name not in existing:
        return None
    total_bytes = 0
    obj_count = 0
    try:
        objs = s3_client.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        obj_count = len(objs)
        total_bytes = sum(int(o.get("Size", 0)) for o in objs)
    except Exception:
        pass
    versioning = "Disabled"
    try:
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name).get("Status") or "Disabled"
    except Exception:
        pass
    has_lifecycle = False
    try:
        lc = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        has_lifecycle = bool(lc.get("Rules"))
    except Exception:
        has_lifecycle = False
    tags = {}
    try:
        tags = _tags_dict(s3_client.get_bucket_tagging(Bucket=bucket_name).get("TagSet"))
    except Exception:
        pass
    return {
        "bucket_name": bucket_name,
        "object_count": obj_count,
        "total_bytes": total_bytes,
        "versioning": versioning,
        "has_lifecycle": has_lifecycle,
        "tags": tags,
    }


def inspect_finops_demo_scenario(
    clients: Optional[Dict[str, Any]] = None,
    region: str = "us-east-1",
) -> Dict[str, Any]:
    """Inspect current FinOps demo scenario resources without modifying simulator state."""
    if clients is None and not is_live_aws() and not is_simulator_available():
        return {
            "simulator_available": False,
            "loaded": False,
            "ec2_instances": [],
            "ebs_volumes": [],
            "s3_buckets": [],
            "reused_identities": [],
            "reused_trails": [],
        }

    cli = _resolve_clients(clients, region)
    ec2 = cli["ec2"]
    s3 = cli["s3"]
    iam = cli.get("iam")
    ct = cli.get("cloudtrail")

    instances = _find_scenario_instances(ec2)
    volumes = _find_scenario_volumes(ec2)
    buckets = [b for b in (_inspect_s3_bucket(s3, bn) for bn in DEMO_BUCKETS) if b is not None]

    reused_identities: List[str] = []
    if iam is not None:
        try:
            reused_identities = [u.get("UserName") for u in iam.list_users().get("Users", []) if u.get("UserName")]
        except Exception:
            pass

    reused_trails: List[str] = []
    if ct is not None:
        try:
            reused_trails = [t.get("Name") for t in ct.describe_trails().get("trailList", []) if t.get("Name")]
        except Exception:
            pass

    ec2_out = [
        {
            "instance_id": inst.get("InstanceId"),
            "instance_type": inst.get("InstanceType"),
            "state": (inst.get("State") or {}).get("Name"),
            "availability_zone": (inst.get("Placement") or {}).get("AvailabilityZone"),
            "tags": _tags_dict(inst.get("Tags")),
        }
        for inst in instances
    ]
    ebs_out = [
        {
            "volume_id": vol.get("VolumeId"),
            "size_gb": vol.get("Size"),
            "volume_type": vol.get("VolumeType"),
            "state": vol.get("State"),
            "availability_zone": vol.get("AvailabilityZone"),
            "attachments": [
                {"instance_id": a.get("InstanceId"), "device": a.get("Device"), "state": a.get("State")}
                for a in (vol.get("Attachments") or [])
            ],
            "tags": _tags_dict(vol.get("Tags")),
        }
        for vol in volumes
    ]

    loaded = bool(ec2_out or ebs_out or buckets)
    return {
        "simulator_available": True,
        "loaded": loaded,
        "scenario_tag": f"{SCENARIO_TAG_KEY}={SCENARIO_TAG_VALUE}",
        "ec2_instances": ec2_out,
        "ebs_volumes": ebs_out,
        "s3_buckets": buckets,
        "reused_identities": reused_identities,
        "reused_trails": reused_trails,
    }


def load_finops_demo_scenario(
    clients: Optional[Dict[str, Any]] = None,
    state_store: Optional[Any] = None,
    region: str = "us-east-1",
) -> Dict[str, Any]:
    """Idempotently provision realistic billable EC2, EBS, and S3 demo resources in Moto."""
    if is_live_aws():
        raise PermissionError("FinOps Demo Scenario cannot be loaded in Live AWS mode.")
    if clients is None and not is_simulator_available():
        raise ConnectionError("Moto simulator is offline on port 5000.")

    cli = _resolve_clients(clients, region)
    ec2 = cli["ec2"]
    s3 = cli["s3"]
    az = f"{region}a"

    existing_instances = _find_scenario_instances(ec2)
    by_name_inst = {_tags_dict(i.get("Tags")).get("Name"): i for i in existing_instances}

    # 1. EC2 Instance 1: Running t3.large compute worker (missing Owner/Environment tags -> governance + rightsizing)
    if "finops-demo-compute-worker" not in by_name_inst:
        resp1 = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t3.large",
            Placement={"AvailabilityZone": az},
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": "finops-demo-compute-worker"},
                    {"Key": SCENARIO_TAG_KEY, "Value": SCENARIO_TAG_VALUE},
                    {"Key": "Role", "Value": "compute-worker"},
                ],
            }],
        )
        inst1 = resp1["Instances"][0]
        for bdm in inst1.get("BlockDeviceMappings", []):
            vid = (bdm.get("Ebs") or {}).get("VolumeId")
            if vid:
                ec2.create_tags(
                    Resources=[vid],
                    Tags=[
                        {"Key": "Name", "Value": "finops-demo-worker-root"},
                        {"Key": SCENARIO_TAG_KEY, "Value": SCENARIO_TAG_VALUE},
                        {"Key": "Owner", "Value": "finops-compute-team"},
                    ],
                )

    # 2. EC2 Instance 2: Stopped m5.large batch standby with attached EBS storage
    if "finops-demo-batch-standby" not in by_name_inst:
        resp2 = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="m5.large",
            Placement={"AvailabilityZone": az},
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": "finops-demo-batch-standby"},
                    {"Key": SCENARIO_TAG_KEY, "Value": SCENARIO_TAG_VALUE},
                    {"Key": "Owner", "Value": "finops-batch-team"},
                ],
            }],
        )
        inst2 = resp2["Instances"][0]
        inst2_id = inst2["InstanceId"]
        for bdm in inst2.get("BlockDeviceMappings", []):
            vid = (bdm.get("Ebs") or {}).get("VolumeId")
            if vid:
                ec2.create_tags(
                    Resources=[vid],
                    Tags=[
                        {"Key": "Name", "Value": "finops-demo-standby-root"},
                        {"Key": SCENARIO_TAG_KEY, "Value": SCENARIO_TAG_VALUE},
                        {"Key": "Owner", "Value": "finops-batch-team"},
                    ],
                )
        ec2.stop_instances(InstanceIds=[inst2_id])
    else:
        inst2_id = by_name_inst["finops-demo-batch-standby"]["InstanceId"]

    # 3. EBS Volumes: 1 attached gp3 (100 GB) + 1 unattached gp2 (80 GB)
    existing_vols = _find_scenario_volumes(ec2)
    by_name_vol = {_tags_dict(v.get("Tags")).get("Name"): v for v in existing_vols}

    if "finops-demo-standby-data" not in by_name_vol:
        v_att = ec2.create_volume(
            AvailabilityZone=az,
            Size=100,
            VolumeType="gp3",
            TagSpecifications=[{
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Name", "Value": "finops-demo-standby-data"},
                    {"Key": SCENARIO_TAG_KEY, "Value": SCENARIO_TAG_VALUE},
                    {"Key": "Owner", "Value": "finops-batch-team"},
                ],
            }],
        )
        ec2.attach_volume(VolumeId=v_att["VolumeId"], InstanceId=inst2_id, Device="/dev/sdf")

    if "finops-demo-orphaned-vol" not in by_name_vol:
        ec2.create_volume(
            AvailabilityZone=az,
            Size=80,
            VolumeType="gp2",
            TagSpecifications=[{
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Name", "Value": "finops-demo-orphaned-vol"},
                    {"Key": SCENARIO_TAG_KEY, "Value": SCENARIO_TAG_VALUE},
                ],
            }],
        )

    # 4. S3 Buckets: 2 buckets with known object sizes, tags, versioning, lifecycle
    existing_bucket_names = {b.get("Name") for b in s3.list_buckets().get("Buckets", [])}

    if DEMO_BUCKET_ANALYTICS not in existing_bucket_names:
        s3.create_bucket(Bucket=DEMO_BUCKET_ANALYTICS)
    s3.put_bucket_versioning(
        Bucket=DEMO_BUCKET_ANALYTICS,
        VersioningConfiguration={"Status": "Enabled"},
    )
    s3.put_bucket_tagging(
        Bucket=DEMO_BUCKET_ANALYTICS,
        Tagging={
            "TagSet": [
                {"Key": SCENARIO_TAG_KEY, "Value": SCENARIO_TAG_VALUE},
                {"Key": "Tier", "Value": "analytics"},
            ]
        },
    )
    existing_objs_1 = {
        o.get("Key") for o in s3.list_objects_v2(Bucket=DEMO_BUCKET_ANALYTICS).get("Contents", [])
    }
    if "raw/events-2026-10.bin" not in existing_objs_1:
        s3.put_object(Bucket=DEMO_BUCKET_ANALYTICS, Key="raw/events-2026-10.bin", Body=b"A" * (4 * 1024 * 1024))
    if "raw/events-2026-11.bin" not in existing_objs_1:
        s3.put_object(Bucket=DEMO_BUCKET_ANALYTICS, Key="raw/events-2026-11.bin", Body=b"B" * (8 * 1024 * 1024))

    if DEMO_BUCKET_ARCHIVE not in existing_bucket_names:
        s3.create_bucket(Bucket=DEMO_BUCKET_ARCHIVE)
    s3.put_bucket_tagging(
        Bucket=DEMO_BUCKET_ARCHIVE,
        Tagging={
            "TagSet": [
                {"Key": SCENARIO_TAG_KEY, "Value": SCENARIO_TAG_VALUE},
                {"Key": "Owner", "Value": "finops-storage-team"},
            ]
        },
    )
    s3.put_bucket_lifecycle_configuration(
        Bucket=DEMO_BUCKET_ARCHIVE,
        LifecycleConfiguration={
            "Rules": [{
                "ID": "archive-ia-transition",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}],
            }]
        },
    )
    existing_objs_2 = {
        o.get("Key") for o in s3.list_objects_v2(Bucket=DEMO_BUCKET_ARCHIVE).get("Contents", [])
    }
    if "logs/oct.log" not in existing_objs_2:
        s3.put_object(Bucket=DEMO_BUCKET_ARCHIVE, Key="logs/oct.log", Body=b"C" * (1 * 1024 * 1024))
    if "logs/nov.log" not in existing_objs_2:
        s3.put_object(Bucket=DEMO_BUCKET_ARCHIVE, Key="logs/nov.log", Body=b"D" * (2 * 1024 * 1024))

    if state_store and hasattr(state_store, "append_audit_entry"):
        state_store.append_audit_entry(
            "FINOPS DEMO SCENARIO LOADED in Moto simulator (2 EC2, 2+ EBS, 2 S3 buckets)."
        )

    return inspect_finops_demo_scenario(clients=cli, region=region)


def reset_finops_demo_scenario(
    clients: Optional[Dict[str, Any]] = None,
    state_store: Optional[Any] = None,
    soc_store: Optional[Any] = None,
    region: str = "us-east-1",
) -> Dict[str, Any]:
    """Delete ONLY resources owned by ThreatGuardScenario=finops-demo, preserving unrelated resources."""
    if is_live_aws():
        raise PermissionError("FinOps Demo Scenario reset is disabled in Live AWS mode.")
    if clients is None and not is_simulator_available():
        raise ConnectionError("Moto simulator is offline on port 5000.")

    cli = _resolve_clients(clients, region)
    ec2 = cli["ec2"]
    s3 = cli["s3"]

    removed_ids: set = set()

    # 1. Detach & delete scenario EBS volumes (skip root volumes that auto-delete with instances)
    volumes = _find_scenario_volumes(ec2)
    explicit_non_root_vols = []
    for v in volumes:
        vid = v.get("VolumeId")
        removed_ids.add(vid)
        v_name = _tags_dict(v.get("Tags")).get("Name", "")
        if v_name not in ("finops-demo-worker-root", "finops-demo-standby-root"):
            explicit_non_root_vols.append(v)

    for v in explicit_non_root_vols:
        vid = v["VolumeId"]
        for att in v.get("Attachments") or []:
            try:
                ec2.detach_volume(VolumeId=vid, InstanceId=att.get("InstanceId"), Force=True)
            except Exception as exc:
                logger.debug("Detach volume %s error: %s", vid, exc)
        try:
            ec2.delete_volume(VolumeId=vid)
        except Exception as exc:
            logger.debug("Delete volume %s error: %s", vid, exc)

    # 2. Terminate scenario EC2 instances
    instances = _find_scenario_instances(ec2)
    inst_ids = [i["InstanceId"] for i in instances if i.get("InstanceId")]
    removed_ids.update(inst_ids)
    if inst_ids:
        ec2.terminate_instances(InstanceIds=inst_ids)

    # 3. Empty (including object versions) & delete ONLY demo S3 buckets
    existing_buckets = {b.get("Name") for b in s3.list_buckets().get("Buckets", [])}
    for bname in DEMO_BUCKETS:
        if bname not in existing_buckets:
            continue
        removed_ids.add(bname)
        try:
            vers = s3.list_object_versions(Bucket=bname)
            del_items = []
            for ov in vers.get("Versions", []):
                del_items.append({"Key": ov["Key"], "VersionId": ov["VersionId"]})
            for dm in vers.get("DeleteMarkers", []):
                del_items.append({"Key": dm["Key"], "VersionId": dm["VersionId"]})
            if del_items:
                s3.delete_objects(Bucket=bname, Delete={"Objects": del_items})
        except Exception:
            pass
        try:
            objs = s3.list_objects_v2(Bucket=bname).get("Contents", [])
            if objs:
                s3.delete_objects(Bucket=bname, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        except Exception:
            pass
        try:
            s3.delete_bucket(Bucket=bname)
        except Exception as exc:
            logger.debug("Delete bucket %s error: %s", bname, exc)

    # 4. Remove only FIN-* remediation tasks linked to removed demo resources
    if soc_store is not None and hasattr(soc_store, "_remediations"):
        with soc_store._lock:
            to_remove = []
            for rem_id, task in soc_store._remediations.items():
                fid = str(getattr(task, "related_finding_id", "") or "")
                res_name = str(getattr(task, "affected_resource", "") or "")
                if fid.startswith("FIN-") and any(rid and rid in res_name for rid in removed_ids):
                    to_remove.append(rem_id)
            for rem_id in to_remove:
                soc_store._remediations.pop(rem_id, None)

    if state_store and hasattr(state_store, "append_audit_entry"):
        state_store.append_audit_entry(
            f"FINOPS DEMO SCENARIO RESET completed (removed {len(removed_ids)} demo resource(s))."
        )

    return inspect_finops_demo_scenario(clients=cli, region=region)
