"""Unit tests for ThreatGuard Cost Intelligence & AWS Cost Optimization.

Covers:
- Pricing configuration loading and regional lookup
- Moto (@mock_aws) resource inventory collection (EC2, EBS, S3, IAM, CloudTrail, STS)
- EC2, EBS, S3 cost estimation and assumption transparency
- Missing metadata, missing pricing, empty datasets, and partial datasets
- Regional pricing differences
- Cost aggregation and before/after savings formula
- Evidence-based optimization findings (confirmed vs inferred)
- Report generation (all 11 sections) and SQLite history persistence
- Remediation execution, independent verification, and Live AWS safety guards
"""
from unittest.mock import MagicMock
import boto3
from moto import mock_aws
import pytest

from backend.aws_guard import get_aws_client, validate_endpoint_url
from backend.cost.estimator import estimate_infrastructure_costs, estimate_resource_cost
from backend.cost.inventory import collect_resource_inventory
from backend.cost.optimizer import analyze_cost_optimizations
from backend.cost.pricing import load_pricing_catalog
from backend.cost.remediation import (
    build_cost_executor_and_verifier,
    create_cost_remediation_task,
    summarize_cost_remediations,
)
from backend.cost.reports import generate_cost_report
from backend.soc.models import RemediationStatus, VerificationState
from backend.soc.store import SOCStore
from backend.state import StateStore


def _make_mock_clients(region: str = "us-east-1"):
    return {
        "ec2": boto3.client("ec2", region_name=region),
        "s3": boto3.client("s3", region_name=region),
        "iam": boto3.client("iam", region_name=region),
        "cloudtrail": boto3.client("cloudtrail", region_name=region),
        "sts": boto3.client("sts", region_name=region),
    }


def test_pricing_configuration_loading_and_override():
    catalog = load_pricing_catalog()
    meta = catalog.to_metadata_dict()
    assert meta["dataset_version"] == "2026.11-aws-finops-v1"
    assert meta["currency"] == "USD"
    assert meta["effective_date"] == "2026-11-01"
    assert meta["entry_count"] > 20

    ec2_us = catalog.lookup("ec2", "t3.large", "us-east-1")
    ec2_eu = catalog.lookup("ec2", "t3.large", "eu-west-1")
    assert ec2_us is not None and ec2_eu is not None
    assert ec2_eu.unit_price > ec2_us.unit_price
    assert catalog.lookup("ec2", "nonexistent.99xlarge", "us-east-1") is None

    # Configurable override dataset works without changing estimation code
    custom = load_pricing_catalog(override_data={
        "dataset_version": "custom-test-v2",
        "effective_date": "2026-12-01",
        "currency": "EUR",
        "pricing_source": "Custom Override",
        "entries": [
            {"service": "ec2", "resource_type": "t3.micro", "region": "us-east-1", "pricing_unit": "hour", "unit_price": 0.02}
        ],
    })
    assert custom.currency == "EUR"
    assert custom.lookup("ec2", "t3.micro", "us-east-1").unit_price == 0.02


def test_inventory_collection_from_moto():
    with mock_aws():
        clients = _make_mock_clients("us-east-1")
        ec2 = clients["ec2"]
        s3 = clients["s3"]
        iam = clients["iam"]
        ct = clients["cloudtrail"]

        # Create EC2 + unattached EBS + S3 + IAM + CloudTrail
        run_resp = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t3.large",
            TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "app-node"}]}],
        )
        inst_id = run_resp["Instances"][0]["InstanceId"]

        vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=50, VolumeType="gp3")
        vol_id = vol["VolumeId"]

        s3.create_bucket(Bucket="finops-test-bucket")
        s3.put_object(Bucket="finops-test-bucket", Key="logs/a.txt", Body=b"A" * 2048)
        s3.put_bucket_versioning(Bucket="finops-test-bucket", VersioningConfiguration={"Status": "Enabled"})

        s3.create_bucket(Bucket="finops-trail-bucket")
        ct.create_trail(Name="finops-trail", S3BucketName="finops-trail-bucket")
        ct.start_logging(Name="finops-trail")

        iam.create_user(UserName="finops-auditor")

        store = StateStore(db_path=":memory:")
        store.log_telemetry_event("DescribeInstances", "ec2", "finops-auditor", "IN", "baseline", "Simulator")

        inv = collect_resource_inventory(clients=clients, state_store=store)
        store.close()

        assert inv["account_id"] == "123456789012"
        assert inv["service_availability"]["sts"]["status"] == "available"
        assert inv["service_availability"]["ec2"]["status"] == "available"
        assert inv["service_availability"]["ebs"]["status"] == "available"
        assert inv["service_availability"]["s3"]["status"] == "available"
        assert inv["service_availability"]["iam"]["status"] == "available"
        assert inv["cloudtrail_summary"]["telemetry_event_count"] == 1

        ids = {(r["service"], r["resource_id"]) for r in inv["resources"]}
        assert ("ec2", inst_id) in ids
        assert ("ebs", vol_id) in ids
        assert ("s3", "finops-test-bucket") in ids
        assert ("iam", "user/finops-auditor") in ids
        assert ("cloudtrail", "finops-trail") in ids

        s3_res = next(r for r in inv["resources"] if r["service"] == "s3" and r["resource_id"] == "finops-test-bucket")
        assert s3_res["metadata"]["total_bytes"] == 2048
        assert s3_res["metadata"]["versioning"] == "Enabled"
        assert s3_res["metadata"]["has_lifecycle"] is False


def test_ec2_ebs_s3_cost_estimation_and_regional_differences():
    catalog = load_pricing_catalog()

    # Running EC2 in us-east-1 vs eu-west-1
    ec2_us = {
        "resource_id": "i-us1", "service": "ec2", "resource_type": "t3.large",
        "region": "us-east-1", "state": "running", "metadata": {}, "tags": {},
    }
    ec2_eu = {
        "resource_id": "i-eu1", "service": "ec2", "resource_type": "t3.large",
        "region": "eu-west-1", "state": "running", "metadata": {}, "tags": {},
    }
    est_us = estimate_resource_cost(ec2_us, catalog, operating_hours_per_month=730)
    est_eu = estimate_resource_cost(ec2_eu, catalog, operating_hours_per_month=730)
    assert est_us["estimated_monthly_cost"] == pytest.approx(0.0832 * 730, rel=1e-4)
    assert est_eu["estimated_monthly_cost"] == pytest.approx(0.0912 * 730, rel=1e-4)
    assert est_eu["estimated_monthly_cost"] > est_us["estimated_monthly_cost"]
    assert est_us["is_assumption_based"] is True
    assert est_us["cost_status"] == "Estimate based on assumptions"
    assert est_us["observed_properties"]["utilization_metrics"] == "unavailable"
    assert est_us["estimated_usage"]["assumed_operating_hours_per_month"] == 730.0

    # Business hours assumption changes EC2 estimate transparently
    est_biz = estimate_resource_cost(ec2_us, catalog, operating_hours_per_month=160)
    assert est_biz["estimated_monthly_cost"] == pytest.approx(0.0832 * 160, rel=1e-4)

    # Stopped EC2 incurs $0 compute
    ec2_stopped = {
        "resource_id": "i-stop", "service": "ec2", "resource_type": "t3.large",
        "region": "us-east-1", "state": "stopped", "metadata": {}, "tags": {},
    }
    est_stop = estimate_resource_cost(ec2_stopped, catalog)
    assert est_stop["estimated_monthly_cost"] == 0.0
    assert est_stop["cost_status"] == "Zero usage observed"
    assert est_stop["estimation_basis"] == "stopped_no_compute"

    # EBS estimation
    ebs_vol = {
        "resource_id": "vol-1", "service": "ebs", "resource_type": "gp3",
        "region": "us-east-1", "state": "available", "metadata": {"size_gb": 100}, "tags": {},
    }
    est_ebs = estimate_resource_cost(ebs_vol, catalog)
    assert est_ebs["estimated_monthly_cost"] == pytest.approx(8.0, rel=1e-4)
    assert est_ebs["cost_status"] == "Calculated"

    # S3 estimation (1 GiB observed) and zero usage S3
    s3_res = {
        "resource_id": "bkt-1", "service": "s3", "resource_type": "STANDARD",
        "region": "us-east-1", "state": "active",
        "metadata": {"total_bytes": 1024 ** 3, "storage_unknown": False, "storage_classes_bytes": {"STANDARD": 1024 ** 3}},
        "tags": {},
    }
    est_s3 = estimate_resource_cost(s3_res, catalog)
    assert est_s3["estimated_monthly_cost"] == pytest.approx(0.023, rel=1e-4)
    assert est_s3["cost_status"] == "Calculated"

    s3_empty = {
        "resource_id": "bkt-0", "service": "s3", "resource_type": "STANDARD",
        "region": "us-east-1", "state": "active",
        "metadata": {"total_bytes": 0, "storage_unknown": False, "storage_classes_bytes": {}},
        "tags": {},
    }
    est_s3_0 = estimate_resource_cost(s3_empty, catalog)
    assert est_s3_0["estimated_monthly_cost"] == 0.0
    assert est_s3_0["cost_status"] == "Zero usage observed"

    # IAM and CloudTrail direct charge treatment
    iam_res = {"resource_id": "user/u1", "service": "iam", "resource_type": "identity", "region": "global", "state": "active", "metadata": {}, "tags": {}}
    ct_res = {"resource_id": "main-trail", "service": "cloudtrail", "resource_type": "management-trail", "region": "us-east-1", "state": "logging", "metadata": {"is_logging": True}, "tags": {}}
    assert estimate_resource_cost(iam_res, catalog)["estimated_monthly_cost"] == 0.0
    assert estimate_resource_cost(iam_res, catalog)["cost_status"] == "Calculated"
    assert estimate_resource_cost(ct_res, catalog)["estimated_monthly_cost"] == 0.0
    assert estimate_resource_cost(ct_res, catalog)["cost_status"] == "Calculated"

    # CloudTrail in unsupported region must NOT silently return $0.00
    ct_missing = {"resource_id": "t-unk", "service": "cloudtrail", "resource_type": "management-trail", "region": "af-south-1", "state": "logging", "metadata": {"is_logging": True}, "tags": {}}
    ct_miss_est = estimate_resource_cost(ct_missing, catalog)
    assert ct_miss_est["estimated_monthly_cost"] is None
    assert ct_miss_est["cost_status"] == "Pricing unavailable"


def test_missing_metadata_and_missing_pricing_not_fabricated():
    catalog = load_pricing_catalog()

    # S3 with unknown storage must NOT fabricate cost
    s3_unknown = {
        "resource_id": "bkt-unk", "service": "s3", "resource_type": "STANDARD",
        "region": "us-east-1", "state": "active",
        "metadata": {"total_bytes": None, "storage_unknown": True}, "tags": {},
    }
    est_s3_unk = estimate_resource_cost(s3_unknown, catalog)
    assert est_s3_unk["estimated_monthly_cost"] is None
    assert est_s3_unk["cost_status"] == "Resource unavailable"
    assert est_s3_unk["estimation_basis"] == "storage_unknown"

    # EBS missing size_gb
    ebs_missing = {
        "resource_id": "vol-unk", "service": "ebs", "resource_type": "gp3",
        "region": "us-east-1", "state": "available", "metadata": {}, "tags": {},
    }
    est_ebs_m = estimate_resource_cost(ebs_missing, catalog)
    assert est_ebs_m["estimated_monthly_cost"] is None
    assert est_ebs_m["cost_status"] == "Resource unavailable"

    # Unsupported instance type / region -> missing_pricing
    ec2_missing_price = {
        "resource_id": "i-x", "service": "ec2", "resource_type": "p5.48xlarge",
        "region": "af-south-1", "state": "running", "metadata": {}, "tags": {},
    }
    est_mp = estimate_resource_cost(ec2_missing_price, catalog)
    assert est_mp["pricing_available"] is False
    assert est_mp["estimated_monthly_cost"] is None
    assert est_mp["cost_status"] == "Pricing unavailable"
    assert est_mp["estimation_basis"] == "missing_pricing"


def test_aggregation_savings_formula_and_optimization_findings():
    catalog = load_pricing_catalog()
    inv = {
        "environment": "Moto Simulated Cloud",
        "account_id": "123456789012",
        "simulator_available": True,
        "regions_scanned": ["us-east-1"],
        "cloudtrail_summary": {"telemetry_event_count": 0, "note": "Missing CloudTrail events do not prove a resource is idle."},
        "resources": [
            {
                "resource_id": "i-oversized", "name": "oversized", "service": "ec2",
                "resource_type": "m5.xlarge", "region": "us-east-1", "availability_zone": "us-east-1a",
                "state": "running", "tags": {"Owner": "platform"},
                "metadata": {"attached_volume_ids": []},
            },
            {
                "resource_id": "i-stopped", "name": "stopped", "service": "ec2",
                "resource_type": "t3.micro", "region": "us-east-1", "availability_zone": "us-east-1a",
                "state": "stopped", "tags": {"Owner": "platform"},
                "metadata": {"attached_volume_ids": ["vol-attached"]},
            },
            {
                "resource_id": "vol-attached", "name": "vol-attached", "service": "ebs",
                "resource_type": "gp3", "region": "us-east-1", "availability_zone": "us-east-1a",
                "state": "in-use", "tags": {"Owner": "platform"},
                "metadata": {"size_gb": 100, "attachments": [{"instance_id": "i-stopped"}]},
            },
            {
                "resource_id": "vol-orphan", "name": "vol-orphan", "service": "ebs",
                "resource_type": "gp2", "region": "us-east-1", "availability_zone": "us-east-1a",
                "state": "available", "tags": {},
                "metadata": {"size_gb": 50, "attachments": []},
            },
            {
                "resource_id": "data-bkt", "name": "data-bkt", "service": "s3",
                "resource_type": "STANDARD", "region": "us-east-1", "availability_zone": "regional",
                "state": "active", "tags": {},
                "metadata": {
                    "total_bytes": 10 * (1024 ** 3),
                    "storage_unknown": False,
                    "storage_classes_bytes": {"STANDARD": 10 * (1024 ** 3)},
                    "versioning": "Enabled",
                    "has_lifecycle": False,
                    "lifecycle_status": "None",
                },
            },
        ],
    }

    est = estimate_infrastructure_costs(inv, catalog=catalog, operating_hours_per_month=730)
    opt = analyze_cost_optimizations(inv, est, catalog=catalog)

    # Verify cost aggregation percentages sum close to 100
    pct_sum = sum(s["percentage_of_total"] for s in est["service_breakdown"])
    assert pct_sum == pytest.approx(100.0, abs=0.1)

    comp = opt["cost_comparison"]
    assert comp["optimized_estimated_monthly_cost"] == pytest.approx(
        comp["current_estimated_monthly_cost"] - comp["potential_monthly_savings"], abs=1e-4
    )
    expected_pct = (comp["potential_monthly_savings"] / comp["current_estimated_monthly_cost"]) * 100.0
    assert comp["percentage_reduction"] == pytest.approx(expected_pct, abs=0.02)

    finding_ids = [f["id"] for f in opt["findings"]]
    assert "FIN-EBS-UNATTACHED-vol-orphan" in finding_ids
    assert "FIN-EC2-STOPPED-EBS-i-stopped" in finding_ids
    assert "FIN-EC2-OVERSIZED-i-oversized" in finding_ids
    assert "FIN-S3-LIFECYCLE-data-bkt" in finding_ids
    assert "FIN-S3-VERSION-RETENTION-data-bkt" in finding_ids
    assert "FIN-TAG-MISSING-EBS-vol-orphan" in finding_ids
    assert "FIN-TAG-MISSING-S3-data-bkt" in finding_ids

    # Check confirmed vs inferred distinction and explicit savings statuses
    oversized = next(f for f in opt["findings"] if f["id"] == "FIN-EC2-OVERSIZED-i-oversized")
    orphan = next(f for f in opt["findings"] if f["id"] == "FIN-EBS-UNATTACHED-vol-orphan")
    missing_tag = next(f for f in opt["findings"] if f["id"] == "FIN-TAG-MISSING-S3-data-bkt")
    assert oversized["classification"] == "inferred"
    assert oversized["savings_status"] == "Estimate based on assumptions"
    assert orphan["classification"] == "confirmed"
    assert orphan["savings_status"] == "Calculated"
    assert missing_tag["estimated_monthly_savings"] == 0.0
    assert missing_tag["savings_status"] == "Governance only"
    assert "Missing CloudTrail events do not prove a resource is idle" in opt["cloudtrail_note"]


def test_empty_and_partial_datasets_and_report_persistence():
    store = StateStore(db_path=":memory:")
    soc = SOCStore(state_store=store)
    soc._remediations.clear()

    # Empty dataset (offline simulator / zero resources)
    empty_clients = {
        "ec2": MagicMock(describe_instances=MagicMock(return_value={"Reservations": []}), describe_volumes=MagicMock(return_value={"Volumes": []})),
        "s3": MagicMock(list_buckets=MagicMock(return_value={"Buckets": []})),
        "iam": MagicMock(list_users=MagicMock(return_value={"Users": []}), list_roles=MagicMock(return_value={"Roles": []}), list_policies=MagicMock(return_value={"Policies": []})),
        "cloudtrail": MagicMock(describe_trails=MagicMock(return_value={"trailList": []})),
        "sts": MagicMock(get_caller_identity=MagicMock(return_value={"Account": "123456789012"})),
    }

    rpt_empty = generate_cost_report(clients=empty_clients, state_store=store, soc_store=soc, persist=True)
    assert rpt_empty["cost_overview"]["estimated_monthly_cost"] == 0.0
    assert rpt_empty["cost_overview"]["analyzed_resources"] == 0
    assert rpt_empty["cost_comparison"]["percentage_reduction"] == 0.0
    assert "1. REPORT INFORMATION" in rpt_empty["narrative_text"]
    assert "11. METHODOLOGY AND LIMITATIONS" in rpt_empty["narrative_text"]
    # Ensure no filesystem paths leak into narrative text
    assert "c:\\" not in rpt_empty["narrative_text"].lower()
    assert "/backend/" not in rpt_empty["narrative_text"].lower()

    # Partial dataset (e.g., EC2/CloudTrail fail, S3 succeeds)
    partial_clients = {
        "ec2": MagicMock(describe_instances=MagicMock(side_effect=RuntimeError("offline")), describe_volumes=MagicMock(side_effect=RuntimeError("offline"))),
        "s3": MagicMock(
            list_buckets=MagicMock(return_value={"Buckets": [{"Name": "partial-bkt"}]}),
            get_bucket_location=MagicMock(return_value={"LocationConstraint": None}),
            list_objects_v2=MagicMock(return_value={"Contents": [], "IsTruncated": False}),
            get_bucket_versioning=MagicMock(return_value={}),
            get_bucket_lifecycle_configuration=MagicMock(side_effect=Exception("NoSuchLifecycleConfiguration")),
            get_bucket_tagging=MagicMock(side_effect=Exception("NoSuchTagSet")),
            get_public_access_block=MagicMock(side_effect=Exception("NoSuchPublicAccessBlock")),
        ),
        "iam": MagicMock(list_users=MagicMock(side_effect=RuntimeError("offline"))),
        "cloudtrail": MagicMock(describe_trails=MagicMock(side_effect=RuntimeError("offline"))),
        "sts": MagicMock(get_caller_identity=MagicMock(return_value={"Account": "123456789012"})),
    }

    rpt_partial = generate_cost_report(clients=partial_clients, state_store=store, soc_store=soc, persist=True)
    assert rpt_partial["cost_overview"]["analyzed_resources"] == 1
    assert rpt_partial["methodology_and_limitations"]["data_availability"]["ec2"]["status"] == "unavailable"
    assert rpt_partial["methodology_and_limitations"]["data_availability"]["s3"]["status"] == "available"

    # Historical report retrieval remains intact even after inventory changes
    history = store.list_cost_reports()
    assert len(history) == 2
    fetched = store.get_cost_report(rpt_empty["report_information"]["report_id"])
    assert fetched is not None
    assert fetched["cost_overview"]["analyzed_resources"] == 0
    store.close()


def test_remediation_execution_verification_and_live_guard(monkeypatch):
    with mock_aws():
        clients = _make_mock_clients("us-east-1")
        ec2 = clients["ec2"]
        s3 = clients["s3"]

        vol_id = ec2.create_volume(AvailabilityZone="us-east-1a", Size=20, VolumeType="gp3")["VolumeId"]
        s3.create_bucket(Bucket="rem-test-bkt")

        store = StateStore(db_path=":memory:")
        soc = SOCStore(state_store=store)
        soc._remediations.clear()

        inv = collect_resource_inventory(clients=clients, state_store=store)
        est = estimate_infrastructure_costs(inv)
        opt = analyze_cost_optimizations(inv, est)

        ebs_finding = next(f for f in opt["findings"] if f["id"] == f"FIN-EBS-UNATTACHED-{vol_id}")
        s3_finding = next(f for f in opt["findings"] if f["id"] == "FIN-S3-LIFECYCLE-rem-test-bkt")

        task_ebs = create_cost_remediation_task(ebs_finding, soc, store)
        task_s3 = create_cost_remediation_task(s3_finding, soc, store)

        # Before approval, summary shows 2 pending and $0 realized savings
        pre_sum = summarize_cost_remediations(soc)
        assert pre_sum["cost_tasks_summary"]["pending"] == 2
        assert pre_sum["realized_monthly_savings"] == 0.0

        # Live AWS guard blocks cost remediation execution
        monkeypatch.setenv("CG_LIVE_AWS", "1")
        exec_ebs, _ = build_cost_executor_and_verifier(task_ebs, clients=clients)
        with pytest.raises(RuntimeError, match="Live AWS mode"):
            exec_ebs()
        monkeypatch.setenv("CG_LIVE_AWS", "0")

        # Approve and execute both against Moto
        soc.approve_remediation_task(task_ebs.id, user="FinOps Lead")
        soc.approve_remediation_task(task_s3.id, user="FinOps Lead")

        exec_ebs, ver_ebs = build_cost_executor_and_verifier(task_ebs, clients=clients)
        exec_s3, ver_s3 = build_cost_executor_and_verifier(task_s3, clients=clients)

        res_ebs = soc.execute_and_verify_remediation(task_ebs.id, executor_fn=exec_ebs, verifier_fn=ver_ebs, user="FinOps Lead")
        res_s3 = soc.execute_and_verify_remediation(task_s3.id, executor_fn=exec_s3, verifier_fn=ver_s3, user="FinOps Lead")

        assert res_ebs.status == RemediationStatus.VERIFIED
        assert res_ebs.verification_state == VerificationState.PASS
        assert res_s3.status == RemediationStatus.VERIFIED
        assert res_s3.verification_state == VerificationState.PASS

        post_sum = summarize_cost_remediations(soc)
        assert post_sum["cost_tasks_summary"]["independently_verified"] == 2
        assert post_sum["realized_monthly_savings"] == pytest.approx(20 * 0.08, rel=1e-4)
        store.close()


def test_simulator_endpoint_isolation_respected():
    with pytest.raises(ValueError, match="Unsafe AWS endpoint"):
        validate_endpoint_url("https://ec2.us-east-1.amazonaws.com")
    client = get_aws_client("ec2", region_name="us-west-2")
    assert "127.0.0.1:5000" in client._endpoint.host


def test_finops_demo_scenario_idempotency_preservation_and_live_guard(monkeypatch):
    from backend.cost.demo_scenario import (
        inspect_finops_demo_scenario,
        load_finops_demo_scenario,
        reset_finops_demo_scenario,
    )

    with mock_aws():
        cli = _make_mock_clients("us-east-1")
        # Pre-existing unrelated ThreatGuard resources
        cli["s3"].create_bucket(Bucket="student-records-demo")
        cli["iam"].create_user(UserName="intern-dev")

        store = StateStore(db_path=":memory:")
        soc = SOCStore(state_store=store)

        # Live AWS guard blocks load and reset
        monkeypatch.setenv("CG_LIVE_AWS", "1")
        with pytest.raises(PermissionError, match="Live AWS mode"):
            load_finops_demo_scenario(clients=cli, state_store=store)
        with pytest.raises(PermissionError, match="Live AWS mode"):
            reset_finops_demo_scenario(clients=cli, state_store=store, soc_store=soc)
        monkeypatch.setenv("CG_LIVE_AWS", "0")

        # Load FinOps demo scenario
        s1 = load_finops_demo_scenario(clients=cli, state_store=store)
        assert s1["loaded"] is True
        assert len(s1["ec2_instances"]) == 2
        assert len(s1["ebs_volumes"]) == 4
        assert len(s1["s3_buckets"]) == 2
        assert "intern-dev" in s1["reused_identities"]

        # Idempotent second call must not duplicate resources
        s2 = load_finops_demo_scenario(clients=cli, state_store=store)
        assert len(s2["ec2_instances"]) == 2
        assert len(s2["ebs_volumes"]) == 4
        assert len(s2["s3_buckets"]) == 2

        # Cost estimation on loaded scenario returns realistic non-zero costs
        inv = collect_resource_inventory(clients=cli, state_store=store)
        est = estimate_infrastructure_costs(inv)
        opt = analyze_cost_optimizations(inv, est)
        assert est["total_monthly_cost"] > 70.0
        assert opt["cost_comparison"]["potential_monthly_savings"] > 35.0

        # Reset removes ONLY demo resources and preserves unrelated bucket/user
        s3 = reset_finops_demo_scenario(clients=cli, state_store=store, soc_store=soc)
        assert s3["loaded"] is False
        assert len(s3["ec2_instances"]) == 0
        assert len(s3["ebs_volumes"]) == 0
        assert len(s3["s3_buckets"]) == 0

        remaining_buckets = [b["Name"] for b in cli["s3"].list_buckets()["Buckets"]]
        remaining_users = [u["UserName"] for u in cli["iam"].list_users()["Users"]]
        assert "student-records-demo" in remaining_buckets
        assert "intern-dev" in remaining_users

        # Inventory after reset excludes terminated EC2 ghosts
        inv_after = collect_resource_inventory(clients=cli, state_store=store)
        assert all(r["service"] != "ec2" for r in inv_after["resources"])
        assert inspect_finops_demo_scenario(clients=cli)["loaded"] is False
        store.close()
