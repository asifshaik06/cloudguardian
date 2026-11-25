"""Integration tests for ThreatGuard Cost Intelligence & Cost Optimization REST APIs."""
import boto3
from moto import mock_aws
import pytest

from app import app as flask_app, context as app_context, soc_store
from backend.security import AUTH_HEADER, CSRF_HEADER, get_active_api_key, session_store
from backend.state import StateStore


@pytest.fixture
def client(tmp_path):
    flask_app.config["TESTING"] = True
    session_store.clear()
    orig_store = app_context.get("state_store")
    orig_rems = dict(soc_store._remediations)
    orig_rem_seq = soc_store._remediation_seq
    test_store = StateStore(db_path=str(tmp_path / "test_cost.db"))
    app_context["state_store"] = test_store

    with flask_app.test_client() as c:
        yield c

    app_context["state_store"] = orig_store
    test_store.close()
    soc_store._remediations.clear()
    soc_store._remediations.update(orig_rems)
    soc_store._remediation_seq = orig_rem_seq
    flask_app.config.pop("COST_CLIENTS", None)
    session_store.clear()


@pytest.fixture
def auth_headers():
    return {AUTH_HEADER: get_active_api_key()}


def _seed_moto_env():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    iam = boto3.client("iam", region_name="us-east-1")
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    sts = boto3.client("sts", region_name="us-east-1")

    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t3.large")
    vol_id = ec2.create_volume(AvailabilityZone="us-east-1a", Size=40, VolumeType="gp3")["VolumeId"]
    s3.create_bucket(Bucket="api-cost-data")
    s3.put_object(Bucket="api-cost-data", Key="obj.bin", Body=b"x" * 4096)
    s3.create_bucket(Bucket="api-cost-trail")
    ct.create_trail(Name="api-trail", S3BucketName="api-cost-trail")
    ct.start_logging(Name="api-trail")
    iam.create_user(UserName="cost-user")
    return {"ec2": ec2, "s3": s3, "iam": iam, "cloudtrail": ct, "sts": sts}, vol_id


def test_cost_read_endpoints_public_access(client):
    with mock_aws():
        clients, _ = _seed_moto_env()
        flask_app.config["COST_CLIENTS"] = clients

        r_ov = client.get("/api/cost/overview")
        assert r_ov.status_code == 200
        ov = r_ov.get_json()
        assert ov["cost_overview"]["estimated_monthly_cost"] > 0
        assert ov["cost_overview"]["analyzed_resources"] >= 4
        assert len(ov["service_breakdown"]) >= 3
        assert len(ov["findings"]) >= 2

        r_pr = client.get("/api/cost/pricing")
        assert r_pr.status_code == 200
        assert r_pr.get_json()["dataset_version"] == "2026.11-aws-finops-v1"

        r_rpts = client.get("/api/cost/reports")
        assert r_rpts.status_code == 200
        assert "reports" in r_rpts.get_json()


def test_cost_overview_validation_errors(client):
    assert client.get("/api/cost/overview?service=invalidsvc").status_code == 400
    assert client.get("/api/cost/overview?period=weekly").status_code == 400
    assert client.get("/api/cost/overview?hours=9999").status_code == 400


def test_cost_write_endpoints_require_auth_and_csrf(client):
    # Unauthenticated POSTs rejected with 401
    assert client.post("/api/cost/reports/generate", json={}).status_code == 401
    assert client.post("/api/cost/findings/FIN-1/remediate", json={}).status_code == 401

    # Session login without CSRF rejected with 403
    login = client.post("/api/auth/login", json={"key": get_active_api_key()})
    assert login.status_code == 200
    csrf = login.get_json()["csrf_token"]
    assert client.post("/api/cost/reports/generate", json={}).status_code == 403

    # With valid CSRF succeeds
    with mock_aws():
        clients, _ = _seed_moto_env()
        flask_app.config["COST_CLIENTS"] = clients
        ok_resp = client.post(
            "/api/cost/reports/generate",
            headers={CSRF_HEADER: csrf},
            json={"reporting_period": "quarterly"},
        )
        assert ok_resp.status_code == 201
        assert ok_resp.get_json()["report"]["report_information"]["reporting_period"] == "quarterly"


def test_cost_report_generation_history_and_remediation_hitl_workflow(client, auth_headers):
    with mock_aws():
        clients, vol_id = _seed_moto_env()
        flask_app.config["COST_CLIENTS"] = clients

        # 1. Check dashboard overview matches newly generated report calculations
        ov_resp = client.get("/api/cost/overview?period=monthly&hours=730")
        assert ov_resp.status_code == 200
        ov_data = ov_resp.get_json()

        # Generate report via API
        gen = client.post(
            "/api/cost/reports/generate",
            headers=auth_headers,
            json={"reporting_period": "monthly", "operating_hours": 730},
        )
        assert gen.status_code == 201
        rpt_id = gen.get_json()["report_id"]
        rpt = gen.get_json()["report"]
        assert rpt["cost_overview"]["estimated_monthly_cost"] == ov_data["cost_overview"]["estimated_monthly_cost"]
        assert rpt["before_after_cost_comparison"]["potential_monthly_savings"] == ov_data["cost_comparison"]["potential_monthly_savings"]
        assert rpt["report_information"]["operating_hours_per_month"] == 730.0
        for key in (
            "report_information",
            "executive_summary",
            "cost_overview",
            "service_wise_cost_analysis",
            "resource_level_analysis",
            "cost_optimization_findings",
            "optimization_recommendations",
            "before_after_cost_comparison",
            "remediation_summary",
            "final_assessment",
            "methodology_and_limitations",
        ):
            assert key in rpt

        # 2. Historical report persists even if inventory changes
        clients["ec2"].delete_volume(VolumeId=vol_id)
        hist_detail = client.get(f"/api/cost/reports/{rpt_id}")
        assert hist_detail.status_code == 200
        assert any(r["resource_id"] == vol_id for r in hist_detail.get_json()["resource_level_analysis"])

        # 3. Stage S3 lifecycle remediation and verify HITL approval enforcement
        finding_id = "FIN-S3-LIFECYCLE-api-cost-data"
        stage = client.post(f"/api/cost/findings/{finding_id}/remediate", headers=auth_headers, json={})
        assert stage.status_code == 201
        rem_id = stage.get_json()["remediation"]["id"]

        # Applying BEFORE approval must be rejected (409)
        unapproved_apply = client.post(f"/api/remediations/{rem_id}/apply", headers=auth_headers, json={})
        assert unapproved_apply.status_code == 409

        # Approve then Apply -> Verified PASS against Moto
        appr = client.post(f"/api/remediations/{rem_id}/approve", headers=auth_headers, json={"user": "FinOpsAdmin"})
        assert appr.status_code == 200
        assert appr.get_json()["remediation"]["status"] == "Approved"

        appl = client.post(f"/api/remediations/{rem_id}/apply", headers=auth_headers, json={"user": "FinOpsAdmin"})
        assert appl.status_code == 200
        rem_res = appl.get_json()["remediation"]
        assert rem_res["status"] == "Verified"
        assert rem_res["verification_state"] == "PASS"

        # Verify audit trail remained intact
        audit_resp = client.get("/api/audit")
        assert audit_resp.status_code == 200
        assert audit_resp.get_json()["chain_ok"] is True


def test_dashboard_cost_intelligence_routes_present_and_no_export_endpoints(client):
    resp_html = client.get("/")
    assert resp_html.status_code == 200
    assert b"Cost Intelligence" in resp_html.data
    assert b"Optimization Reports" in resp_html.data
    assert b"cost-reports-layout" in resp_html.data
    assert b"cost-history-panel" in resp_html.data
    assert b"cost-report-detail" in resp_html.data
    assert b"cost-tbl" in resp_html.data

    # Ensure no PDF/CSV/JSON download endpoints exist for cost reports
    assert client.get("/api/cost/reports/export").status_code == 404
    assert client.get("/api/cost/reports/pdf").status_code == 404
    assert client.get("/api/cost/reports/csv").status_code == 404


def test_finops_demo_scenario_api_workflow_and_auth(client, auth_headers):
    # Unauthenticated load/reset rejected with 401
    assert client.post("/api/cost/demo-scenario/load", json={}).status_code == 401
    assert client.post("/api/cost/demo-scenario/reset", json={}).status_code == 401

    with mock_aws():
        clients = {
            "ec2": boto3.client("ec2", region_name="us-east-1"),
            "s3": boto3.client("s3", region_name="us-east-1"),
            "iam": boto3.client("iam", region_name="us-east-1"),
            "cloudtrail": boto3.client("cloudtrail", region_name="us-east-1"),
            "sts": boto3.client("sts", region_name="us-east-1"),
        }
        clients["s3"].create_bucket(Bucket="student-records-demo")
        flask_app.config["COST_CLIENTS"] = clients

        # Status initially unloaded
        st0 = client.get("/api/cost/demo-scenario")
        assert st0.status_code == 200
        assert st0.get_json()["loaded"] is False

        # Load scenario
        ld = client.post("/api/cost/demo-scenario/load", headers=auth_headers, json={})
        assert ld.status_code == 201
        ld_data = ld.get_json()
        assert ld_data["loaded"] is True
        assert len(ld_data["ec2_instances"]) == 2
        assert len(ld_data["ebs_volumes"]) == 4
        assert len(ld_data["s3_buckets"]) == 2

        # Overview reflects loaded scenario costs
        ov = client.get("/api/cost/overview").get_json()
        assert ov["cost_overview"]["estimated_monthly_cost"] > 70.0
        assert ov["cost_overview"]["potential_monthly_savings"] > 35.0

        # Reset scenario cleans up demo resources without touching student-records-demo
        rs = client.post("/api/cost/demo-scenario/reset", headers=auth_headers, json={})
        assert rs.status_code == 200
        assert rs.get_json()["loaded"] is False
        assert "student-records-demo" in [b["Name"] for b in clients["s3"].list_buckets()["Buckets"]]
