"""Unit tests for AWS Safety Guard:
- Prevention of accidental live AWS resource mutation
- Explicit authorization checks
- Dry-run simulation behavior
- Account ID masking in live mode
"""
from unittest.mock import MagicMock
import pytest
from botocore.exceptions import EndpointConnectionError

from backend.aws_guard import (
    is_dry_run,
    is_live_aws,
    is_live_setup_allowed,
    resolve_account_id,
    safe_execute_remediation,
    safe_setup,
)


def test_environment_flags(monkeypatch):
    monkeypatch.setenv("CG_LIVE_AWS", "1")
    monkeypatch.setenv("CG_DRY_RUN", "1")
    monkeypatch.setenv("CG_ALLOW_LIVE_SETUP", "1")
    assert is_live_aws() is True
    assert is_dry_run() is True
    assert is_live_setup_allowed() is True

    monkeypatch.setenv("CG_LIVE_AWS", "0")
    monkeypatch.setenv("CG_DRY_RUN", "0")
    monkeypatch.setenv("CG_ALLOW_LIVE_SETUP", "0")
    assert is_live_aws() is False
    assert is_dry_run() is False
    assert is_live_setup_allowed() is False


def test_safe_setup_blocks_live_aws_by_default(monkeypatch):
    """Verify that in Live AWS mode, safe_setup() strictly refuses to create resources
    unless CG_ALLOW_LIVE_SETUP=1 is set."""
    monkeypatch.setenv("CG_LIVE_AWS", "1")
    monkeypatch.delenv("CG_ALLOW_LIVE_SETUP", raising=False)

    s3_mock = MagicMock()
    ct_mock = MagicMock()
    ec2_mock = MagicMock()
    iam_mock = MagicMock()

    success, res_ids, msg = safe_setup(
        s3_mock, ct_mock, ec2_mock, iam_mock,
        "test-bucket", "test-trail", "test-user",
        {"BlockPublicAcls": True}, lambda cidr: []
    )

    assert success is False
    assert res_ids == {}
    assert "Live AWS mode" in msg
    assert "SKIPPED" in msg

    # Ensure none of the creation APIs were called
    s3_mock.create_bucket.assert_not_called()
    ct_mock.create_trail.assert_not_called()
    ec2_mock.create_security_group.assert_not_called()
    iam_mock.create_user.assert_not_called()


def test_safe_setup_executes_when_authorized_in_live(monkeypatch):
    monkeypatch.setenv("CG_LIVE_AWS", "1")
    monkeypatch.setenv("CG_ALLOW_LIVE_SETUP", "1")

    s3_mock = MagicMock()
    ct_mock = MagicMock()
    ec2_mock = MagicMock()
    iam_mock = MagicMock()

    ec2_mock.create_security_group.return_value = {"GroupId": "sg-12345"}
    iam_mock.create_access_key.return_value = {"AccessKey": {"AccessKeyId": "AKIA123"}}

    success, res_ids, msg = safe_setup(
        s3_mock, ct_mock, ec2_mock, iam_mock,
        "test-bucket", "test-trail", "test-user",
        {"BlockPublicAcls": True}, lambda cidr: []
    )

    assert success is True
    assert res_ids["sg"] == "sg-12345"
    assert res_ids["key"] == "AKIA123"
    s3_mock.create_bucket.assert_called()


def test_safe_setup_simulator_mode(monkeypatch):
    monkeypatch.setenv("CG_LIVE_AWS", "0")

    s3_mock = MagicMock()
    ct_mock = MagicMock()
    ec2_mock = MagicMock()
    iam_mock = MagicMock()

    ec2_mock.create_security_group.return_value = {"GroupId": "sg-sim"}
    iam_mock.create_access_key.return_value = {"AccessKey": {"AccessKeyId": "AKIA-SIM"}}

    success, res_ids, msg = safe_setup(
        s3_mock, ct_mock, ec2_mock, iam_mock,
        "test-bucket", "test-trail", "test-user",
        {"BlockPublicAcls": True}, lambda cidr: []
    )

    assert success is True
    assert res_ids["sg"] == "sg-sim"
    assert res_ids["key"] == "AKIA-SIM"


def test_safe_setup_handles_moto_connection_error(monkeypatch):
    monkeypatch.setenv("CG_LIVE_AWS", "0")

    s3_mock = MagicMock()
    s3_mock.create_bucket.side_effect = EndpointConnectionError(endpoint_url="http://127.0.0.1:5000")

    success, res_ids, msg = safe_setup(
        s3_mock, MagicMock(), MagicMock(), MagicMock(),
        "test-bucket", "test-trail", "test-user",
        {"BlockPublicAcls": True}, lambda cidr: []
    )

    assert success is False
    assert "Cannot connect to Moto simulator" in msg


def test_safe_execute_remediation_dry_run():
    fix_called = False

    def dummy_fix():
        nonlocal fix_called
        fix_called = True

    # When dry-run is True
    ok, msg = safe_execute_remediation("Enable S3 Block", dummy_fix, dry_run=True)
    assert ok is True
    assert "DRY-RUN" in msg
    assert fix_called is False

    # When dry-run is False
    ok, msg = safe_execute_remediation("Enable S3 Block", dummy_fix, dry_run=False)
    assert ok is True
    assert fix_called is True


def test_resolve_account_id_masks_in_live_mode(monkeypatch):
    sts_mock = MagicMock()
    sts_mock.get_caller_identity.return_value = {"Account": "123456789012"}

    # Live mode -> masked
    monkeypatch.setenv("CG_LIVE_AWS", "1")
    live_id = resolve_account_id(sts_mock)
    assert live_id == "1234****9012"

    # Simulator mode -> unmasked
    monkeypatch.setenv("CG_LIVE_AWS", "0")
    sim_id = resolve_account_id(sts_mock)
    assert sim_id == "123456789012"
