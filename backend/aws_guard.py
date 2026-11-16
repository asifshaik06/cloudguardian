"""AWS Safety Guard and Client Management for CloudGuardian.

Provides:
- Guarded boto3 client factory for Moto vs Live AWS.
- Safe startup initialization preventing unprompted modification of live AWS resources.
- Dry-run execution controller for safe auditing and testing.
- Account ID masking and safety validation.
"""
import logging
import os
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

logger = logging.getLogger("cloudguardian.aws_guard")

# Authorized local emulator hostnames in simulator mode
ALLOWED_SIMULATOR_HOSTS = {
    "127.0.0.1",
    "localhost",
    "::1",
    "0.0.0.0",
}


def validate_endpoint_url(endpoint_url: str) -> str:
    """Validate that endpoint URL points to an authorized local emulator in simulator mode.

    Raises ValueError if the endpoint points to a public or remote AWS service
    without CG_LIVE_AWS=1.
    """
    if not endpoint_url:
        return "http://127.0.0.1:5000"

    parsed = urlparse(endpoint_url)
    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"[SECURITY GUARD] Invalid endpoint URL scheme '{parsed.scheme}': must be http or https."
        )

    hostname = (parsed.hostname or "").lower()

    # Explicitly block any connection to real AWS domains in simulator mode
    if "amazonaws.com" in hostname or hostname.endswith(".aws"):
        raise ValueError(
            f"[SECURITY GUARD] Unsafe AWS endpoint detected in simulator mode: '{endpoint_url}'. "
            "Simulator traffic cannot be routed to public AWS infrastructure without CG_LIVE_AWS=1."
        )

    # In simulator mode, hostname must be a recognized loopback or local emulator
    if hostname not in ALLOWED_SIMULATOR_HOSTS and not hostname.startswith("mock") and not hostname.startswith("moto"):
        raise ValueError(
            f"[SECURITY GUARD] Non-local endpoint '{endpoint_url}' rejected in simulator mode. "
            "Must resolve to loopback (127.0.0.1, localhost) or local emulator container."
        )

    return endpoint_url


def is_live_aws() -> bool:
    """Return True if CloudGuardian is configured to connect to live AWS."""
    return os.getenv("CG_LIVE_AWS") == "1"


def is_dry_run() -> bool:
    """Return True if dry-run mode is enabled (mutating operations are simulated)."""
    return os.getenv("CG_DRY_RUN") == "1"


def is_live_setup_allowed() -> bool:
    """Return True if operator has explicitly authorized setup() in Live AWS mode."""
    return os.getenv("CG_ALLOW_LIVE_SETUP") == "1"


def get_aws_client(service_name: str, region_name: str = "us-east-1") -> Any:
    """Factory creating boto3 client with proper simulation vs live configuration."""
    if is_live_aws():
        # Live AWS: rely on standard AWS credential chain and region
        return boto3.client(service_name, region_name=region_name)

    # Simulator / Moto mode: point to local endpoint with test credentials
    raw_endpoint = os.getenv("AWS_ENDPOINT_URL", "http://127.0.0.1:5000")
    validated_endpoint = validate_endpoint_url(raw_endpoint)

    return boto3.client(
        service_name,
        region_name=region_name,
        endpoint_url=validated_endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        aws_session_token=None,
    )


def resolve_account_id(sts_client: Any) -> str:
    """Safely fetch and mask account ID."""
    live = is_live_aws()
    try:
        acct = sts_client.get_caller_identity()["Account"]
        if live:
            return acct[:4] + "****" + acct[-4:] if len(acct) >= 8 else "********"
        return acct
    except Exception as exc:
        logger.warning("Could not retrieve caller identity: %s", exc)
        return "unknown"


def safe_setup(
    s3_client: Any,
    ct_client: Any,
    ec2_client: Any,
    iam_client: Any,
    bucket_name: str,
    trail_name: str,
    user_name: str,
    block_config: Dict[str, bool],
    cidr_perm_fn: Callable[[str], list],
) -> Tuple[bool, Dict[str, str], str]:
    """Execute initial resource setup with strict safety guards for live mode.

    Returns:
        (success: bool, resource_ids: dict, message: str)
    """
    if is_live_aws() and not is_live_setup_allowed():
        msg = (
            "[SECURITY ALERT] Running in Live AWS mode (CG_LIVE_AWS=1). "
            "Automatic setup() SKIPPED to protect real AWS resources. "
            "Set CG_ALLOW_LIVE_SETUP=1 only if you explicitly authorize creating demo resources."
        )
        logger.warning(msg)
        return False, {}, msg

    resource_ids: Dict[str, str] = {}
    try:
        # S3 Buckets
        s3_client.create_bucket(Bucket=bucket_name)
        s3_client.create_bucket(Bucket=bucket_name + "-trail")
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=block_config
        )

        # CloudTrail
        ct_client.create_trail(Name=trail_name, S3BucketName=bucket_name + "-trail")
        ct_client.start_logging(Name=trail_name)

        # EC2 Security Group
        sg_resp = ec2_client.create_security_group(GroupName="web-sg", Description="web")
        sg_id = sg_resp["GroupId"]
        resource_ids["sg"] = sg_id
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=cidr_perm_fn("10.0.0.0/8")
        )

        # IAM User & Access Key
        iam_client.create_user(UserName=user_name)
        key_resp = iam_client.create_access_key(UserName=user_name)
        resource_ids["key"] = key_resp["AccessKey"]["AccessKeyId"]

        return True, resource_ids, "Setup completed successfully."

    except (EndpointConnectionError, ConnectionRefusedError) as conn_err:
        msg = (
            f"Cannot connect to Moto simulator at {os.getenv('AWS_ENDPOINT_URL', 'http://127.0.0.1:5000')}. "
            "Please start moto_server -p 5000 in another terminal."
        )
        logger.error("%s (%s)", msg, conn_err)
        return False, {}, msg
    except Exception as exc:
        msg = f"Setup failed: {exc}"
        logger.error(msg)
        return False, {}, msg


def safe_execute_remediation(
    action_name: str,
    fix_fn: Callable[[], Any],
    dry_run: Optional[bool] = None,
) -> Tuple[bool, str]:
    """Execute a remediation action, or simulate it if in dry-run mode."""
    use_dry_run = is_dry_run() if dry_run is None else dry_run

    if use_dry_run:
        msg = f"[DRY-RUN] Remediation '{action_name}' simulated without modifying cloud state."
        logger.info(msg)
        return True, msg

    try:
        fix_fn()
        return True, f"Remediation '{action_name}' executed."
    except Exception as exc:
        err_msg = f"Failed to execute remediation '{action_name}': {exc}"
        logger.error(err_msg)
        return False, err_msg
