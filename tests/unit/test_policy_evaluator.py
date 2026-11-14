"""Unit tests for Deterministic IAM Policy Evaluator (PolicyEvaluator).

Verifies AWS IAM policy statement evaluation, wildcard action/resource matching,
explicit Deny precedence, condition evaluation, trust policy verification,
and path classification (Confirmed, Potential, Theoretical).
"""
import pytest

from backend.graph.iam_graph import EdgeType, IAMCapabilityGraph, NodeType
from backend.graph.policy_evaluator import PolicyEvaluator
from backend.scenarios.models import PathClassification, StatementSpec


def test_wildcard_action_matching():
    """Verify wildcard matching for IAM action strings."""
    assert PolicyEvaluator.match_wildcard("*", "s3:GetObject")
    assert PolicyEvaluator.match_wildcard("s3:*", "s3:GetObject")
    assert PolicyEvaluator.match_wildcard("s3:*", "s3:PutObject")
    assert not PolicyEvaluator.match_wildcard("s3:*", "iam:PassRole")
    assert PolicyEvaluator.match_wildcard("iam:create*", "iam:CreateAccessKey")
    assert not PolicyEvaluator.match_wildcard("iam:create*", "iam:DeleteAccessKey")


def test_wildcard_resource_matching():
    """Verify wildcard matching for IAM resource ARNs."""
    assert PolicyEvaluator.match_wildcard("*", "arn:aws:s3:::my-bucket/*")
    assert PolicyEvaluator.match_wildcard("arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket/secret.txt")
    assert not PolicyEvaluator.match_wildcard("arn:aws:s3:::my-bucket/*", "arn:aws:s3:::other-bucket/secret.txt")


def test_condition_evaluation_bool():
    """Verify evaluation of Boolean condition operators (e.g. MFA)."""
    cond = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    assert PolicyEvaluator.evaluate_conditions(cond, {"mfa_present": True})
    assert not PolicyEvaluator.evaluate_conditions(cond, {"mfa_present": False})
    assert not PolicyEvaluator.evaluate_conditions(cond, {})


def test_condition_evaluation_string():
    """Verify evaluation of String condition operators."""
    # StringEquals
    cond_eq = {"StringEquals": {"aws:PrincipalTag/Department": "engineering"}}
    assert PolicyEvaluator.evaluate_conditions(cond_eq, {"aws:PrincipalTag/Department": "engineering"})
    assert not PolicyEvaluator.evaluate_conditions(cond_eq, {"aws:PrincipalTag/Department": "finance"})

    # StringLike
    cond_like = {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/admin-*"}}
    assert PolicyEvaluator.evaluate_conditions(cond_like, {"caller_arn": "arn:aws:iam::123456789012:role/admin-role"})
    assert not PolicyEvaluator.evaluate_conditions(cond_like, {"caller_arn": "arn:aws:iam::123456789012:role/dev-role"})


def test_condition_evaluation_ip():
    """Verify evaluation of IpAddress CIDR condition operators."""
    cond = {"IpAddress": {"aws:SourceIp": "192.168.1.0/24"}}
    assert PolicyEvaluator.evaluate_conditions(cond, {"source_ip": "192.168.1.50"})
    assert not PolicyEvaluator.evaluate_conditions(cond, {"source_ip": "10.0.0.1"})


def test_explicit_deny_precedence():
    """Verify that explicit Deny terminates and overrides any Allow."""
    statements = [
        StatementSpec(
            effect="Allow",
            actions=["s3:*"],
            resources=["*"],
        ),
        StatementSpec(
            effect="Deny",
            actions=["s3:Delete*"],
            resources=["arn:aws:s3:::main-trail-bucket/*"],
        ),
    ]

    # Reading an object is allowed
    assert PolicyEvaluator.evaluate_permissions(
        statements,
        action="s3:GetObject",
        resource="arn:aws:s3:::main-trail-bucket/logs",
    ) == "ALLOW"

    # Deleting object from trail bucket is explicitly DENIED despite wildcard Allow
    assert PolicyEvaluator.evaluate_permissions(
        statements,
        action="s3:DeleteObject",
        resource="arn:aws:s3:::main-trail-bucket/logs",
    ) == "DENY"

    # Action outside statements defaults to DENY
    assert PolicyEvaluator.evaluate_permissions(
        statements,
        action="iam:PassRole",
        resource="arn:aws:iam::123456789012:role/admin",
    ) == "DEFAULT_DENY"


def test_trust_policy_evaluation():
    """Verify AssumeRolePolicyDocument evaluation for STS AssumeRole."""
    trust_statements = [
        StatementSpec(
            effect="Allow",
            actions=["sts:AssumeRole"],
            principals={"AWS": ["arn:aws:iam::123456789012:role/cicd-deployer"]},
            conditions={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        ),
    ]

    # Authorized caller with MFA present
    assert PolicyEvaluator.evaluate_trust_policy(
        trust_statements,
        caller_arn="arn:aws:iam::123456789012:role/cicd-deployer",
        context={"mfa_present": True},
    )

    # Authorized caller but MFA missing -> rejected
    assert not PolicyEvaluator.evaluate_trust_policy(
        trust_statements,
        caller_arn="arn:aws:iam::123456789012:role/cicd-deployer",
        context={"mfa_present": False},
    )

    # Unauthorized caller -> rejected
    assert not PolicyEvaluator.evaluate_trust_policy(
        trust_statements,
        caller_arn="arn:aws:iam::123456789012:user/intern-dev",
        context={"mfa_present": True},
    )


def test_classify_path_confirmed():
    """Verify path classification as CONFIRMED when all hops allow with no restrictions."""
    graph = IAMCapabilityGraph()
    graph.add_principal("user/intern-dev", name="intern-dev", principal_type=NodeType.USER)
    graph.add_principal(
        "role/dev-role",
        name="dev-role",
        principal_type=NodeType.ROLE,
        arn="arn:aws:iam::123456789012:role/dev-role",
        evidence={
            "trust_policy": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": "*"},
                }
            ]
        },
    )
    graph.add_resource("s3/public-data", name="public-data", resource_type=NodeType.S3)

    graph.add_relationship("user/intern-dev", "role/dev-role", EdgeType.ASSUMES_ROLE, actions=["sts:AssumeRole"])
    graph.add_relationship("role/dev-role", "s3/public-data", EdgeType.CAN_ACCESS, actions=["s3:GetObject"])

    cls, reason, hops = PolicyEvaluator.classify_path(graph, ["user/intern-dev", "role/dev-role", "s3/public-data"])
    assert cls == PathClassification.CONFIRMED
    assert len(hops) == 2
    assert all(h["status"] == "PERMITTED" for h in hops)


def test_classify_path_potential_passrole():
    """Verify path classification as POTENTIAL when PassRole requires compute trigger."""
    graph = IAMCapabilityGraph()
    graph.add_principal("user/intern-dev", name="intern-dev", principal_type=NodeType.USER)
    graph.add_principal("role/admin-role", name="admin-role", principal_type=NodeType.ROLE, is_admin=True)

    graph.add_relationship(
        "user/intern-dev",
        "role/admin-role",
        EdgeType.PASS_ROLE,
        actions=["iam:PassRole", "ec2:RunInstances"],
    )

    cls, reason, hops = PolicyEvaluator.classify_path(graph, ["user/intern-dev", "role/admin-role"])
    assert cls == PathClassification.POTENTIAL
    assert "compute trigger" in reason.lower()
    assert hops[0]["status"] == "REQUIRES_COMPUTE_TRIGGER"


def test_classify_path_theoretical_explicit_deny():
    """Verify path classification as THEORETICAL when an edge has explicit Deny."""
    graph = IAMCapabilityGraph()
    graph.add_principal("user/intern-dev", name="intern-dev", principal_type=NodeType.USER)
    graph.add_principal("role/admin-role", name="admin-role", principal_type=NodeType.ROLE, is_admin=True)

    graph.add_relationship(
        "user/intern-dev",
        "role/admin-role",
        EdgeType.ASSUMES_ROLE,
        actions=["sts:AssumeRole"],
        effect="Deny",
    )

    cls, reason, hops = PolicyEvaluator.classify_path(graph, ["user/intern-dev", "role/admin-role"])
    assert cls == PathClassification.THEORETICAL
    assert "explicit deny" in reason.lower()
    assert hops[0]["status"] == "EXPLICIT_DENY"
