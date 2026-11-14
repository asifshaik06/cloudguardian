"""Predefined Scenario Catalog for CloudGuardian 2.0 IAM Attack Simulation Lab.

Implements all 12 comprehensive cloud attack scenarios spanning:
1. IAM Privilege Escalation (Excessive IAM, Risky Trust, PassRole+Compute, Policy Versioning)
2. Cloud Resource Exposure (Public S3, Wildcard S3, Unrestricted KMS, EC2 SSH Ingress)
3. Identity & Lateral Movement (Compromised Dev, Role Chaining, CreateAccessKey, CloudTrail Tampering)

All scenarios run in isolated in-memory Moto simulation state.
"""
from typing import Any, Dict, List, Optional

from backend.scenarios.models import (
    IdentitySpec,
    PolicySpec,
    RelationshipSpec,
    ResourceSpec,
    ScenarioCategory,
    ScenarioDefinition,
    ScenarioDifficulty,
    StatementSpec,
)


def _build_scenario_definitions() -> Dict[str, ScenarioDefinition]:
    """Construct and return the registry of all 12 predefined attack scenarios."""
    scenarios: List[ScenarioDefinition] = [
        # ====================================================================
        # 1. IAM Privilege Escalation
        # ====================================================================
        ScenarioDefinition(
            id="privesc-excessive-iam",
            name="Excessive IAM Permissions Escalation",
            description=(
                "A junior operator account possesses unrestricted 'iam:*' permissions, "
                "allowing it to attach administrative policies to itself or assume the corporate admin role."
            ),
            category=ScenarioCategory.PRIVILEGE_ESCALATION,
            difficulty=ScenarioDifficulty.BEGINNER,
            learning_objective=(
                "Understand why 'iam:*' is equivalent to AdministratorAccess and practice "
                "scoping IAM modification permissions using permission boundaries and least privilege."
            ),
            mitre_attack=["T1098", "T1548.005"],
            identities=[
                IdentitySpec(
                    id="user/junior-operator",
                    name="junior-operator",
                    type="user",
                    arn="arn:aws:iam::123456789012:user/junior-operator",
                    attached_policies=["policy/excessive-iam-perm"],
                    is_admin=False,
                ),
                IdentitySpec(
                    id="role/admin-role",
                    name="admin-role",
                    type="role",
                    arn="arn:aws:iam::123456789012:role/admin-role",
                    attached_policies=["policy/AdministratorAccess"],
                    is_admin=True,
                ),
            ],
            resources=[
                ResourceSpec(
                    id="s3/prod-data",
                    name="prod-data",
                    type="s3",
                    arn="arn:aws:s3:::prod-data",
                    is_sensitive=True,
                ),
            ],
            policies=[
                PolicySpec(
                    id="policy/excessive-iam-perm",
                    name="ExcessiveIAMPermissions",
                    statements=[
                        StatementSpec(
                            sid="AllowAllIAM",
                            effect="Allow",
                            actions=["iam:*"],
                            resources=["*"],
                        ),
                    ],
                ),
                PolicySpec(
                    id="policy/AdministratorAccess",
                    name="AdministratorAccess",
                    statements=[
                        StatementSpec(
                            sid="FullAdmin",
                            effect="Allow",
                            actions=["*"],
                            resources=["*"],
                        ),
                    ],
                ),
            ],
            relationships=[
                RelationshipSpec(
                    source_id="user/junior-operator",
                    target_id="policy/excessive-iam-perm",
                    relationship="HasPolicy",
                    actions=["iam:*"],
                ),
                RelationshipSpec(
                    source_id="user/junior-operator",
                    target_id="role/admin-role",
                    relationship="CanEscalateTo",
                    actions=["iam:AttachUserPolicy", "iam:PutUserPolicy"],
                    evidence={"vector": "Direct policy attachment to self"},
                ),
                RelationshipSpec(
                    source_id="role/admin-role",
                    target_id="policy/AdministratorAccess",
                    relationship="HasPolicy",
                    actions=["*"],
                ),
                RelationshipSpec(
                    source_id="role/admin-role",
                    target_id="s3/prod-data",
                    relationship="CanAccessResource",
                    actions=["s3:*"],
                    evidence={"impact": "Full data exfiltration and destruction"},
                ),
            ],
            expected_findings=["Privilege Escalation: user/junior-operator -> role/admin-role"],
            expected_remediation={
                "type": "revoke_excessive_iam",
                "target": "user/junior-operator",
                "recommended_policy": "ReadOnlyAccess",
            },
            verification_criteria="Zero direct or transitive escalation paths from junior-operator to admin-role.",
            is_predefined=True,
        ),

        ScenarioDefinition(
            id="privesc-risky-trust",
            name="Risky AssumeRole Trust Policy",
            description=(
                "A sensitive infrastructure management role has an overly permissive trust policy "
                "allowing any authenticated AWS principal ('*') to assume it without MFA or external ID requirements."
            ),
            category=ScenarioCategory.PRIVILEGE_ESCALATION,
            difficulty=ScenarioDifficulty.INTERMEDIATE,
            learning_objective=(
                "Examine how misconfigured AssumeRole trust documents create lateral pivot points "
                "across disparate accounts and principals."
            ),
            mitre_attack=["T1078.004", "T1548.005"],
            identities=[
                IdentitySpec(
                    id="user/contractor",
                    name="contractor",
                    type="user",
                    arn="arn:aws:iam::123456789012:user/contractor",
                    is_admin=False,
                ),
                IdentitySpec(
                    id="role/infra-manager",
                    name="infra-manager",
                    type="role",
                    arn="arn:aws:iam::123456789012:role/infra-manager",
                    is_admin=True,
                    trust_policy=[
                        StatementSpec(
                            effect="Allow",
                            actions=["sts:AssumeRole"],
                            principals={"AWS": "*"},
                        ),
                    ],
                ),
            ],
            resources=[
                ResourceSpec(
                    id="s3/corp-secrets",
                    name="corp-secrets",
                    type="s3",
                    arn="arn:aws:s3:::corp-secrets",
                    is_sensitive=True,
                ),
            ],
            policies=[],
            relationships=[
                RelationshipSpec(
                    source_id="user/contractor",
                    target_id="role/infra-manager",
                    relationship="AssumesRole",
                    actions=["sts:AssumeRole"],
                    evidence={"flaw": "Unrestricted wildcard trust document"},
                ),
                RelationshipSpec(
                    source_id="role/infra-manager",
                    target_id="s3/corp-secrets",
                    relationship="CanAccessResource",
                    actions=["s3:GetObject", "s3:ListBucket"],
                ),
            ],
            expected_findings=["Privilege Escalation: user/contractor -> role/infra-manager"],
            expected_remediation={
                "type": "restrict_trust_policy",
                "target": "role/infra-manager",
                "allowed_principals": ["arn:aws:iam::123456789012:role/trusted-devops"],
            },
            verification_criteria="Role trust policy explicitly denies or restricts assumption from contractor user.",
            is_predefined=True,
        ),

        ScenarioDefinition(
            id="privesc-passrole-ec2",
            name="PassRole Combined with EC2 Execution",
            description=(
                "A developer possesses iam:PassRole combined with ec2:RunInstances. "
                "The developer can launch an EC2 compute instance with an attached administrative instance profile, "
                "retrieving full admin credentials via IMDS."
            ),
            category=ScenarioCategory.PRIVILEGE_ESCALATION,
            difficulty=ScenarioDifficulty.ADVANCED,
            learning_objective=(
                "Analyze the classic iam:PassRole + compute execution vulnerability and learn "
                "how resource-scoped PassRole statements prevent privilege escalation."
            ),
            mitre_attack=["T1548.005", "T1078"],
            identities=[
                IdentitySpec(
                    id="user/dev-tester",
                    name="dev-tester",
                    type="user",
                    arn="arn:aws:iam::123456789012:user/dev-tester",
                    is_admin=False,
                ),
                IdentitySpec(
                    id="role/ec2-admin-role",
                    name="ec2-admin-role",
                    type="role",
                    arn="arn:aws:iam::123456789012:role/ec2-admin-role",
                    is_admin=True,
                ),
            ],
            resources=[
                ResourceSpec(
                    id="ec2/compute-worker",
                    name="compute-worker",
                    type="ec2",
                    arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
                    configuration={"instance_profile": "ec2-admin-role"},
                ),
            ],
            policies=[],
            relationships=[
                RelationshipSpec(
                    source_id="user/dev-tester",
                    target_id="role/ec2-admin-role",
                    relationship="PassRole",
                    actions=["iam:PassRole", "ec2:RunInstances"],
                    evidence={"vector": "PassRole without resource boundary on launch"},
                ),
                RelationshipSpec(
                    source_id="role/ec2-admin-role",
                    target_id="ec2/compute-worker",
                    relationship="AssumesRole",
                    actions=["sts:AssumeRole"],
                ),
            ],
            expected_findings=["Potential Privilege Escalation: user/dev-tester -> role/ec2-admin-role"],
            expected_remediation={
                "type": "restrict_passrole_resource",
                "target": "user/dev-tester",
                "allowed_roles": ["arn:aws:iam::123456789012:role/dev-worker-only"],
            },
            verification_criteria="PassRole capability restricted to non-administrative instance profiles.",
            is_predefined=True,
        ),

        ScenarioDefinition(
            id="privesc-policy-version",
            name="Dangerous IAM Policy Modification",
            description=(
                "An application maintainer possesses iam:CreatePolicyVersion and iam:SetDefaultPolicyVersion permissions. "
                "The maintainer can create a new version of their own policy granting '*' permissions and make it active."
            ),
            category=ScenarioCategory.PRIVILEGE_ESCALATION,
            difficulty=ScenarioDifficulty.INTERMEDIATE,
            learning_objective=(
                "Detect how policy modification APIs allow indirect privilege escalation without requiring "
                "direct policy attachment rights."
            ),
            mitre_attack=["T1098"],
            identities=[
                IdentitySpec(
                    id="user/app-maintainer",
                    name="app-maintainer",
                    type="user",
                    arn="arn:aws:iam::123456789012:user/app-maintainer",
                    is_admin=False,
                ),
                IdentitySpec(
                    id="role/super-admin",
                    name="super-admin",
                    type="role",
                    arn="arn:aws:iam::123456789012:role/super-admin",
                    is_admin=True,
                ),
            ],
            resources=[],
            policies=[
                PolicySpec(
                    id="policy/editable-app-policy",
                    name="EditableAppPolicy",
                    statements=[
                        StatementSpec(
                            effect="Allow",
                            actions=["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
                            resources=["*"],
                        ),
                    ],
                ),
            ],
            relationships=[
                RelationshipSpec(
                    source_id="user/app-maintainer",
                    target_id="policy/editable-app-policy",
                    relationship="HasPolicy",
                    actions=["iam:CreatePolicyVersion"],
                ),
                RelationshipSpec(
                    source_id="user/app-maintainer",
                    target_id="role/super-admin",
                    relationship="CanEscalateTo",
                    actions=["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
                    evidence={"vector": "Self-escalation via policy version manipulation"},
                ),
            ],
            expected_findings=["Privilege Escalation: user/app-maintainer -> role/super-admin"],
            expected_remediation={
                "type": "remove_policy_version_privilege",
                "target": "user/app-maintainer",
            },
            verification_criteria="App maintainer no longer possesses policy versioning or default selection permissions.",
            is_predefined=True,
        ),

        # ====================================================================
        # 2. Cloud Resource Exposure
        # ====================================================================
        ScenarioDefinition(
            id="resource-s3-public",
            name="Public S3 Bucket Exposure",
            description=(
                "A sensitive S3 storage bucket containing confidential records has public access blocks disabled "
                "and an unrestricted bucket policy permitting anonymous 's3:GetObject' requests from the internet."
            ),
            category=ScenarioCategory.RESOURCE_EXPOSURE,
            difficulty=ScenarioDifficulty.BEGINNER,
            learning_objective=(
                "Understand S3 Public Access Block settings and learn how resource policies inadvertently expose "
                "cloud storage to unauthorized public enumeration."
            ),
            mitre_attack=["T1530"],
            identities=[
                IdentitySpec(
                    id="user/anonymous",
                    name="anonymous-caller",
                    type="user",
                    arn="arn:aws:iam::anonymous:user/public",
                    is_admin=False,
                ),
            ],
            resources=[
                ResourceSpec(
                    id="s3/student-records-public",
                    name="student-records-public",
                    type="s3",
                    arn="arn:aws:s3:::student-records-public",
                    is_sensitive=True,
                    configuration={"public_access": True, "public_exposure": True},
                ),
            ],
            policies=[],
            relationships=[
                RelationshipSpec(
                    source_id="user/anonymous",
                    target_id="s3/student-records-public",
                    relationship="CanAccessResource",
                    actions=["s3:GetObject", "s3:ListBucket"],
                    evidence={"public_access": True},
                ),
            ],
            expected_findings=["Public Resource Exposure: student-records-public"],
            expected_remediation={
                "type": "enable_s3_public_access_block",
                "target": "s3/student-records-public",
            },
            verification_criteria="S3 Public Access Block enabled and unauthenticated access revoked.",
            is_predefined=True,
        ),

        ScenarioDefinition(
            id="resource-s3-wildcard",
            name="Excessive S3 Wildcard Access",
            description=(
                "A support analyst's IAM policy uses 'Resource: *' for S3 actions, unintentionally "
                "granting full read and write access to sensitive payroll database archives."
            ),
            category=ScenarioCategory.RESOURCE_EXPOSURE,
            difficulty=ScenarioDifficulty.INTERMEDIATE,
            learning_objective=(
                "Practice scoping S3 resource ARNs to specific bucket namespaces rather than "
                "permitting global wildcard storage access."
            ),
            mitre_attack=["T1530"],
            identities=[
                IdentitySpec(
                    id="user/support-analyst",
                    name="support-analyst",
                    type="user",
                    arn="arn:aws:iam::123456789012:user/support-analyst",
                    is_admin=False,
                ),
            ],
            resources=[
                ResourceSpec(
                    id="s3/general-assets",
                    name="general-assets",
                    type="s3",
                    arn="arn:aws:s3:::general-assets",
                    is_sensitive=False,
                ),
                ResourceSpec(
                    id="s3/payroll-database-archive",
                    name="payroll-database-archive",
                    type="s3",
                    arn="arn:aws:s3:::payroll-database-archive",
                    is_sensitive=True,
                ),
            ],
            policies=[],
            relationships=[
                RelationshipSpec(
                    source_id="user/support-analyst",
                    target_id="s3/general-assets",
                    relationship="CanAccessResource",
                    actions=["s3:GetObject"],
                ),
                RelationshipSpec(
                    source_id="user/support-analyst",
                    target_id="s3/payroll-database-archive",
                    relationship="CanAccessResource",
                    actions=["s3:GetObject", "s3:DeleteObject"],
                    evidence={"risk": "Unintended wildcard access to sensitive archive"},
                ),
            ],
            expected_findings=["Asset Access: user/support-analyst -> s3/payroll-database-archive"],
            expected_remediation={
                "type": "scope_s3_resource_arn",
                "target": "user/support-analyst",
                "allowed_buckets": ["arn:aws:s3:::general-assets/*"],
            },
            verification_criteria="Support analyst can only access general-assets and is blocked from payroll archive.",
            is_predefined=True,
        ),

        ScenarioDefinition(
            id="resource-kms-unrestricted",
            name="KMS Key Access Misconfiguration",
            description=(
                "A customer-managed KMS key used to encrypt customer PII has an unrestricted key policy "
                "allowing any IAM user in the account to execute kms:Decrypt and kms:CreateGrant."
            ),
            category=ScenarioCategory.RESOURCE_EXPOSURE,
            difficulty=ScenarioDifficulty.ADVANCED,
            learning_objective=(
                "Master KMS key policy evaluation and ensure cryptographic boundaries remain distinct "
                "from general IAM user permissions."
            ),
            mitre_attack=["T1530", "T1078"],
            identities=[
                IdentitySpec(
                    id="user/intern-viewer",
                    name="intern-viewer",
                    type="user",
                    arn="arn:aws:iam::123456789012:user/intern-viewer",
                    is_admin=False,
                ),
            ],
            resources=[
                ResourceSpec(
                    id="kms/pii-encryption-key",
                    name="pii-encryption-key",
                    type="kms",
                    arn="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789abc",
                    is_sensitive=True,
                ),
            ],
            policies=[],
            relationships=[
                RelationshipSpec(
                    source_id="user/intern-viewer",
                    target_id="kms/pii-encryption-key",
                    relationship="CanAccessResource",
                    actions=["kms:Decrypt", "kms:CreateGrant"],
                    evidence={"flaw": "Unrestricted KMS key policy"},
                ),
            ],
            expected_findings=["Asset Access: user/intern-viewer -> kms/pii-encryption-key"],
            expected_remediation={
                "type": "restrict_kms_key_policy",
                "target": "kms/pii-encryption-key",
                "authorized_roles": ["arn:aws:iam::123456789012:role/crypto-service-role"],
            },
            verification_criteria="Intern viewer loses kms:Decrypt capability on PII key.",
            is_predefined=True,
        ),

        ScenarioDefinition(
            id="resource-ec2-ingress-ssh",
            name="EC2 Security Group SSH Exposure",
            description=(
                "An EC2 bastion host has an inbound security group rule allowing SSH (port 22) "
                "from the entire internet (0.0.0.0/0), exposing the administrative entry point to brute-force attacks."
            ),
            category=ScenarioCategory.RESOURCE_EXPOSURE,
            difficulty=ScenarioDifficulty.BEGINNER,
            learning_objective=(
                "Identify high-risk security group ingress configurations and implement secure alternatives "
                "such as AWS Systems Manager Session Manager."
            ),
            mitre_attack=["T1190", "T1021.004"],
            identities=[
                IdentitySpec(
                    id="user/external-attacker",
                    name="external-attacker",
                    type="user",
                    arn="arn:aws:iam::external:user/attacker",
                    is_admin=False,
                ),
            ],
            resources=[
                ResourceSpec(
                    id="ec2/bastion-host",
                    name="bastion-host",
                    type="ec2",
                    arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0987654321",
                    configuration={"public_exposure": True, "ingress_port": 22, "cidr": "0.0.0.0/0"},
                ),
            ],
            policies=[],
            relationships=[
                RelationshipSpec(
                    source_id="user/external-attacker",
                    target_id="ec2/bastion-host",
                    relationship="CanAccessResource",
                    actions=["network:ssh_ingress"],
                    evidence={"cidr": "0.0.0.0/0", "port": 22},
                ),
            ],
            expected_findings=["Public Resource Exposure: bastion-host"],
            expected_remediation={
                "type": "close_security_group_ingress",
                "target": "ec2/bastion-host",
                "revoked_cidr": "0.0.0.0/0",
            },
            verification_criteria="0.0.0.0/0 ingress on port 22 revoked and public exposure eliminated.",
            is_predefined=True,
        ),

        # ====================================================================
        # 3. Identity and Lateral Movement
        # ====================================================================
        ScenarioDefinition(
            id="lateral-compromised-dev",
            name="Compromised Developer Identity Pivot",
            description=(
                "A developer's long-term access keys are compromised in source code. "
                "The identity can assume a staging deployer role, which in turn can assume production admin."
            ),
            category=ScenarioCategory.LATERAL_MOVEMENT,
            difficulty=ScenarioDifficulty.INTERMEDIATE,
            learning_objective=(
                "Trace blast radius propagation from a compromised developer identity through "
                "intermediate deployment roles to full administrative control."
            ),
            mitre_attack=["T1078.004", "T1548.005"],
            identities=[
                IdentitySpec(
                    id="user/compromised-developer",
                    name="compromised-developer",
                    type="user",
                    arn="arn:aws:iam::123456789012:user/compromised-developer",
                    is_admin=False,
                    metadata={"compromised": True},
                ),
                IdentitySpec(
                    id="role/staging-deployer",
                    name="staging-deployer",
                    type="role",
                    arn="arn:aws:iam::123456789012:role/staging-deployer",
                    is_admin=False,
                ),
                IdentitySpec(
                    id="role/production-admin",
                    name="production-admin",
                    type="role",
                    arn="arn:aws:iam::123456789012:role/production-admin",
                    is_admin=True,
                ),
            ],
            resources=[
                ResourceSpec(
                    id="s3/production-secrets",
                    name="production-secrets",
                    type="s3",
                    arn="arn:aws:s3:::production-secrets",
                    is_sensitive=True,
                ),
            ],
            policies=[],
            relationships=[
                RelationshipSpec(
                    source_id="user/compromised-developer",
                    target_id="role/staging-deployer",
                    relationship="AssumesRole",
                    actions=["sts:AssumeRole"],
                ),
                RelationshipSpec(
                    source_id="role/staging-deployer",
                    target_id="role/production-admin",
                    relationship="AssumesRole",
                    actions=["sts:AssumeRole"],
                    evidence={"vector": "Excessive trust relationship between staging and prod"},
                ),
                RelationshipSpec(
                    source_id="role/production-admin",
                    target_id="s3/production-secrets",
                    relationship="CanAccessResource",
                    actions=["s3:*"],
                ),
            ],
            expected_findings=["Privilege Escalation: user/compromised-developer -> role/production-admin"],
            expected_remediation={
                "type": "sever_cross_environment_trust",
                "source": "role/staging-deployer",
                "target": "role/production-admin",
            },
            verification_criteria="Staging deployer role severed from production admin trust.",
            is_predefined=True,
        ),

        ScenarioDefinition(
            id="lateral-role-chaining",
            name="Multi-Hop Role Chaining Attack",
            description=(
                "An adversary traverses three distinct intermediate roles across security tiers "
                "(Analyst -> Tier 1 Reader -> Tier 2 Operator -> Tier 3 Orchestrator -> Cloud Admin) "
                "to obscure attribution and bypass single-hop monitoring."
            ),
            category=ScenarioCategory.LATERAL_MOVEMENT,
            difficulty=ScenarioDifficulty.ADVANCED,
            learning_objective=(
                "Evaluate graph traversal algorithms capable of detecting deep multi-hop role chaining "
                "and learn how to enforce session tags and trust condition boundaries."
            ),
            mitre_attack=["T1078.004", "T1548.005"],
            identities=[
                IdentitySpec(id="user/analyst", name="analyst", type="user", arn="arn:aws:iam::123456789012:user/analyst"),
                IdentitySpec(id="role/tier1-reader", name="tier1-reader", type="role", arn="arn:aws:iam::123456789012:role/tier1-reader"),
                IdentitySpec(id="role/tier2-operator", name="tier2-operator", type="role", arn="arn:aws:iam::123456789012:role/tier2-operator"),
                IdentitySpec(id="role/tier3-orchestrator", name="tier3-orchestrator", type="role", arn="arn:aws:iam::123456789012:role/tier3-orchestrator"),
                IdentitySpec(id="role/cloud-admin", name="cloud-admin", type="role", arn="arn:aws:iam::123456789012:role/cloud-admin", is_admin=True),
            ],
            resources=[],
            policies=[],
            relationships=[
                RelationshipSpec(source_id="user/analyst", target_id="role/tier1-reader", relationship="AssumesRole", actions=["sts:AssumeRole"]),
                RelationshipSpec(source_id="role/tier1-reader", target_id="role/tier2-operator", relationship="AssumesRole", actions=["sts:AssumeRole"]),
                RelationshipSpec(source_id="role/tier2-operator", target_id="role/tier3-orchestrator", relationship="AssumesRole", actions=["sts:AssumeRole"]),
                RelationshipSpec(source_id="role/tier3-orchestrator", target_id="role/cloud-admin", relationship="AssumesRole", actions=["sts:AssumeRole"]),
            ],
            expected_findings=["Privilege Escalation: user/analyst -> role/cloud-admin"],
            expected_remediation={
                "type": "break_role_chain",
                "intermediate_hop": "role/tier2-operator",
            },
            verification_criteria="Role chain broken at tier 2, preventing progression to tier 3 and cloud-admin.",
            is_predefined=True,
        ),

        ScenarioDefinition(
            id="lateral-create-access-key",
            name="Unauthorized Access-Key Creation",
            description=(
                "A low-privilege service account possesses iam:CreateAccessKey without a resource restriction, "
                "enabling it to generate persistent API access keys for administrative users."
            ),
            category=ScenarioCategory.LATERAL_MOVEMENT,
            difficulty=ScenarioDifficulty.INTERMEDIATE,
            learning_objective=(
                "Detect credential persistence mechanisms in AWS IAM and implement least-privilege "
                "scoping for credential creation APIs."
            ),
            mitre_attack=["T1098", "T1078"],
            identities=[
                IdentitySpec(
                    id="user/service-account",
                    name="service-account",
                    type="user",
                    arn="arn:aws:iam::123456789012:user/service-account",
                    is_admin=False,
                ),
                IdentitySpec(
                    id="user/backup-admin",
                    name="backup-admin",
                    type="user",
                    arn="arn:aws:iam::123456789012:user/backup-admin",
                    is_admin=True,
                ),
            ],
            resources=[],
            policies=[],
            relationships=[
                RelationshipSpec(
                    source_id="user/service-account",
                    target_id="user/backup-admin",
                    relationship="CanEscalateTo",
                    actions=["iam:CreateAccessKey"],
                    evidence={"vector": "Creation of secondary credentials on high-privilege target"},
                ),
            ],
            expected_findings=["Privilege Escalation: user/service-account -> user/backup-admin"],
            expected_remediation={
                "type": "revoke_credential_creation",
                "target": "user/service-account",
            },
            verification_criteria="Service account restricted from generating keys on other IAM users.",
            is_predefined=True,
        ),

        ScenarioDefinition(
            id="defense-evasion-cloudtrail",
            name="CloudTrail Logging Tampering Risk",
            description=(
                "An operational role possesses s3:DeleteBucket and s3:DeleteObject permissions on the "
                "centralized CloudTrail audit logging bucket, allowing an attacker to destroy security audit evidence."
            ),
            category=ScenarioCategory.LATERAL_MOVEMENT,
            difficulty=ScenarioDifficulty.ADVANCED,
            learning_objective=(
                "Analyze audit-log tampering vectors (MITRE ATT&CK T1562.001) and apply "
                "immutable S3 Object Lock and Service Control Policy guardrails."
            ),
            mitre_attack=["T1562.001", "T1530"],
            identities=[
                IdentitySpec(
                    id="user/rogue-operator",
                    name="rogue-operator",
                    type="user",
                    arn="arn:aws:iam::123456789012:user/rogue-operator",
                    is_admin=False,
                ),
            ],
            resources=[
                ResourceSpec(
                    id="s3/cloudtrail-audit-logs",
                    name="cloudtrail-audit-logs",
                    type="s3",
                    arn="arn:aws:s3:::cloudtrail-audit-logs",
                    is_sensitive=True,
                ),
            ],
            policies=[],
            relationships=[
                RelationshipSpec(
                    source_id="user/rogue-operator",
                    target_id="s3/cloudtrail-audit-logs",
                    relationship="CanAccessResource",
                    actions=["s3:DeleteBucket", "s3:DeleteObject", "cloudtrail:StopLogging"],
                    evidence={"defense_evasion": True},
                ),
            ],
            expected_findings=["Asset Access: user/rogue-operator -> s3/cloudtrail-audit-logs"],
            expected_remediation={
                "type": "enforce_s3_object_lock_and_deny_delete",
                "target": "s3/cloudtrail-audit-logs",
            },
            verification_criteria="Deletion actions explicitly denied for audit storage.",
            is_predefined=True,
        ),
    ]

    return {s.id: s for s in scenarios}


# Global catalog registry
_SCENARIO_CATALOG: Dict[str, ScenarioDefinition] = _build_scenario_definitions()


def get_scenario_catalog() -> Dict[str, ScenarioDefinition]:
    """Retrieve all 12 predefined scenarios."""
    return dict(_SCENARIO_CATALOG)


def get_scenario_by_id(scenario_id: str) -> Optional[ScenarioDefinition]:
    """Lookup a predefined scenario by unique identifier."""
    return _SCENARIO_CATALOG.get(scenario_id)


def list_scenario_summaries() -> List[Dict[str, Any]]:
    """Return catalog summary list for UI library cards and API endpoints."""
    return [
        {
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "category": s.category.value,
            "difficulty": s.difficulty.value,
            "learning_objective": s.learning_objective,
            "mitre_attack": s.mitre_attack,
            "identity_count": len(s.identities),
            "resource_count": len(s.resources),
            "relationship_count": len(s.relationships),
            "expected_findings_count": len(s.expected_findings),
        }
        for s in _SCENARIO_CATALOG.values()
    ]
