"""Scenario Data Model for CloudGuardian 2.0 IAM Attack Simulation Lab.

Defines declarative Pydantic schemas for predefined scenarios, dynamic custom scenarios,
IAM statements, identities, resources, findings, and isolated runtime state.
"""
from enum import Enum
import time
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class ScenarioCategory(str, Enum):
    """Broad classification of security attack scenarios."""
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    RESOURCE_EXPOSURE = "Resource Exposure"
    LATERAL_MOVEMENT = "Identity & Lateral Movement"
    CUSTOM = "Custom Scenario"


class ScenarioDifficulty(str, Enum):
    """Complexity level for analyst learning and simulation."""
    BEGINNER = "Beginner"
    INTERMEDIATE = "Intermediate"
    ADVANCED = "Advanced"


class PathClassification(str, Enum):
    """Confidence classification of discovered attack paths."""
    CONFIRMED = "CONFIRMED"       # All Allow, no Deny, valid trust, conditions satisfied
    POTENTIAL = "POTENTIAL"       # Capability exists (e.g. PassRole), requires external compute context
    BLOCKED = "BLOCKED"           # Blocked by explicit Deny, boundary restriction, or unmet condition
    UNVERIFIED = "UNVERIFIED"     # Ambiguous or missing relationship edge/trust
    THEORETICAL = "BLOCKED"       # Backward-compatible alias for BLOCKED

    @classmethod
    def _missing_(cls, value: object) -> Any:
        if isinstance(value, str):
            val_upper = value.upper()
            if val_upper in ("THEORETICAL", "BLOCKED"):
                return cls.BLOCKED
            for member in cls:
                if member.value == val_upper:
                    return member
        return super()._missing_(value)

    def __hash__(self) -> int:
        return hash(self.value.upper())

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            val_upper = self.value.upper()
            oth_upper = other.upper()
            if val_upper == oth_upper:
                return True
            if val_upper == "BLOCKED" and oth_upper in ("THEORETICAL", "BLOCKED"):
                return True
        return super().__eq__(other)


class RunStatus(str, Enum):
    """Lifecycle state of an isolated scenario execution."""
    INITIALIZED = "initialized"
    ANALYZED = "analyzed"
    REMEDIATED = "remediated"
    VERIFIED = "verified"
    RESET = "reset"


class StatementSpec(BaseModel):
    """Declarative specification for an individual IAM statement."""
    sid: Optional[str] = None
    effect: Literal["Allow", "Deny"] = "Allow"
    actions: List[str] = Field(default_factory=list)
    resources: List[str] = Field(default_factory=lambda: ["*"])
    conditions: Dict[str, Any] = Field(default_factory=dict)
    principals: Dict[str, Any] = Field(default_factory=dict)

    def to_iam_dict(self) -> Dict[str, Any]:
        """Convert to standard AWS IAM Statement dictionary."""
        stmt: Dict[str, Any] = {
            "Effect": self.effect,
            "Action": self.actions if len(self.actions) > 1 else (self.actions[0] if self.actions else "*"),
            "Resource": self.resources if len(self.resources) > 1 else (self.resources[0] if self.resources else "*"),
        }
        if self.sid:
            stmt["Sid"] = self.sid
        if self.conditions:
            stmt["Condition"] = self.conditions
        if self.principals:
            stmt["Principal"] = self.principals
        return stmt


class PolicySpec(BaseModel):
    """Declarative specification of an IAM policy."""
    id: str
    name: str
    arn: Optional[str] = None
    is_managed: bool = True
    statements: List[StatementSpec] = Field(default_factory=list)

    def to_iam_document(self) -> Dict[str, Any]:
        """Convert to standard AWS IAM Policy Document."""
        return {
            "Version": "2012-10-17",
            "Statement": [s.to_iam_dict() for s in self.statements],
        }


class IdentitySpec(BaseModel):
    """Declarative specification of an IAM principal (User, Role, Group)."""
    id: str                       # e.g. "user/intern-dev", "role/staging-role"
    name: str
    type: Literal["user", "role", "group"] = "user"
    arn: str
    attached_policies: List[str] = Field(default_factory=list) # IDs of attached PolicySpecs
    inline_policies: List[PolicySpec] = Field(default_factory=list)
    trust_policy: Optional[List[StatementSpec]] = None          # AssumeRolePolicyDocument for roles
    is_admin: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ResourceSpec(BaseModel):
    """Declarative specification of an AWS resource (S3 bucket, EC2 instance, KMS key)."""
    id: str                       # e.g. "s3/student-records-demo", "ec2/bastion"
    name: str
    type: Literal["s3", "ec2", "kms"] = "s3"
    arn: str
    is_sensitive: bool = False
    resource_policy: Optional[List[StatementSpec]] = None
    configuration: Dict[str, Any] = Field(default_factory=dict)


class RelationshipSpec(BaseModel):
    """Explicitly specified relationship or initial capability transition."""
    source_id: str
    target_id: str
    relationship: str            # AssumesRole, PassRole, CanAccessResource, HasPolicy, MemberOf, CanEscalateTo
    actions: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)


class ScenarioFinding(BaseModel):
    """Evidence-backed security finding generated dynamically during scenario analysis."""
    finding_id: str
    title: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    category: str
    description: str
    remediation_advice: str
    affected_resources: List[str] = Field(default_factory=list)
    attack_path_id: Optional[str] = None
    mitre_attack: Optional[str] = None
    detected_at: str = Field(default_factory=lambda: time.strftime("%H:%M:%S"))


class ScenarioDefinition(BaseModel):
    """Complete declarative definition of an attack scenario."""
    id: str
    name: str
    description: str
    category: ScenarioCategory
    difficulty: ScenarioDifficulty
    learning_objective: str
    mitre_attack: List[str] = Field(default_factory=list)
    identities: List[IdentitySpec] = Field(default_factory=list)
    resources: List[ResourceSpec] = Field(default_factory=list)
    policies: List[PolicySpec] = Field(default_factory=list)
    relationships: List[RelationshipSpec] = Field(default_factory=list)
    expected_findings: List[str] = Field(default_factory=list)
    expected_remediation: Dict[str, Any] = Field(default_factory=dict)
    verification_criteria: str = ""
    is_predefined: bool = True


class ScenarioRun(BaseModel):
    """Runtime tracking of an isolated execution of a scenario."""
    run_id: str
    scenario_id: str
    scenario_name: str
    status: RunStatus = RunStatus.INITIALIZED
    created_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    definition: ScenarioDefinition
    findings: List[ScenarioFinding] = Field(default_factory=list)
    paths: List[Dict[str, Any]] = Field(default_factory=list)
    blast_radius: Dict[str, Any] = Field(default_factory=dict)
    remediation_applied: Optional[Dict[str, Any]] = None
    verification_result: Optional[Dict[str, Any]] = None
