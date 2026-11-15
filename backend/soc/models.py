"""Data models for CloudGuardian 2.0 Security Operations Center (SOC) Layer.

Defines Pydantic schemas for:
- Alerts (lifecycle, severity, detection source, raw event evidence, timeline)
- Incidents (incident response lifecycle, containment, response actions, notes)
- Remediations (independent verification states PASS/PARTIAL/FAIL, before/after diffs, rollback)
"""
from enum import Enum
import time
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class AlertStatus(str, Enum):
    NEW = "New"
    ACKNOWLEDGED = "Acknowledged"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    SUPPRESSED = "Suppressed"


class IncidentSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class IncidentStatus(str, Enum):
    TRIAGE = "Triage"
    INVESTIGATION = "Investigation"
    CONTAINMENT = "Containment"
    REMEDIATION = "Remediation"
    VERIFICATION = "Verification"
    CLOSED = "Closed"


class RemediationStatus(str, Enum):
    PENDING = "Pending"
    APPROVED = "Approved"
    IN_PROGRESS = "In Progress"
    APPLIED = "Applied"
    VERIFICATION_PENDING = "Verification Pending"
    VERIFIED = "Verified"
    FAILED = "Failed"
    ROLLED_BACK = "Rolled Back"


class VerificationState(str, Enum):
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"
    UNVERIFIED = "UNVERIFIED"


class AlertRecord(BaseModel):
    """Complete security alert representation."""
    id: str
    title: str
    severity: AlertSeverity
    affected_resource: str
    account_id: str = "123456789012"
    environment: str = "Moto Simulated Cloud"
    detection_source: str = "Rule Engine"  # "Rule Engine", "ML Anomaly Detector", "IAM Graph", "Simulation Lab"
    category: str = "Threat Detection"
    timestamp: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    status: AlertStatus = AlertStatus.NEW
    evidence: Dict[str, Any] = Field(default_factory=dict)
    raw_event: Optional[Dict[str, Any]] = None
    rule_ref: str = ""
    trigger_reason: str = ""
    related_finding_id: Optional[str] = None
    risk_score: int = 75
    ml_anomaly_score: Optional[float] = None
    ml_explanation: Optional[Dict[str, Any]] = None
    principal_id: Optional[str] = None
    attack_path_id: Optional[str] = None
    incident_id: Optional[str] = None
    assigned_analyst: Optional[str] = None
    timeline: List[Dict[str, Any]] = Field(default_factory=list)


class IncidentRecord(BaseModel):
    """Complete security incident lifecycle representation."""
    id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.TRIAGE
    created_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    updated_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    lead_responder: str = "Security Operations Team"
    description: str = ""
    summary: str = ""
    investigation_notes: List[Dict[str, Any]] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    linked_alert_ids: List[str] = Field(default_factory=list)
    linked_finding_ids: List[str] = Field(default_factory=list)
    linked_remediation_ids: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    containment_evidence: Optional[Dict[str, Any]] = None
    closure_reason: Optional[str] = None
    # Enriched escalation context
    escalation_evidence: Optional[Dict[str, Any]] = None
    detection_source: str = ""
    mitre_technique: str = ""
    region: str = ""
    account_id: str = ""


class RemediationTask(BaseModel):
    """Actionable remediation workflow with independent verification."""
    id: str
    related_finding_id: Optional[str] = None
    related_alert_id: Optional[str] = None
    related_incident_id: Optional[str] = None
    affected_resource: str
    severity: str = "High"
    title: str
    recommended_action: str
    technical_explanation: str = ""
    why_it_matters: str = ""
    proposed_change: Dict[str, Any] = Field(default_factory=dict)
    operational_impact: str = "Low risk to active operations in isolated sandbox."
    rollback_plan: str = "Revert to prior resource configuration and verify state."
    assigned_owner: str = "SOC Automation / Operator"
    status: RemediationStatus = RemediationStatus.PENDING
    verification_state: VerificationState = VerificationState.UNVERIFIED
    verification_evidence: Dict[str, Any] = Field(default_factory=dict)
    before_config: Optional[Any] = None
    after_config: Optional[Any] = None
    before_attack_paths_count: int = 0
    after_attack_paths_count: int = 0
    created_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    updated_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    applied_at: Optional[str] = None
    verified_at: Optional[str] = None
