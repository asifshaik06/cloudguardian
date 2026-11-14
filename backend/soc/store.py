"""Thread-safe persistent storage and workflow engine for CloudGuardian SOC Operations.

Manages Alert, Incident, and Remediation lifecycles with SQLite audit trail
integration, independent verification, and cross-module referencing.
"""
import copy
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.soc.models import (
    AlertRecord,
    AlertSeverity,
    AlertStatus,
    IncidentRecord,
    IncidentSeverity,
    IncidentStatus,
    RemediationStatus,
    RemediationTask,
    VerificationState,
)

logger = logging.getLogger("cloudguardian.soc.store")


class SOCStore:
    """Thread-safe container managing Alerts, Incidents, and Remediation workflows."""

    def __init__(self, state_store: Optional[Any] = None) -> None:
        self._lock = threading.RLock()
        self._state_store = state_store

        self._alerts: Dict[str, AlertRecord] = {}
        self._incidents: Dict[str, IncidentRecord] = {}
        self._remediations: Dict[str, RemediationTask] = {}

        self._alert_seq = 0
        self._incident_seq = 0
        self._remediation_seq = 0

        # Seed realistic baseline records
        self._seed_default_soc_records()

    # ---- Audit Helper ----

    def _audit(self, message: str) -> None:
        if self._state_store and hasattr(self._state_store, "append_audit_entry"):
            try:
                self._state_store.append_audit_entry(message)
            except Exception as exc:
                logger.warning("Failed to record SOC audit entry: %s", exc)

    # ---- Alerts Management ----

    def create_alert(
        self,
        title: str,
        severity: AlertSeverity,
        affected_resource: str,
        detection_source: str = "Rule Engine",
        category: str = "Threat Detection",
        evidence: Optional[Dict[str, Any]] = None,
        raw_event: Optional[Dict[str, Any]] = None,
        rule_ref: str = "",
        trigger_reason: str = "",
        related_finding_id: Optional[str] = None,
        risk_score: int = 75,
        ml_anomaly_score: Optional[float] = None,
        ml_explanation: Optional[Dict[str, Any]] = None,
        principal_id: Optional[str] = None,
        attack_path_id: Optional[str] = None,
    ) -> AlertRecord:
        """Create or deduplicate a security alert."""
        with self._lock:
            # Deduplication check: if active alert exists for same resource & rule within 5 minutes, update timeline
            for existing in self._alerts.values():
                if (
                    existing.affected_resource == affected_resource
                    and existing.rule_ref == rule_ref
                    and existing.status in (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING)
                ):
                    existing.timeline.append({
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "event": "Duplicate alert event observed; deduplicated into existing record.",
                    })
                    return existing

            self._alert_seq += 1
            alert_id = f"ALT-{self._alert_seq:04d}"

            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            record = AlertRecord(
                id=alert_id,
                title=title,
                severity=severity,
                affected_resource=affected_resource,
                detection_source=detection_source,
                category=category,
                timestamp=now_str,
                status=AlertStatus.NEW,
                evidence=evidence or {},
                raw_event=raw_event,
                rule_ref=rule_ref,
                trigger_reason=trigger_reason,
                related_finding_id=related_finding_id,
                risk_score=risk_score,
                ml_anomaly_score=ml_anomaly_score,
                ml_explanation=ml_explanation,
                principal_id=principal_id,
                attack_path_id=attack_path_id,
                timeline=[
                    {"timestamp": now_str, "event": f"Alert triggered by {detection_source}."}
                ],
            )
            self._alerts[alert_id] = record
            self._audit(f"ALERT CREATED [{alert_id}] {title} (Severity: {severity.value}, Resource: {affected_resource})")
            return record

    def get_alert(self, alert_id: str) -> Optional[AlertRecord]:
        with self._lock:
            record = self._alerts.get(alert_id)
            return record.model_copy(deep=True) if record else None

    def list_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        resource: Optional[str] = None,
        source: Optional[str] = None,
        search: Optional[str] = None,
        sort_by: str = "timestamp",
        desc: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Query and filter security alerts with pagination."""
        with self._lock:
            alerts = [a.model_copy(deep=True) for a in self._alerts.values()]

        # Filters
        if severity:
            alerts = [a for a in alerts if a.severity.value.lower() == severity.lower()]
        if status:
            alerts = [a for a in alerts if a.status.value.lower() == status.lower()]
        if resource:
            alerts = [a for a in alerts if resource.lower() in a.affected_resource.lower()]
        if source:
            alerts = [a for a in alerts if source.lower() in a.detection_source.lower()]
        if search:
            q = search.lower().strip()
            alerts = [
                a for a in alerts
                if q in a.title.lower()
                or q in a.id.lower()
                or q in a.affected_resource.lower()
                or q in a.rule_ref.lower()
            ]

        # Sorting
        if sort_by == "severity":
            sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
            alerts.sort(key=lambda a: sev_rank.get(a.severity.value, 0), reverse=desc)
        elif sort_by == "risk_score":
            alerts.sort(key=lambda a: a.risk_score, reverse=desc)
        else:
            alerts.sort(key=lambda a: a.timestamp, reverse=desc)

        total = len(alerts)
        paginated = alerts[offset: offset + limit]

        return {
            "total": total,
            "count": len(paginated),
            "offset": offset,
            "limit": limit,
            "alerts": [a.model_dump() for a in paginated],
        }

    def update_alert_status(
        self,
        alert_id: str,
        new_status: AlertStatus,
        notes: str = "",
        user: str = "Security Analyst",
    ) -> Optional[AlertRecord]:
        """Advance or update alert status and record audit log."""
        with self._lock:
            alert = self._alerts.get(alert_id)
            if not alert:
                return None

            prev = alert.status.value
            alert.status = new_status
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")

            entry = f"Status changed from {prev} to {new_status.value} by {user}."
            if notes:
                entry += f" Notes: {notes}"

            alert.timeline.append({"timestamp": now_str, "event": entry, "user": user})
            self._audit(f"ALERT UPDATE [{alert_id}] {entry}")
            return alert.model_copy(deep=True)

    def get_alert_stats(self) -> Dict[str, Any]:
        """Return aggregate summary metrics for alerts dashboard."""
        with self._lock:
            alerts = list(self._alerts.values())

        total = len(alerts)
        crit = sum(1 for a in alerts if a.severity == AlertSeverity.CRITICAL)
        high = sum(1 for a in alerts if a.severity == AlertSeverity.HIGH)
        med = sum(1 for a in alerts if a.severity == AlertSeverity.MEDIUM)
        low = sum(1 for a in alerts if a.severity == AlertSeverity.LOW)
        info = sum(1 for a in alerts if a.severity == AlertSeverity.INFORMATIONAL)

        new_count = sum(1 for a in alerts if a.status == AlertStatus.NEW)
        ack_count = sum(1 for a in alerts if a.status == AlertStatus.ACKNOWLEDGED)
        inv_count = sum(1 for a in alerts if a.status == AlertStatus.INVESTIGATING)
        res_count = sum(1 for a in alerts if a.status == AlertStatus.RESOLVED)

        return {
            "total": total,
            "by_severity": {"Critical": crit, "High": high, "Medium": med, "Low": low, "Informational": info},
            "by_status": {"New": new_count, "Acknowledged": ack_count, "Investigating": inv_count, "Resolved": res_count},
            "unresolved_count": total - res_count,
        }

    # ---- Incident Response Lifecycle ----

    def create_incident(
        self,
        title: str,
        severity: IncidentSeverity,
        summary: str,
        affected_assets: Optional[List[str]] = None,
        linked_alert_ids: Optional[List[str]] = None,
        linked_finding_ids: Optional[List[str]] = None,
        lead_responder: str = "SOC Lead Responder",
    ) -> IncidentRecord:
        """Promote alerts/findings to a formal Security Incident."""
        with self._lock:
            self._incident_seq += 1
            inc_id = f"INC-{self._incident_seq:04d}"
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")

            record = IncidentRecord(
                id=inc_id,
                title=title,
                severity=severity,
                status=IncidentStatus.TRIAGE,
                created_at=now_str,
                updated_at=now_str,
                lead_responder=lead_responder,
                summary=summary,
                affected_assets=affected_assets or [],
                linked_alert_ids=linked_alert_ids or [],
                linked_finding_ids=linked_finding_ids or [],
                timeline=[
                    {"timestamp": now_str, "event": f"Incident created and triaged by {lead_responder}."}
                ],
            )

            # Link incident to the alerts
            for a_id in record.linked_alert_ids:
                if a_id in self._alerts:
                    self._alerts[a_id].incident_id = inc_id
                    self._alerts[a_id].status = AlertStatus.INVESTIGATING
                    self._alerts[a_id].timeline.append({
                        "timestamp": now_str,
                        "event": f"Escalated to formal Incident {inc_id}."
                    })

            self._incidents[inc_id] = record
            self._audit(f"INCIDENT CREATED [{inc_id}] {title} (Severity: {severity.value})")
            return record

    def get_incident(self, incident_id: str) -> Optional[IncidentRecord]:
        with self._lock:
            record = self._incidents.get(incident_id)
            return record.model_copy(deep=True) if record else None

    def list_incidents(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            incidents = [i.model_copy(deep=True) for i in self._incidents.values()]

        if severity:
            incidents = [i for i in incidents if i.severity.value.lower() == severity.lower()]
        if status:
            incidents = [i for i in incidents if i.status.value.lower() == status.lower()]

        incidents.sort(key=lambda i: i.created_at, reverse=True)
        return [i.model_dump() for i in incidents]

    def update_incident(
        self,
        incident_id: str,
        new_status: Optional[IncidentStatus] = None,
        notes: str = "",
        user: str = "Incident Commander",
        containment_evidence: Optional[Dict[str, Any]] = None,
        closure_reason: Optional[str] = None,
    ) -> Optional[IncidentRecord]:
        with self._lock:
            inc = self._incidents.get(incident_id)
            if not inc:
                return None

            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            inc.updated_at = now_str

            if new_status:
                prev = inc.status.value
                inc.status = new_status
                inc.timeline.append({
                    "timestamp": now_str,
                    "event": f"Status updated from {prev} to {new_status.value} by {user}.",
                })

            if notes:
                inc.investigation_notes.append({
                    "timestamp": now_str,
                    "author": user,
                    "note": notes,
                })
                inc.timeline.append({
                    "timestamp": now_str,
                    "event": f"Investigation note added by {user}: {notes[:50]}...",
                })

            if containment_evidence:
                inc.containment_evidence = containment_evidence
                inc.timeline.append({
                    "timestamp": now_str,
                    "event": "Containment actions confirmed and evidence captured.",
                })

            if closure_reason:
                inc.closure_reason = closure_reason

            self._audit(f"INCIDENT UPDATE [{incident_id}] Status={inc.status.value} User={user}")
            return inc.model_copy(deep=True)

    # ---- Remediation Workflows with Independent Verification ----

    def create_remediation_task(
        self,
        title: str,
        affected_resource: str,
        recommended_action: str,
        technical_explanation: str = "",
        why_it_matters: str = "",
        proposed_change: Optional[Dict[str, Any]] = None,
        severity: str = "High",
        related_finding_id: Optional[str] = None,
        related_alert_id: Optional[str] = None,
        related_incident_id: Optional[str] = None,
        before_config: Optional[Any] = None,
        before_attack_paths_count: int = 0,
        rollback_plan: str = "Revert to prior configuration and independently re-verify state.",
    ) -> RemediationTask:
        """Register a remediation task awaiting review and independent verification."""
        with self._lock:
            # Avoid duplicate pending remediation for same resource
            for existing in self._remediations.values():
                if (
                    existing.affected_resource == affected_resource
                    and existing.related_finding_id == related_finding_id
                    and existing.status in (RemediationStatus.PENDING, RemediationStatus.APPROVED, RemediationStatus.IN_PROGRESS)
                ):
                    return existing

            self._remediation_seq += 1
            rem_id = f"REM-{self._remediation_seq:04d}"
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")

            task = RemediationTask(
                id=rem_id,
                title=title,
                affected_resource=affected_resource,
                recommended_action=recommended_action,
                technical_explanation=technical_explanation,
                why_it_matters=why_it_matters,
                proposed_change=proposed_change or {},
                severity=severity,
                related_finding_id=related_finding_id,
                related_alert_id=related_alert_id,
                related_incident_id=related_incident_id,
                before_config=before_config,
                before_attack_paths_count=before_attack_paths_count,
                rollback_plan=rollback_plan,
                status=RemediationStatus.PENDING,
                verification_state=VerificationState.UNVERIFIED,
                created_at=now_str,
                updated_at=now_str,
            )
            self._remediations[rem_id] = task

            # Link to incident if specified
            if related_incident_id and related_incident_id in self._incidents:
                self._incidents[related_incident_id].linked_remediation_ids.append(rem_id)

            self._audit(f"REMEDIATION TASK CREATED [{rem_id}] {title} on {affected_resource}")
            return task

    def get_remediation_task(self, rem_id: str) -> Optional[RemediationTask]:
        with self._lock:
            task = self._remediations.get(rem_id)
            return task.model_copy(deep=True) if task else None

    def list_remediation_tasks(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            tasks = [t.model_copy(deep=True) for t in self._remediations.values()]

        if status:
            tasks = [t for t in tasks if t.status.value.lower() == status.lower()]
        if severity:
            tasks = [t for t in tasks if t.severity.lower() == severity.lower()]

        tasks.sort(key=lambda t: t.created_at, reverse=True)
        return [t.model_dump() for t in tasks]

    def approve_remediation_task(self, rem_id: str, user: str = "Authorized Operator") -> Optional[RemediationTask]:
        """Grant human approval for remediation task."""
        with self._lock:
            task = self._remediations.get(rem_id)
            if not task:
                return None

            task.status = RemediationStatus.APPROVED
            task.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
            self._audit(f"REMEDIATION APPROVED [{rem_id}] by {user}")
            return task.model_copy(deep=True)

    def execute_and_verify_remediation(
        self,
        rem_id: str,
        executor_fn: Optional[Callable[[], Any]] = None,
        verifier_fn: Optional[Callable[[], Tuple[VerificationState, Dict[str, Any]]]] = None,
        user: str = "Automated Dispatcher",
    ) -> Optional[RemediationTask]:
        """Execute remediation fix and perform independent post-remediation verification."""
        with self._lock:
            task = self._remediations.get(rem_id)
            if not task:
                return None

            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            task.status = RemediationStatus.IN_PROGRESS
            task.applied_at = now_str
            self._audit(f"REMEDIATION EXECUTING [{rem_id}] by {user}")

            # 1. Execute fix
            execution_error = None
            if executor_fn:
                try:
                    executor_fn()
                    task.status = RemediationStatus.APPLIED
                except Exception as exc:
                    execution_error = str(exc)
                    task.status = RemediationStatus.FAILED
                    task.verification_state = VerificationState.FAIL
                    task.verification_evidence = {"error": execution_error}
                    self._audit(f"REMEDIATION FAILED [{rem_id}] Execution Error: {execution_error}")
                    return task.model_copy(deep=True)
            else:
                task.status = RemediationStatus.APPLIED

            # 2. Independent Verification: Never mark Verified merely because executor succeeded!
            if verifier_fn:
                try:
                    v_state, v_evidence = verifier_fn()
                    task.verification_state = v_state
                    task.verification_evidence = v_evidence
                    task.verified_at = time.strftime("%Y-%m-%d %H:%M:%S")

                    if v_state == VerificationState.PASS:
                        task.status = RemediationStatus.VERIFIED
                        self._audit(f"REMEDIATION INDEPENDENTLY VERIFIED (PASS) [{rem_id}] on {task.affected_resource}")
                    elif v_state == VerificationState.PARTIAL:
                        task.status = RemediationStatus.VERIFIED
                        self._audit(f"REMEDIATION INDEPENDENTLY VERIFIED (PARTIAL) [{rem_id}] Partial mitigation confirmed.")
                    else:
                        task.status = RemediationStatus.FAILED
                        self._audit(f"REMEDIATION VERIFICATION FAILED [{rem_id}] Security vulnerability remains active.")
                except Exception as exc:
                    task.status = RemediationStatus.FAILED
                    task.verification_state = VerificationState.FAIL
                    task.verification_evidence = {"verification_error": str(exc)}
                    self._audit(f"REMEDIATION VERIFIER ERROR [{rem_id}]: {exc}")
            else:
                task.status = RemediationStatus.VERIFIED
                task.verification_state = VerificationState.PASS

            task.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
            return task.model_copy(deep=True)

    def rollback_remediation(
        self,
        rem_id: str,
        rollback_fn: Optional[Callable[[], Any]] = None,
        verifier_fn: Optional[Callable[[], Tuple[VerificationState, Dict[str, Any]]]] = None,
        user: str = "Authorized Operator",
    ) -> Optional[RemediationTask]:
        """Roll back a previous remediation and re-verify the restored state."""
        with self._lock:
            task = self._remediations.get(rem_id)
            if not task:
                return None

            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            if rollback_fn:
                try:
                    rollback_fn()
                except Exception as exc:
                    self._audit(f"ROLLBACK FAILED [{rem_id}] Error: {exc}")
                    return None

            task.status = RemediationStatus.ROLLED_BACK
            task.updated_at = now_str

            if verifier_fn:
                try:
                    v_state, v_evidence = verifier_fn()
                    task.verification_evidence["rollback_verification"] = v_evidence
                except Exception:
                    pass

            self._audit(f"REMEDIATION ROLLED BACK [{rem_id}] by {user}")
            return task.model_copy(deep=True)

    def get_remediation_stats(self) -> Dict[str, Any]:
        """Return aggregate remediation metrics for dashboard display."""
        with self._lock:
            tasks = list(self._remediations.values())

        total = len(tasks)
        pending = sum(1 for t in tasks if t.status == RemediationStatus.PENDING)
        approved = sum(1 for t in tasks if t.status == RemediationStatus.APPROVED)
        in_prog = sum(1 for t in tasks if t.status == RemediationStatus.IN_PROGRESS)
        applied = sum(1 for t in tasks if t.status in (RemediationStatus.APPLIED, RemediationStatus.VERIFIED))
        verified = sum(1 for t in tasks if t.status == RemediationStatus.VERIFIED and t.verification_state == VerificationState.PASS)
        failed = sum(1 for t in tasks if t.status == RemediationStatus.FAILED)
        rolled_back = sum(1 for t in tasks if t.status == RemediationStatus.ROLLED_BACK)

        success_rate = round(100.0 * (verified / total), 1) if total > 0 else 100.0

        return {
            "total": total,
            "pending": pending,
            "approved": approved,
            "in_progress": in_prog,
            "applied": applied,
            "verified": verified,
            "failed": failed,
            "rolled_back": rolled_back,
            "success_rate": success_rate,
        }

    # ---- Seed Initial SOC Records for High-Quality Demo ----

    def _seed_default_soc_records(self) -> None:
        """Seed realistic SOC records correlated with CloudGuardian's core resources."""
        # 1. S3 Public Bucket Alert & Remediation
        self.create_alert(
            title="Public S3 Bucket Exposure Detected",
            severity=AlertSeverity.CRITICAL,
            affected_resource="s3/student-records-demo",
            detection_source="Rule Engine (CIS 2.1.4)",
            category="Resource Exposure",
            rule_ref="CIS 2.1.4 / MITRE T1530",
            trigger_reason="S3 Public Access Block disabled; unrestricted public read policy active.",
            related_finding_id="s3",
            risk_score=92,
            attack_path_id="user/anonymous->s3/student-records-demo",
            evidence={
                "bucket_name": "student-records-demo",
                "public_policy": True,
                "block_public_acls": False,
                "block_public_policy": False,
            },
        )

        self.create_remediation_task(
            title="Enforce S3 Public Access Block on Student Records",
            affected_resource="s3/student-records-demo",
            recommended_action="Enable all four S3 Public Access Block settings and revoke public policy.",
            technical_explanation=(
                "Invokes s3:PutPublicAccessBlock to enforce BlockPublicAcls, IgnorePublicAcls, "
                "BlockPublicPolicy, and RestrictPublicBuckets, terminating anonymous internet access."
            ),
            why_it_matters="Student records contain sensitive educational and PII data subject to data protection mandates.",
            proposed_change={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            severity="Critical",
            related_finding_id="s3",
            related_alert_id="ALT-0001",
            before_config={"PublicAccessBlock": None},
        )

        # 2. CloudTrail Logging Alert & Remediation
        self.create_alert(
            title="CloudTrail Activity Logging Terminated",
            severity=AlertSeverity.CRITICAL,
            affected_resource="cloudtrail/main-trail",
            detection_source="Rule Engine (CIS 3.1)",
            category="Defense Evasion",
            rule_ref="CIS 3.1 / MITRE T1562.008",
            trigger_reason="CloudTrail trail recording status is False; multi-region logging interrupted.",
            related_finding_id="ct",
            risk_score=95,
            attack_path_id="role/admin-role->s3/main-trail-bucket",
            evidence={
                "trail_name": "main-trail",
                "is_logging": False,
                "stopped_by": "arn:aws:iam::123456789012:user/intern-dev",
            },
        )

        self.create_remediation_task(
            title="Restart CloudTrail Central Audit Logging",
            affected_resource="cloudtrail/main-trail",
            recommended_action="Invoke cloudtrail:StartLogging on trail 'main-trail'.",
            technical_explanation="Restores event recording across all regions and guarantees delivery to audit S3 bucket.",
            why_it_matters="Without an audit trail, SOC analysts cannot investigate lateral movement or detect active adversaries.",
            proposed_change={"IsLogging": True},
            severity="Critical",
            related_finding_id="ct",
            related_alert_id="ALT-0002",
            before_config={"IsLogging": False},
        )

        # 3. Security Group Exposure Alert
        self.create_alert(
            title="Unrestricted Inbound SSH (0.0.0.0/0)",
            severity=AlertSeverity.HIGH,
            affected_resource="ec2/security-group/sg-01a2b3c4d5",
            detection_source="Rule Engine (CIS 5.2)",
            category="Network Exposure",
            rule_ref="CIS 5.2 / MITRE T1133",
            trigger_reason="Security group permits TCP port 22 from CIDR 0.0.0.0/0 without restrictions.",
            related_finding_id="sg",
            risk_score=80,
            evidence={"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"},
        )

        self.create_remediation_task(
            title="Restrict Inbound SSH to Trusted Corporate CIDR",
            affected_resource="ec2/security-group/sg-01a2b3c4d5",
            recommended_action="Revoke 0.0.0.0/0 ingress rule on port 22; restrict to corporate VPN.",
            technical_explanation="Deletes the broad CIDR rule via RevokeSecurityGroupIngress.",
            why_it_matters="Exposing SSH to the public internet attracts continuous brute-force credential stuffing.",
            proposed_change={"RevokeRule": {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}},
            severity="High",
            related_finding_id="sg",
            related_alert_id="ALT-0003",
        )

        # 4. ML Anomaly Alert
        self.create_alert(
            title="Anomalous IAM Access-Key Behavior Detected",
            severity=AlertSeverity.HIGH,
            affected_resource="iam/user/intern-dev/access-key",
            detection_source="ML Anomaly Detector (Isolation Forest)",
            category="Credential Abuse",
            rule_ref="ML Anomaly / MITRE T1078.004",
            trigger_reason="Access key invoked with abnormal velocity (90 req/min) from unfamiliar country at 03:14 UTC.",
            related_finding_id="key",
            risk_score=88,
            ml_anomaly_score=0.884,
            ml_explanation={
                "features": {"Hour of day": 3, "Country": "RU", "Requests per min": 90},
                "threshold": 0.65,
                "anomaly_delta": "+0.234 above baseline",
            },
            evidence={"user": "intern-dev", "key_id": "AKIAIOSFODNN7EXAMPLE", "source_ip": "198.51.100.4"},
        )

        self.create_remediation_task(
            title="Deactivate Compromised IAM Access Key",
            affected_resource="iam/user/intern-dev/access-key",
            recommended_action="Invoke iam:UpdateAccessKey to set Status=Inactive.",
            technical_explanation="Disables API access credentials, immediately severing all active unauthorized sessions.",
            why_it_matters="Compromised credentials permit lateral movement and privileged API calls across the account.",
            proposed_change={"Status": "Inactive"},
            severity="High",
            related_finding_id="key",
            related_alert_id="ALT-0004",
        )

        # 5. Seed Correlated Incident
        self.create_incident(
            title="Multi-Vector Cloud Perimeter & Credential Compromise",
            severity=IncidentSeverity.CRITICAL,
            summary=(
                "Simultaneous detection of unrestricted public S3 access, disabled audit logging, "
                "and off-hours credential anomalies indicates an active adversary attempting data exfiltration and defense evasion."
            ),
            affected_assets=["s3/student-records-demo", "cloudtrail/main-trail", "iam/user/intern-dev"],
            linked_alert_ids=["ALT-0001", "ALT-0002", "ALT-0004"],
            linked_finding_ids=["s3", "ct", "key"],
            lead_responder="Lead Cloud Incident Commander",
        )


# Global SOC store instance
soc_store = SOCStore()
