"""Authoritative Security Posture Calculation Engine for ThreatGuard.

Computes a single authoritative Security Posture Score (0-100%) based on:
1. Actual cloud resource verification checks (R[k]["check"]()).
2. StateStore finding lifecycles (status, verified).
3. SOC remediation task verification states (PASS, FAIL, PENDING, ROLLED_BACK).
4. Severity-weighted penalties.
"""
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("threatguard.posture")

# Monitored rules severity weights (sum strictly to 100)
# CIS 3.1 CloudTrail Logging: Critical (30 pts)
# CIS 2.1.4 S3 Public Access Block: High (25 pts)
# CIS 5.2 Security Group SSH 0.0.0.0/0: High (25 pts)
# ML Anomaly IAM Compromised Credential: High (20 pts)
CORE_WEIGHTS: Dict[str, int] = {
    "ct": 30,
    "s3": 25,
    "sg": 25,
    "key": 20,
}

DEFAULT_SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 30,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 10,
}


def compute_posture_score(
    rules: Dict[str, Dict[str, Any]],
    state_store: Optional[Any] = None,
    soc_store: Optional[Any] = None,
) -> int:
    """Calculate the authoritative system security posture score (0 - 100%).

    Requirements:
    1. Successfully remediated and independently verified findings must stop contributing their resolved risk.
    2. Failed, pending or unverified remediation must not be treated as resolved.
    3. New findings must affect the score according to their severity and risk.
    4. A rollback must restore the associated unresolved risk when appropriate.
    5. Suppressed/rejected findings must not automatically be treated as remediated.
    6. Unsupported or unverified security states must not be silently treated as safe.
    7. When every applicable security finding is genuinely resolved and independently verified,
       and no other unresolved risk remains, the posture score reaches exactly 100%.
    """
    total_penalty = 0

    # Build lookup of SOC remediation tasks by finding id
    soc_remediations: Dict[str, Any] = {}
    if soc_store and hasattr(soc_store, "_remediations"):
        try:
            with soc_store._lock:
                for rem in soc_store._remediations.values():
                    if rem.related_finding_id:
                        soc_remediations[rem.related_finding_id] = rem
        except Exception as exc:
            logger.warning("Error reading SOC remediations for posture score: %s", exc)

    # Evaluate each core registered rule
    for k, r in rules.items():
        weight = CORE_WEIGHTS.get(k)
        if weight is None:
            sev_str = str(r.get("sev", "HIGH")).upper()
            weight = DEFAULT_SEVERITY_WEIGHTS.get(sev_str, 20)

        # 1. Independent cloud check
        check_ok = False
        try:
            check_ok = bool(r["check"]())
        except Exception as exc:
            logger.warning("Cloud check exception for %s: %s", k, exc)
            check_ok = False

        # 2. Finding record from state store
        finding = None
        if state_store and hasattr(state_store, "get_finding"):
            finding = state_store.get_finding(k)

        # 3. Correlated SOC remediation task
        rem_task = soc_remediations.get(k)

        # Determine whether risk is resolved and verified
        risk_active = False

        if not check_ok:
            # Cloud state is definitely vulnerable/failing check
            risk_active = True
        else:
            # Cloud check passed. Now verify workflow lifecycle integrity:
            if finding is not None:
                # If finding exists, it must be marked fixed and verified
                if finding.get("status") != "fixed" or not finding.get("verified"):
                    risk_active = True

            if rem_task is not None:
                # If a remediation task exists, it must be VERIFIED with PASS
                from backend.soc.models import RemediationStatus, VerificationState
                if (
                    rem_task.status != RemediationStatus.VERIFIED
                    or rem_task.verification_state != VerificationState.PASS
                ):
                    risk_active = True

        if risk_active:
            total_penalty += weight

    # Deduct penalty, clamped between 0 and 100
    score = max(0, min(100, 100 - total_penalty))
    return score
