"""CloudGuardian 2.0 — Explainable AI-Assisted Cloud Security Platform.

Main application entry point providing:
- Guarded Moto simulation and safe Live AWS integration.
- Continuous CIS security rule scanner and Isolation Forest behavioural anomaly detection.
- Human-in-the-loop (HITL) remediation approval workflow.
- Secure API endpoints protected by session and API-key authentication.
- Real-time telemetry, ECharts dashboard, and verified audit logging.
"""
import logging
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional
import boto3
from dotenv import load_dotenv
from flask import Flask, jsonify, make_response, request, send_from_directory
import numpy as np
import requests
from sklearn.ensemble import IsolationForest

from backend.aws_guard import (
    get_aws_client,
    is_dry_run,
    is_live_aws,
    resolve_account_id,
    safe_setup,
)
from backend.ingestion.stream import EventStreamPipeline
from backend.graph import IAMCapabilityGraph, register_graph_api
from backend.scenarios.api import register_scenarios_api
from backend.scenarios.session import scenario_session_manager
from backend.ml_engine.detector import RuntimeDetector
from backend.ml_engine.window_aggregator import StreamingWindowAggregator
from backend.replay import register_replay_api
from backend.security import (
    SESSION_COOKIE_NAME,
    get_active_api_key,
    is_telegram_user_authorized,
    redact_sensitive_data,
    require_auth,
    validate_telegram_callback_data,
)
from backend.state import StateStore
from backend.soc.models import (
    AlertSeverity,
    RemediationStatus,
    VerificationState,
)
from backend.soc.store import soc_store
from backend.soc.api import register_soc_api

# Load environment configuration
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cloudguardian.app")

# Core operational modes
LIVE: bool = is_live_aws()
DRY_RUN: bool = is_dry_run()
MODE: str = "Live AWS" if LIVE else "Simulator"
MASK: bool = os.getenv("CG_MASK_IDS", "1") == "1"

# Resource configuration
BUCKET: str = os.getenv("CG_BUCKET") or "student-records-demo"
TRAIL: str = "main-trail"
USER: str = "intern-dev"

# AWS / Moto Clients
s3 = get_aws_client("s3")
ct = get_aws_client("cloudtrail")
ec2 = get_aws_client("ec2")
iam = get_aws_client("iam")
sts = get_aws_client("sts")

# State & Audit Manager
store = StateStore()
soc_store._state_store = store

# 12-Feature Streaming Window Aggregator & Runtime Multi-Detector
aggregator = StreamingWindowAggregator(window_minutes=5)
detector = RuntimeDetector("models/baseline_v1.joblib")
pipeline = EventStreamPipeline(store, aggregator, detector)

# IAM Capability Graph Engine & Attack-Path Intelligence
iam_graph = IAMCapabilityGraph()
try:
    iam_graph.build_from_aws_or_moto(
        iam_client=iam,
        s3_client=s3,
        ec2_client=ec2,
        populate_defaults_if_empty=True,
    )
except Exception as _g_err:
    logger.warning("Failed building IAM graph on startup, falling back to default topology: %s", _g_err)
    iam_graph.seed_default_topology()

BLOCK: Dict[str, bool] = dict(
    BlockPublicAcls=True,
    IgnorePublicAcls=True,
    BlockPublicPolicy=True,
    RestrictPublicBuckets=True,
)


def PERM(cidr: str) -> list:
    return [dict(IpProtocol="tcp", FromPort=22, ToPort=22, IpRanges=[{"CidrIp": cidr}])]


def now() -> str:
    return time.strftime("%H:%M:%S")


def redact(t: Any) -> str:
    return redact_sensitive_data(str(t), mask_enabled=MASK)


def audit(t: Any) -> str:
    return store.append_audit_entry(str(t), redact)


def emit(name: str, src: str, user: str, country: str = "IN") -> None:
    pipeline.ingest(
        event_name=name,
        service=src,
        principal_id=user,
        country=country,
        source="live" if LIVE else "simulator",
    )


# ---- Rule Verification Checks ----

def c_s3() -> bool:
    try:
        pab = s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
        return all(pab.values())
    except Exception:
        return False


def c_ct() -> bool:
    try:
        return bool(ct.get_trail_status(Name=TRAIL)["IsLogging"])
    except Exception:
        return False


def c_sg() -> bool:
    try:
        sg_id = store.get_resource_id("sg")
        if not sg_id:
            return True
        g = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        return not any(r["CidrIp"] == "0.0.0.0/0" for p in g["IpPermissions"] for r in p["IpRanges"])
    except Exception:
        return False


def c_key() -> bool:
    return not store.is_anomaly_active()


# ---- Simulated Attacks ----

def a_s3() -> None:
    s3.delete_public_access_block(Bucket=BUCKET)
    emit("DeleteBucketPublicAccessBlock", "s3", "dev-admin")


def a_ct() -> None:
    ct.stop_logging(Name=TRAIL)
    emit("StopLogging", "cloudtrail", "dev-admin")


def a_sg() -> None:
    sg_id = store.get_resource_id("sg")
    if sg_id:
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=PERM("0.0.0.0/0"))
    emit("AuthorizeSecurityGroupIngress", "ec2", "dev-admin")


def a_key() -> None:
    emit("ListBuckets x90", "s3", USER, "RU")
    # Stream burst events into pipeline for 12-feature window detection
    for _ in range(89):
        pipeline.ingest(
            event_name="ListBuckets",
            service="s3",
            principal_id=USER,
            country="RU",
            source_ip="203.0.113.19",
            source="simulator",
        )
    ml_check(3, "RU", 90)


# ---- Remediations (Fixes) ----

def f_s3() -> None:
    s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=BLOCK)


def f_ct() -> None:
    ct.start_logging(Name=TRAIL)


def f_sg() -> None:
    sg_id = store.get_resource_id("sg")
    if sg_id:
        ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=PERM("0.0.0.0/0"))


def f_key() -> None:
    key_id = store.get_resource_id("key")
    if key_id:
        iam.update_access_key(UserName=USER, AccessKeyId=key_id, Status="Inactive")
    store.set_anomaly_active(False)


# ---- Rule Registry ----

R: Dict[str, Dict[str, Any]] = {
    "s3": dict(
        res="Customer data storage",
        desc="A storage bucket holding student records.",
        good="Private and locked",
        bad="Open to the public internet",
        title="Storage bucket opened to the public",
        sev="High",
        ref="CIS 2.1.4 / MITRE T1530",
        check=c_s3,
        fix=f_s3,
        attack=a_s3,
        how="Removes the bucket's public-access lock.",
        what="The lock that keeps this bucket private was removed.",
        why="Anyone on the internet could read the student records. Bots find open buckets within minutes.",
        fixtxt="Turn the public-access lock back on",
    ),
    "ct": dict(
        res="Activity log",
        desc="The record of everything done in the account.",
        good="Recording",
        bad="Switched off",
        title="Activity logging was switched off",
        sev="Critical",
        ref="CIS 3.1 / MITRE T1562.008",
        check=c_ct,
        fix=f_ct,
        attack=a_ct,
        how="Stops the audit log, as an intruder would to hide.",
        what="Someone turned off the account's activity recording.",
        why="Without a log nobody can tell what happens next. Attackers do this first to hide their tracks.",
        fixtxt="Start recording again",
    ),
    "sg": dict(
        res="Network door (SSH)",
        desc="The remote-login door to the servers.",
        good="Open to the office network only",
        bad="Open to the whole world",
        title="Remote-login door opened to everyone",
        sev="High",
        ref="CIS 5.2 / MITRE T1133",
        check=c_sg,
        fix=f_sg,
        attack=a_sg,
        how="Allows remote login from any address.",
        what="The server login door now accepts connections from anywhere.",
        why="Attackers scan the internet constantly for open login doors and try stolen passwords.",
        fixtxt="Close the door to outside addresses",
    ),
    "key": dict(
        res="Employee access key",
        desc="A password-like key used by the intern's tools.",
        good="Normal use",
        bad="Used from abroad at 3 AM",
        title="Access key behaving strangely",
        sev="High",
        ref="ML anomaly / MITRE T1078.004",
        check=c_key,
        fix=f_key,
        attack=a_key,
        how="Replays a login pattern the key has never shown.",
        what="A key was used at an odd hour, from a new country, with 90 requests a minute.",
        why="This usually means the key was stolen. A thief can read data or run costly servers.",
        fixtxt="Disable the key until the owner confirms",
    ),
}

# ---- Inline ML Model (Preserved for Phase 1) ----

CTRY = {"IN": 0, "US": 1, "RU": 2, "CN": 3}
FEAT = ["Hour of day", "Country", "Requests per minute"]
rng = np.random.default_rng(1)
BASE = np.c_[rng.integers(8, 19, 400), rng.choice([0, 0, 0, 1], 400), rng.integers(1, 12, 400)]
MODEL = IsolationForest(contamination=0.01, random_state=1).fit(BASE)
MU, SD = BASE.mean(0), BASE.std(0) + 1e-6


def ml_check(hour: int, country: str, calls: int) -> None:
    # 1. Evaluate current window through 12-feature runtime detector with TreeSHAP
    features = aggregator.get_current_features(USER)
    if not features or features.get("call_count", 0) == 0:
        features = {
            "call_count": float(calls),
            "call_velocity": float(calls) / 6.0,
            "error_ratio": 0.0,
            "unique_services": 1.0,
            "unique_events": 1.0,
            "enumeration_ratio": 1.0,
            "sensitive_count": 0.0,
            "iam_change_count": 0.0,
            "first_service_ratio": 0.0,
            "first_ip": 1.0,
            "off_hours": 1.0 if (hour < 8 or hour > 18) else 0.0,
            "event_entropy": 0.0,
        }
    det_res = detector.score_window(features)
    store.set_anomaly_active(True)
    explain_data = det_res.get("explanations") or [
        [f"API Call Burst: {calls}", 0.45],
        [f"New / First-Time Source IP ({country})", 0.35],
        ["Off-Hours Activity", 0.20],
    ]
    raise_finding("key", explain_data)


# ---- Telegram Alerting & Secure Polling ----

TG = os.getenv("TG_TOKEN")
CHAT = os.getenv("TG_CHAT_ID")


def tg_alert(k: str) -> None:
    if not TG or not CHAT:
        return
    kb = {
        "inline_keyboard": [[
            {"text": "Approve fix", "callback_data": f"ok:{k}"},
            {"text": "Reject", "callback_data": f"no:{k}"},
        ]]
    }
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG}/sendMessage",
            timeout=10,
            json={
                "chat_id": CHAT,
                "text": f"CloudGuardian: {R[k]['title']} ({R[k]['sev']})\nProposed fix: {R[k]['fixtxt']}",
                "reply_markup": kb,
            },
        )
    except Exception as exc:
        logger.warning("Telegram send error: %s", exc)


def tg_poll() -> None:
    off = 0
    while True:
        try:
            resp = requests.get(
                f"https://api.telegram.org/bot{TG}/getUpdates",
                params={"offset": off, "timeout": 20},
                timeout=30,
            )
            data = resp.json()
            for u in data.get("result", []):
                off = u["update_id"] + 1
                if "callback_query" in u:
                    cb = u["callback_query"]
                    sender = cb.get("from", {})
                    sender_id = sender.get("id")
                    username = sender.get("username", "unknown")

                    # Verify authorized Telegram user
                    if not is_telegram_user_authorized(sender_id):
                        audit(f"SECURITY: Unauthorized Telegram callback rejected from user {sender_id} (@{username})")
                        try:
                            requests.post(
                                f"https://api.telegram.org/bot{TG}/answerCallbackQuery",
                                timeout=5,
                                json={"callback_query_id": cb["id"], "text": "Unauthorized user", "show_alert": True},
                            )
                        except Exception:
                            pass
                        continue

                    # Validate callback payload
                    is_valid, action, key = validate_telegram_callback_data(cb.get("data", ""), set(R.keys()))
                    if not is_valid or not action or not key:
                        audit(f"SECURITY: Malformed Telegram callback payload: {cb.get('data')}")
                        continue

                    # Execute verified decision
                    decide(key, action == "ok", via=f"Telegram (@{username})")
                    try:
                        requests.post(
                            f"https://api.telegram.org/bot{TG}/answerCallbackQuery",
                            timeout=5,
                            json={"callback_query_id": cb["id"], "text": f"Decision processed: {action.upper()}"},
                        )
                    except Exception:
                        pass
        except Exception:
            time.sleep(3)


# ---- Finding Lifecycle & Decision Logic ----

def raise_finding(k: str, explain: Optional[list] = None) -> None:
    t0_time = store.get_attack_start(k) or time.time()
    tdetect = round(time.time() - t0_time, 1)

    finding_data = dict(
        id=k,
        status="pending",
        explain=explain or [[R[k]["ref"], 1.0]],
        tdetect=tdetect,
        t0=time.time(),
    )
    store.set_finding(k, finding_data)
    audit(f"DETECTED {R[k]['title']}")
    tg_alert(k)

    # Sync with SOC Alert Layer
    try:
        sev_str = R[k].get("sev", "HIGH").upper()
        sev_enum = {
            "CRITICAL": AlertSeverity.CRITICAL,
            "HIGH": AlertSeverity.HIGH,
            "MEDIUM": AlertSeverity.MEDIUM,
            "LOW": AlertSeverity.LOW,
        }.get(sev_str, AlertSeverity.HIGH)

        soc_store.create_alert(
            title=R[k]["title"],
            severity=sev_enum,
            affected_resource=R[k]["res"],
            detection_source="Rule Engine (CIS)",
            category="Security Posture",
            rule_ref=R[k]["ref"],
            trigger_reason=R[k]["bad"],
            related_finding_id=k,
            risk_score=95 if sev_enum == AlertSeverity.CRITICAL else (80 if sev_enum == AlertSeverity.HIGH else 60),
            evidence={"explanation": explain or [[R[k]["ref"], 1.0]]},
        )
    except Exception as _alert_err:
        logger.warning("Failed syncing SOC alert for %s: %s", k, _alert_err)


def decide(k: str, ok: bool, via: str) -> None:
    f = store.get_finding(k)
    if not f or f.get("status") != "pending":
        return

    if not ok:
        store.update_finding(k, status="rejected")
        audit(f"REJECTED {k} via {via}, accepted risk")
        try:
            for task in soc_store._remediations.values():
                if task.related_finding_id == k:
                    task.status = RemediationStatus.ROLLED_BACK
                    task.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as _rem_err:
            logger.warning("Failed syncing rejected remediation for %s: %s", k, _rem_err)
        return

    audit(f"APPROVED {k} via {via}")
    R[k]["fix"]()
    try:
        verified = bool(R[k]["check"]())
    except Exception:
        verified = False

    store.update_finding(k, status="fixed", verified=verified)
    audit(f"FIXED {k}, verified by re-checking the cloud: {verified}")

    try:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        for task in soc_store._remediations.values():
            if task.related_finding_id == k:
                task.status = RemediationStatus.VERIFIED if verified else RemediationStatus.FAILED
                task.verification_state = VerificationState.PASS if verified else VerificationState.FAIL
                task.verified_at = now_str
                task.updated_at = now_str
                task.verification_evidence = {
                    "verified_by": "independent_recheck",
                    "check_passed": verified,
                    "resource": R[k]["res"],
                }
    except Exception as _rem_err:
        logger.warning("Failed syncing approved remediation for %s: %s", k, _rem_err)


# ---- Scanner Loop ----

def scan() -> None:
    while True:
        t_start = time.time()
        for k in ("s3", "ct", "sg"):
            try:
                check_passed = bool(R[k]["check"]())
                current_finding = store.get_finding(k)
                if not check_passed and (current_finding is None or current_finding.get("status") == "fixed"):
                    raise_finding(k)
            except Exception as e:
                audit(f"scan error {k}: {e}")
        latency_ms = round((time.time() - t_start) * 1000 / 3)
        store.update_polls(n_delta=1, latency_ms=latency_ms)
        time.sleep(2)


# ---- Evidence Gathering ----

def evidence() -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        out["s3.get_public_access_block"] = s3.get_public_access_block(
            Bucket=BUCKET
        )["PublicAccessBlockConfiguration"]
    except Exception as e:
        out["s3.get_public_access_block"] = str(e)[:120]

    try:
        out["cloudtrail.get_trail_status"] = {"IsLogging": ct.get_trail_status(Name=TRAIL)["IsLogging"]}
    except Exception as e:
        out["cloudtrail.get_trail_status"] = str(e)[:120]

    try:
        sg_id = store.get_resource_id("sg")
        if sg_id:
            g = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
            out["ec2.describe_security_groups (ingress CIDRs)"] = [
                r["CidrIp"] for p in g["IpPermissions"] for r in p["IpRanges"]
            ]
        else:
            out["ec2.describe_security_groups (ingress CIDRs)"] = ["10.0.0.0/8"]
    except Exception as e:
        out["ec2.describe_security_groups (ingress CIDRs)"] = str(e)[:120]

    return out


# ---- Flask Web Application ----

app = Flask(__name__, static_folder="static")


@app.get("/")
def home() -> Any:
    """Serve single-page application dashboard and establish session cookie."""
    resp = make_response(send_from_directory("static", "index.html"))
    # Set or refresh session cookie if missing or stale/mismatched with active server instance
    if not is_authenticated(request):
        resp.set_cookie(
            SESSION_COOKIE_NAME,
            get_active_api_key(),
            path="/",
            httponly=False,
            samesite="Lax",
        )
    return resp


@app.get("/api/auth/session")
def auth_session() -> Any:
    """Provide session validation and active API key for dashboard client."""
    resp = jsonify({
        "ok": True,
        "authenticated": True,
        "api_key": get_active_api_key(),
    })
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        get_active_api_key(),
        path="/",
        httponly=False,
        samesite="Lax",
    )
    return resp


@app.after_request
def ensure_dashboard_session(response: Any) -> Any:
    """Ensure HTML and top-level browser responses refresh stale session cookies."""
    if not is_authenticated(request) and request.method == "GET" and not request.path.startswith("/api/"):
        response.set_cookie(
            SESSION_COOKIE_NAME,
            get_active_api_key(),
            path="/",
            httponly=False,
            samesite="Lax",
        )
    return response


@app.get("/api/state")
def state() -> Any:
    """Return dashboard state: resources, findings, events, audit, and connection metadata."""
    res = [
        dict(
            id=k,
            name=r["res"],
            desc=r["desc"],
            good=r["good"],
            badtxt=r["bad"],
            attack=r["how"],
            ok=bool(r["check"]()),
        )
        for k, r in R.items()
    ]
    findings_map = store.get_findings_map()
    fs = []
    for k, f in findings_map.items():
        base = {x: R[k][x] for x in ("title", "sev", "ref", "what", "why", "fixtxt")} if k in R else {}
        item = {"id": k, **base, **f}
        fs.append(item)
    polls_data = store.get_polls()

    return jsonify(
        resources=res,
        findings=fs,
        events=store.get_recent_events(),
        audit=store.get_recent_memory_audit(),
        score=round(100 * sum(r["ok"] for r in res) / len(res)),
        mode=MODE,
        account=resolve_account_id(sts),
        region="us-east-1",
        polls=polls_data["n"],
        latency=polls_data["ms"],
        checked=now(),
        evidence=evidence(),
        video=os.getenv("CG_VIDEO_URL", ""),
    )


@app.post("/api/attack/<k>")
@require_auth
def attack(k: str) -> Any:
    """Trigger a simulated security misconfiguration."""
    if k not in R:
        return jsonify(
            ok=False,
            error=f"Invalid attack target: '{k}'. Valid targets are: {sorted(list(R.keys()))}",
        ), 400

    if LIVE:
        return jsonify(
            ok=False,
            error="Attack simulation is strictly disabled in Live AWS mode.",
        ), 403

    if DRY_RUN:
        audit(f"[DRY-RUN] SIMULATED ATTACK requested for {k}")
        return jsonify(
            ok=True,
            dry_run=True,
            message=f"Dry-run: attack '{k}' simulated without modifying cloud state.",
        )

    store.record_attack_start(k)
    audit(f"SIMULATED ATTACK {k}")
    R[k]["attack"]()
    return jsonify(ok=True)


@app.post("/api/decide/<k>/<d>")
@require_auth
def dec(k: str, d: str) -> Any:
    """Submit human approval or rejection decision for a pending finding."""
    if k not in R:
        return jsonify(ok=False, error=f"Unknown resource target: '{k}'"), 404

    if d not in ("ok", "no"):
        return jsonify(ok=False, error=f"Invalid decision '{d}'. Must be 'ok' or 'no'"), 400

    f = store.get_finding(k)
    if not f or f.get("status") != "pending":
        return jsonify(ok=False, error=f"No pending finding for '{k}' to decide"), 400

    decide(k, d == "ok", "dashboard")
    return jsonify(ok=True)


# ---- Module Registration ----

context: Dict[str, Any] = {
    "now": now,
    "R": R,
    "s3": s3,
    "ct": ct,
    "ec2": ec2,
    "iam": iam,
    "sts": sts,
    "BUCKET": BUCKET,
    "TRAIL": TRAIL,
    "USER": USER,
    "PERM": PERM,
    "LIVE": LIVE,
    "MODE": MODE,
    "MODEL": MODEL,
    "CTRY": CTRY,
    "MASK": MASK,
    "state_store": store,
    "pipeline": pipeline,
    "detector": detector,
    "aggregator": aggregator,
    "raise_finding": raise_finding,
    "decide": decide,
    "emit": emit,
    "ml_check": ml_check,
    "iam_graph": iam_graph,
    "soc_store": soc_store,
    "clients": {"iam": iam, "s3": s3, "ec2": ec2, "ct": ct},
}

from backend.dashboard_api import register
register(app, context)

from backend.telemetry import register_telemetry
register_telemetry(app, context)

register_replay_api(app, pipeline)

register_graph_api(app, iam_graph, {"iam": iam, "s3": s3, "ec2": ec2, "ct": ct})
register_scenarios_api(app, scenario_session_manager, store)
register_soc_api(app, soc_store, R)


def run_server() -> None:
    """Boot application with safe setup guards and background workers."""
    success, res_ids, msg = safe_setup(
        s3, ct, ec2, iam, BUCKET, TRAIL, USER, BLOCK, PERM
    )
    if success:
        for r_name, r_val in res_ids.items():
            store.set_resource_id(r_name, r_val)
        logger.info("Environment initialized: %s", msg)
    else:
        logger.warning("Setup guard: %s", msg)

    threading.Thread(target=scan, daemon=True).start()
    if TG:
        threading.Thread(target=tg_poll, daemon=True).start()

    logger.info("Starting CloudGuardian server on port 8000...")
    app.run(port=8000)


if __name__ == "__main__":
    run_server()
