"""Dashboard API module for ThreatGuard.

Provides:
- State versioning and cryptographic verification.
- Stale-approval rejection.
- Remediation rollback controller with authentication and parameter validation.
- Endpoints for rules, ML benchmarks, dataset provenance, and hash-chained audit queries.
"""
import csv
import glob
import hashlib
import json
import logging
import os
import time
from typing import Any, Callable, Dict, Optional
import joblib
from flask import Flask, jsonify, request

from backend.aws_guard import safe_execute_remediation
from backend.security import redact_sensitive_data, require_auth
from backend.state import StateStore

logger = logging.getLogger("threatguard.dashboard_api")


def register(app: Flask, g: Dict[str, Any]) -> None:
    """Register dashboard and audit API endpoints."""
    # Retrieve dependencies from context
    store: StateStore = g.get("state_store") or StateStore()
    g["state_store"] = store

    R = g["R"]
    s3, ct, ec2, iam = g["s3"], g["ct"], g["ec2"], g["iam"]
    BUCKET, TRAIL, USER, PERM = g["BUCKET"], g["TRAIL"], g["USER"], g["PERM"]

    # Provide audit function
    def audit(text: Any) -> str:
        return store.append_audit_entry(str(text), lambda t: redact_sensitive_data(t, g.get("MASK", True)))
    g["audit"] = audit

    # Current resource state extractors
    def pab() -> Optional[Dict[str, Any]]:
        try:
            return s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
        except Exception:
            return None

    def cidrs() -> list:
        try:
            sg_id = store.get_resource_id("sg")
            gp = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
            return sorted(r["CidrIp"] for p in gp["IpPermissions"] for r in p["IpRanges"])
        except Exception:
            return []

    def key_status() -> list:
        try:
            meta = iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]
            st = meta[0]["Status"] if meta else "Inactive"
        except Exception:
            st = "Inactive"
        return [st, store.is_anomaly_active()]

    STATE: Dict[str, Callable[[], Any]] = {
        "s3": pab,
        "ct": lambda: ct.get_trail_status(Name=TRAIL).get("IsLogging", False) if TRAIL else False,
        "sg": cidrs,
        "key": key_status,
    }
    g["state_fn"] = lambda k: STATE[k]() if k in STATE else None

    def ver(k: str) -> str:
        """Compute 12-char SHA-256 fingerprint of current resource state."""
        try:
            state_val = STATE[k]() if k in STATE else None
            return hashlib.sha256(json.dumps(state_val, sort_keys=True).encode("utf-8")).hexdigest()[:12]
        except Exception as exc:
            logger.warning("Error computing version fingerprint for %s: %s", k, exc)
            return "000000000000"

    g["ver_fn"] = ver

    # Rollback (undo) actions
    def u_key() -> None:
        key_id = store.get_resource_id("key")
        if key_id:
            iam.update_access_key(UserName=USER, AccessKeyId=key_id, Status="Active")
        store.set_anomaly_active(True)

    def u_sg() -> None:
        sg_id = store.get_resource_id("sg")
        if sg_id:
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=PERM("0.0.0.0/0"))

    UNDO: Dict[str, Callable[[], None]] = {
        "s3": lambda: s3.delete_public_access_block(Bucket=BUCKET),
        "ct": lambda: ct.stop_logging(Name=TRAIL),
        "sg": u_sg,
        "key": u_key,
    }

    # Wrap remediation functions with pre/post state capture
    def wrap_fix(k: str, fix_fn: Callable[[], Any]) -> Callable[[], Any]:
        def wrapped() -> Any:
            before_state = STATE[k]() if k in STATE else None
            store.update_finding(k, before=before_state)
            res = fix_fn()
            after_state = STATE[k]() if k in STATE else None
            after_v = ver(k)
            store.update_finding(
                k,
                after=after_state,
                after_ver=after_v,
                t_fix=time.time(),
            )
            return res
        return wrapped

    for k in R:
        R[k]["fix"] = wrap_fix(k, R[k]["fix"])

    # Wrap raise_finding to capture detection state and version
    orig_raise = g.get("raise_finding")

    def raise_finding_with_ver(k: str, explain: Optional[list] = None) -> None:
        if orig_raise:
            orig_raise(k, explain)
        v = ver(k)
        det = STATE[k]() if k in STATE else None
        store.update_finding(k, ver=v, t0=time.time(), detected=det)

    g["raise_finding"] = raise_finding_with_ver

    # Wrap decide to prevent stale approvals
    orig_decide = g.get("decide")

    def decide_with_stale_check(k: str, ok: bool, via: str) -> None:
        f = store.get_finding(k)
        if f and f.get("status") == "pending" and ok:
            current_ver = ver(k)
            recorded_ver = f.get("ver")
            if recorded_ver and recorded_ver != current_ver:
                audit(
                    f"STALE approval rejected for {k}: the resource changed after detection "
                    f"(detected {recorded_ver}, now {current_ver}), re-detecting"
                )
                store.pop_finding(k)
                return

        if orig_decide:
            orig_decide(k, ok, via)

    g["decide"] = decide_with_stale_check

    # ---- Endpoints ----

    @app.post("/api/rollback/<k>")
    @require_auth
    def rollback(k: str) -> Any:
        """Roll back a previously applied remediation if cloud state has not changed."""
        if k not in R:
            return jsonify(ok=False, error=f"Unknown resource target: '{k}'"), 404

        f = store.get_finding(k)
        if not f or f.get("status") != "fixed":
            return jsonify(ok=False, error="nothing to roll back"), 400

        current_ver = ver(k)
        after_ver = f.get("after_ver")
        if after_ver and current_ver != after_ver:
            audit(f"ROLLBACK refused for {k}: the resource changed after the fix")
            return jsonify(
                ok=False,
                error="the resource changed after the fix, so rollback was refused"
            ), 409

        if k in UNDO:
            UNDO[k]()

        new_ver = ver(k)
        store.update_finding(k, status="pending", ver=new_ver)
        audit(f"ROLLED BACK {k} to its pre-fix state, awaiting approval again")
        return jsonify(ok=True)

    @app.get("/api/audit")
    def audit_api() -> Any:
        """Query cryptographic hash-chained audit trail."""
        q = request.args.get("q", "")
        res = store.query_audit_trail(query=q, limit=200)
        return jsonify(res)

    @app.get("/api/rules")
    def rules() -> Any:
        """List active CIS/MITRE rules and status."""
        out = []
        for r_id, r in R.items():
            try:
                ok = bool(r["check"]())
            except Exception:
                ok = False
            out.append(dict(
                id=r_id,
                name=r["res"],
                title=r["title"],
                ref=r["ref"],
                sev=r["sev"],
                ok=ok,
            ))
        return jsonify(out)

    def _read_file(p: str) -> str:
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fp:
                return fp.read()
        return ""

    @app.get("/api/ml")
    def ml() -> Any:
        """Return ML benchmark results, model card, and top review windows."""
        res_json = json.loads(_read_file("docs/ml_results.json") or "{}")
        card: Dict[str, Any] = {}
        if os.path.exists("models/baseline_v1.joblib"):
            try:
                m = joblib.load("models/baseline_v1.joblib")
                card = dict(
                    features=m.get("features", []),
                    thresholds={k: round(v, 3) for k, v in m.get("thresholds", {}).items()},
                    window=m.get("window", "5min"),
                    threshold_rule=m.get("threshold_rule", ""),
                )
            except Exception as e:
                logger.warning("Error reading models/baseline_v1.joblib: %s", e)

        top = []
        p = "datasets/processed/flaws_top_alerts_for_review.csv"
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as fp:
                    top = list(csv.DictReader(fp))[:10]
            except Exception as e:
                logger.warning("Error reading top alerts: %s", e)

        return jsonify(
            results=res_json,
            card=card,
            multi=_read_file("docs/multi_seed_results.md"),
            top=top,
        )

    @app.get("/api/datasets")
    def datasets() -> Any:
        """Return dataset provenance metadata."""
        meta_dir = "datasets/metadata"
        if not os.path.isdir(meta_dir):
            return jsonify([])
        files = sorted(glob.glob(os.path.join(meta_dir, "*.md")))
        return jsonify([
            dict(name=os.path.basename(f), text=_read_file(f))
            for f in files
        ])
