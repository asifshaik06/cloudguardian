"""Telemetry and Metrics module for CloudGuardian.

Provides:
- Background posture polling loop (score over time).
- Baseline simulated traffic generation (Simulator mode).
- Real-time event logging and minute-bucket aggregation.
- Composite risk scoring (CSPM severity, ML anomaly score, asset sensitivity).
- MITRE ATT&CK technique mapping.
"""
from collections import deque
import logging
import os
import random
import re
import threading
import time
from typing import Any, Dict, List, Optional
import numpy as np
from flask import Flask, jsonify, request

from backend.state import StateStore

logger = logging.getLogger("cloudguardian.telemetry")

# Reference data (MITRE ATT&CK mapping and project risk weights)
MITRE = {
    "T1530": ("Data from Cloud Storage", "Collection"),
    "T1562.008": ("Impair Defenses: Disable or Modify Cloud Logs", "Defense Evasion"),
    "T1133": ("External Remote Services", "Initial Access, Persistence"),
    "T1078.004": ("Valid Accounts: Cloud Accounts", "Initial Access, Persistence, Privilege Escalation, Defense Evasion"),
}

ASSET = {
    "s3": ("Holds student records", 1.0),
    "ct": ("Account-wide audit log", 0.9),
    "sg": ("Remote access to servers", 0.7),
    "key": ("Employee credential", 0.7),
}

SEVW = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25}
W = dict(cspm=0.35, ml=0.35, asset=0.30)  # Project weights
EVMAP = {
    "s3": "DeleteBucketPublicAccessBlock",
    "ct": "StopLogging",
    "sg": "AuthorizeSecurityGroupIngress",
    "key": "ListBuckets x90",
}


def register_telemetry(app: Flask, g: Dict[str, Any]) -> None:
    """Register telemetry collectors, background loops, and metrics endpoints."""
    store: StateStore = g.get("state_store") or StateStore()
    g["state_store"] = store

    R = g["R"]
    LIVE = g["LIVE"]
    MODE = g["MODE"]
    MODEL = g["MODEL"]
    CTRY = g["CTRY"]

    detector = g.get("detector")
    if detector and getattr(detector, "thresholds", None):
        THR = float(detector.thresholds.get("isolation_forest", 0.610))
    else:
        THR = float(-MODEL.offset_) if hasattr(MODEL, "offset_") else 0.610

    def calc_score(hour: int, country: str, calls: int) -> float:
        if detector:
            # Score synthetic baseline through 12-feature detector
            feat = {
                "call_count": float(calls),
                "call_velocity": 1.0,
                "error_ratio": 0.0,
                "unique_services": 1.0,
                "unique_events": 1.0,
                "enumeration_ratio": 0.2,
                "sensitive_count": 0.0,
                "iam_change_count": 0.0,
                "first_service_ratio": 0.0,
                "first_ip": 0.0,
                "off_hours": 0.0 if (8 <= hour <= 18) else 1.0,
                "event_entropy": 0.5,
            }
            res = detector.score_window(feat)
            return float(res["score"])
        country_code = CTRY.get(country, 0)
        x = np.array([[hour, country_code, calls]])
        return float(-MODEL.score_samples(x)[0])

    # Intercept emit to record in telemetry event log
    orig_emit = g.get("emit")

    def telemetry_emit(name: str, src: str, user: str, country: str = "IN") -> None:
        if orig_emit:
            orig_emit(name, src, user, country)
        store.log_telemetry_event(name, src, user, country, "attack", MODE)

    g["emit"] = telemetry_emit

    # Intercept ml_check to record anomaly scores
    orig_ml = g.get("ml_check")

    def telemetry_ml_check(hour: int, country: str, calls: int) -> None:
        s = calc_score(hour, country, calls)
        store.add_anomaly_score(s, "attack")
        if orig_ml:
            orig_ml(hour, country, calls)

    g["ml_check"] = telemetry_ml_check

    # Background Posture Loop
    def posture_loop() -> None:
        time.sleep(2)
        while True:
            try:
                ok_count = 0
                for r in R.values():
                    try:
                        if bool(r["check"]()):
                            ok_count += 1
                    except Exception:
                        pass
                posture_score = round(100 * ok_count / max(len(R), 1))
                pending_count = sum(
                    1 for f in store.get_all_findings() if f.get("status") == "pending"
                )
                store.add_posture_sample(posture_score, pending_count)
            except Exception as exc:
                logger.warning("Telemetry posture loop error: %s", exc)
            time.sleep(5)

    threading.Thread(target=posture_loop, daemon=True).start()

    # Background Baseline Traffic Simulation Loop (Simulator mode only)
    if not LIVE and os.getenv("CG_BASELINE", "1") == "1":
        def baseline_loop() -> None:
            rng = random.Random(7)
            ops = [
                ("s3", "GetObject"),
                ("s3", "ListBuckets"),
                ("ec2", "DescribeInstances"),
                ("cloudwatch", "GetMetricData"),
                ("lambda", "ListFunctions"),
            ]
            time.sleep(1)
            while True:
                try:
                    time.sleep(rng.uniform(2.5, 5.0))
                    svc, op = rng.choice(ops)
                    hr = rng.randint(8, 18)
                    calls = rng.randint(1, 11)
                    s = calc_score(hr, "IN", calls)
                    user_name = f"user-{rng.randint(1, 8):03d}"
                    store.log_telemetry_event(op, svc, user_name, "IN", "baseline", MODE)
                    store.add_anomaly_score(s, "baseline")
                except Exception as exc:
                    logger.warning("Baseline loop error: %s", exc)

        threading.Thread(target=baseline_loop, daemon=True).start()

    # ---- Telemetry Endpoints ----

    @app.get("/api/metrics")
    def metrics() -> Any:
        """Return system posture, anomaly timeline, and remediation KPI metrics."""
        rb_count = store.count_rollback_events()
        findings = store.get_all_findings()

        items = []
        for f in findings:
            f_id = f.get("id")
            t_fix = f.get("t_fix")
            t0 = f.get("t0")
            ttr = round(t_fix - t0, 1) if t_fix and t0 else None
            items.append(dict(
                id=f_id,
                status=f.get("status"),
                ttd=f.get("tdetect"),
                verified=f.get("verified"),
                ttr=ttr,
            ))

        done = [i for i in items if i.get("status") == "fixed"]

        return jsonify(
            posture=store.get_posture_samples(),
            anomaly=store.get_anomaly_scores(limit=400),
            threshold=round(THR, 4),
            buckets=store.get_minute_buckets(),
            events_total=store.get_telemetry_events_count(),
            rem=dict(
                items=items,
                fixed=len(done),
                verified=sum(1 for i in done if i.get("verified")),
                rolled_back=rb_count,
            ),
        )

    @app.get("/api/events")
    def events_api() -> Any:
        """Query recent event records with optional query and kind filters."""
        q = request.args.get("q", "")
        kind = request.args.get("kind", "")
        rows = store.get_telemetry_events(kind=kind or None, query=q or None, limit=300)
        return jsonify(
            total=store.get_telemetry_events_count(),
            matched=len(rows),
            rows=rows,
        )

    @app.get("/api/finding/<k>")
    def finding(k: str) -> Any:
        """Return detailed finding data including MITRE mapping and risk breakdown."""
        if k not in R:
            return jsonify(error="unknown finding"), 404

        f = store.get_finding(k)
        if not f:
            return jsonify(error="finding not active"), 404

        r = R[k]
        m = re.search(r"T\d{4}(?:\.\d{3})?", r["ref"])
        tid = m.group(0) if m else None
        mitre_name, tactics = MITRE.get(tid, (None, None))

        anomaly_list = [
            a for a in store.get_anomaly_scores(limit=100) if a.get("kind") == "attack"
        ]
        parts = {"CSPM severity": (W["cspm"], SEVW.get(r["sev"], 0.5))}
        if k == "key" and anomaly_list:
            parts["ML anomaly score"] = (W["ml"], anomaly_list[-1]["score"])
        parts["Asset sensitivity"] = (W["asset"], ASSET[k][1])

        tot = sum(w for w, _ in parts.values())
        rows = [
            dict(
                name=n,
                weight=round(w / tot, 2),
                value=round(v, 2),
                points=round(w / tot * v * 100, 1),
            )
            for n, (w, v) in parts.items()
        ]

        # Audit timeline for this finding
        audit_lines = store.get_audit_lines()
        rel_lines = [
            t for t in audit_lines
            if re.search(rf"\b{re.escape(k)}\b", t) or r["title"] in t
        ]

        state_fn = g.get("state_fn", lambda _: None)
        matching_events = [
            e for e in store.get_telemetry_events(limit=100)
            if e.get("name") == EVMAP.get(k)
        ][:5]

        return jsonify(
            id=k,
            title=r["title"],
            sev=r["sev"],
            status=f.get("status"),
            ref=r["ref"],
            what=r["what"],
            why=r["why"],
            fix=r["fixtxt"],
            mitre=dict(id=tid, name=mitre_name, tactics=tactics),
            explain=f.get("explain"),
            verified=f.get("verified"),
            detected=f.get("detected"),
            before=f.get("before"),
            after=f.get("after"),
            current=state_fn(k),
            risk=dict(
                score=round(sum(x["points"] for x in rows)),
                rows=rows,
                note="Weights are project-defined, not learned.",
                excluded="Graph exposure is not included because the IAM graph is not built yet.",
            ),
            events=matching_events,
            timeline=rel_lines[-14:],
            asset=ASSET[k][0],
        )
