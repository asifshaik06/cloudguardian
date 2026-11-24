"""CloudTrail Log Replay Engine for ThreatGuard.

Streams historical attack datasets (Splunk, flaws.cloud) into the live
event ingestion pipeline, rolling window aggregator, and ML detector.
"""
from datetime import datetime, timezone
import glob
import logging
import os
from typing import Any, Dict, List, Optional
from flask import Flask, jsonify

from backend.ingestion.stream import EventStreamPipeline
from backend.ml_engine.pipeline import read_records
from backend.security import require_auth
from backend.state import StateStore

logger = logging.getLogger("threatguard.replay")

AVAILABLE_DATASETS: Dict[str, Dict[str, str]] = {
    "splunk_s3_public_bucket": {
        "path": "datasets/raw/new/splunk_s3_public_bucket.json",
        "title": "Splunk S3 Public Bucket Attack",
        "description": "T1530 S3 public policy tampering & enumeration",
    },
    "splunk_bedrock": {
        "path": "datasets/raw/new/splunk_bedrock.json",
        "title": "Splunk Bedrock Attack Simulation",
        "description": "Unauthorized LLM foundation model access",
    },
    "splunk_security_scanner": {
        "path": "datasets/raw/new/splunk_security_scanner.json",
        "title": "Splunk High-Velocity Scanner",
        "description": "Rapid automated reconnaissance bursts",
    },
    "flaws_chunk00": {
        "path": "datasets/raw/flaws/flaws_cloudtrail_logs/flaws_cloudtrail00.json.gz",
        "title": "flaws.cloud Chunk 00",
        "description": "Real unlabelled production CloudTrail chunk",
    },
}


def _extract_principal(r: Dict[str, Any]) -> str:
    u = r.get("userIdentity") or {}
    return (
        u.get("userName")
        or u.get("arn", "").split("/")[-1]
        or u.get("principalId")
        or u.get("accessKeyId")
        or "replay-user"
    )


def replay_file(
    file_path: str,
    pipeline: EventStreamPipeline,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Parse and stream CloudTrail records from file_path into pipeline."""
    if not os.path.exists(file_path):
        return {"ok": False, "error": f"File not found: {file_path}"}

    records = read_records(file_path)
    if not records:
        return {"ok": False, "error": f"No records could be parsed from {file_path}"}

    if limit:
        records = records[:limit]

    replayed = 0
    anomalies = 0

    for idx, r in enumerate(records):
        if not isinstance(r, dict):
            continue
        if "eventName" not in r and isinstance(r.get("event"), dict):
            r = r["event"]

        ev_name = r.get("eventName")
        if not ev_name:
            continue

        service = (r.get("eventSource") or "unknown.amazonaws.com").split(".")[0]
        principal = _extract_principal(r)
        ip = r.get("sourceIPAddress") or "203.0.113.1"
        err = r.get("errorCode")

        t_raw = r.get("eventTime")
        try:
            ev_time = datetime.fromisoformat(t_raw.replace("Z", "+00:00")) if t_raw else datetime.now(timezone.utc)
        except Exception:
            ev_time = datetime.now(timezone.utc)

        ev, det = pipeline.ingest(
            event_name=ev_name,
            service=service,
            principal_id=principal,
            country="US" if ip.startswith("203.") else "IN",
            source="replay",
            source_ip=ip,
            error_code=err,
            event_time=ev_time,
            event_id=f"replay-{idx}-{ev_name}",
        )

        if ev is not None:
            replayed += 1
            if det and det.get("is_anomaly"):
                anomalies += 1

    pipeline.store.append_audit_entry(
        f"REPLAY completed for {os.path.basename(file_path)}: {replayed} events replayed, {anomalies} anomalies flagged."
    )

    return {
        "ok": True,
        "dataset": os.path.basename(file_path),
        "events_replayed": replayed,
        "anomalies_detected": anomalies,
    }


def register_replay_api(app: Flask, pipeline: EventStreamPipeline) -> None:
    """Register replay endpoints."""

    @app.get("/api/replay/datasets")
    def list_datasets() -> Any:
        """List available CloudTrail replay datasets."""
        out = []
        for d_id, info in AVAILABLE_DATASETS.items():
            p = info["path"]
            exists = os.path.exists(p)
            size = os.path.getsize(p) if exists else 0
            out.append(dict(
                id=d_id,
                title=info["title"],
                description=info["description"],
                path=p,
                exists=exists,
                size_kb=round(size / 1024, 1),
            ))
        return jsonify(out)

    @app.post("/api/replay/<dataset_id>")
    @require_auth
    def run_replay(dataset_id: str) -> Any:
        """Replay specified dataset into the detection engine."""
        if dataset_id not in AVAILABLE_DATASETS:
            return jsonify(
                ok=False,
                error=f"Unknown dataset '{dataset_id}'. Available: {list(AVAILABLE_DATASETS.keys())}",
            ), 404

        info = AVAILABLE_DATASETS[dataset_id]
        res = replay_file(info["path"], pipeline, limit=200)
        return jsonify(res)
