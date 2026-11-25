"""Thread-safe state management and hash-chained audit storage for ThreatGuard.

Provides:
- ThreadSafeStateStore: Reentrant lock protection over all shared application data.
- Safe snapshot generation to prevent 'dictionary changed size during iteration' errors.
- Thread-safe SQLite audit trail with SHA-256 hash chaining and tamper verification.
"""
from collections import deque
import copy
import hashlib
import json
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


class StateStore:
    """Thread-safe central state container for ThreatGuard."""

    def __init__(self, db_path: str = "cg_audit.db", check_same_thread: bool = False):
        self._lock = threading.RLock()
        self._db_lock = threading.Lock()
        self._db_path = db_path

        # Core state stores
        self._findings: Dict[str, Dict[str, Any]] = {}
        self._events: deque = deque(maxlen=30)
        self._evlog: deque = deque(maxlen=3000)
        self._audit_mem: deque = deque(maxlen=100)
        self._posture: deque = deque(maxlen=720)
        self._anomaly_scores: deque = deque(maxlen=600)
        self._polls: Dict[str, int] = {"n": 0, "ms": 0}
        self._t0: Dict[str, float] = {}
        self._anom: Dict[str, bool] = {"on": False}
        self._resource_ids: Dict[str, str] = {}
        self._ev_seq: int = 0

        # Initialize SQLite database
        self._db = sqlite3.connect(self._db_path, check_same_thread=check_same_thread)
        with self._db_lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS audit ("
                "i INTEGER PRIMARY KEY, "
                "text TEXT, "
                "prev TEXT, "
                "hash TEXT)"
            )
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS cost_reports ("
                "report_id TEXT PRIMARY KEY, "
                "title TEXT NOT NULL, "
                "generated_at TEXT NOT NULL, "
                "reporting_period TEXT NOT NULL, "
                "service_filter TEXT, "
                "environment TEXT NOT NULL, "
                "currency TEXT NOT NULL, "
                "pricing_version TEXT NOT NULL, "
                "total_monthly_cost REAL NOT NULL, "
                "potential_monthly_savings REAL NOT NULL, "
                "optimized_monthly_cost REAL NOT NULL, "
                "resource_count INTEGER NOT NULL, "
                "findings_count INTEGER NOT NULL, "
                "snapshot_json TEXT NOT NULL)"
            )
            self._db.commit()

    # ---- Findings Thread-Safe Methods ----

    def get_finding(self, key: str) -> Optional[Dict[str, Any]]:
        """Return a copy of a finding by key, or None if not present."""
        with self._lock:
            f = self._findings.get(key)
            return dict(f) if f else None

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Return a snapshot list of copies of all findings."""
        with self._lock:
            return [dict(f) for f in self._findings.values()]

    def get_findings_map(self) -> Dict[str, Dict[str, Any]]:
        """Return a copy of the findings mapping."""
        with self._lock:
            return {k: dict(v) for k, v in self._findings.items()}

    def set_finding(self, key: str, finding_dict: Dict[str, Any]) -> None:
        """Store or replace a finding dictionary under key."""
        with self._lock:
            self._findings[key] = dict(finding_dict)

    def update_finding(self, key: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
        """Update existing finding attributes under key and return updated copy."""
        with self._lock:
            if key not in self._findings:
                return None
            self._findings[key].update(kwargs)
            return dict(self._findings[key])

    def pop_finding(self, key: str) -> Optional[Dict[str, Any]]:
        """Remove and return finding if present."""
        with self._lock:
            return self._findings.pop(key, None)

    def clear_findings(self) -> None:
        """Clear all findings (for testing)."""
        with self._lock:
            self._findings.clear()

    # ---- Anomaly & Timing State ----

    def is_anomaly_active(self) -> bool:
        with self._lock:
            return bool(self._anom.get("on", False))

    def set_anomaly_active(self, active: bool) -> None:
        with self._lock:
            self._anom["on"] = bool(active)

    def record_attack_start(self, key: str, timestamp: Optional[float] = None) -> None:
        with self._lock:
            self._t0[key] = timestamp or time.time()

    def get_attack_start(self, key: str) -> Optional[float]:
        with self._lock:
            return self._t0.get(key)

    def set_resource_id(self, key: str, value: str) -> None:
        with self._lock:
            self._resource_ids[key] = value

    def get_resource_id(self, key: str, default: str = "") -> str:
        with self._lock:
            return self._resource_ids.get(key, default)

    def get_all_resource_ids(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._resource_ids)

    # ---- Event Logging Methods ----

    def append_event(self, event_data: Dict[str, Any]) -> None:
        with self._lock:
            self._events.appendleft(dict(event_data))

    def get_recent_events(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def log_telemetry_event(self, name: str, src: str, user: str, country: str, kind: str, mode: str) -> Dict[str, Any]:
        with self._lock:
            self._ev_seq += 1
            entry = dict(
                id=self._ev_seq,
                ts=time.time(),
                t=time.strftime("%H:%M:%S"),
                name=name,
                src=src,
                user=user,
                country=country,
                kind=kind,
                mode=mode,
            )
            self._evlog.appendleft(entry)
            return entry

    def get_telemetry_events(
        self,
        kind: Optional[str] = None,
        query: Optional[str] = None,
        limit: int = 300,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            events_copy = list(self._evlog)

        q = (query or "").lower().strip()
        filtered = []
        for e in events_copy:
            if kind and e.get("kind") != kind:
                continue
            if q:
                search_text = (
                    f"{e.get('name', '')}{e.get('user', '')}"
                    f"{e.get('src', '')}{e.get('country', '')}"
                ).lower()
                if q not in search_text:
                    continue
            filtered.append(e)
            if len(filtered) >= limit:
                break
        return filtered

    def get_telemetry_events_count(self) -> int:
        with self._lock:
            return len(self._evlog)

    def get_minute_buckets(self, window_minutes: int = 15) -> List[Dict[str, Any]]:
        """Aggregate event counts into continuous 1-minute buckets without missing intervals."""
        with self._lock:
            events_copy = list(self._evlog)

        cur_m = int(time.time() // 60)
        start_m = cur_m - window_minutes + 1
        out: Dict[int, Dict[str, int]] = {
            m: {"baseline": 0, "attack": 0} for m in range(start_m, cur_m + 1)
        }
        for e in events_copy:
            m = int(e.get("ts", 0) // 60)
            if m in out:
                k = e.get("kind", "baseline")
                if k in out[m]:
                    out[m][k] += 1
                else:
                    out[m]["baseline"] += 1

        return [dict(t=m * 60, **v) for m, v in sorted(out.items())]

    # ---- Posture & Anomaly Score Telemetry ----

    def add_posture_sample(self, score: int, open_findings: int) -> None:
        with self._lock:
            self._posture.append(dict(t=time.time(), score=score, open=open_findings))

    def get_posture_samples(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._posture)

    def add_anomaly_score(self, score: float, kind: str) -> None:
        with self._lock:
            self._anomaly_scores.append(dict(t=time.time(), score=round(score, 4), kind=kind))

    def get_anomaly_scores(self, limit: int = 400) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._anomaly_scores)[-limit:]

    def update_polls(self, n_delta: int = 1, latency_ms: Optional[int] = None) -> None:
        with self._lock:
            self._polls["n"] += n_delta
            if latency_ms is not None:
                self._polls["ms"] = latency_ms

    def get_polls(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._polls)

    # ---- Hash-Chained SQLite Audit Trail ----

    def append_audit_entry(self, raw_text: str, redact_fn: Optional[Callable[[str], str]] = None) -> str:
        """Atomically append a tamper-evident hash-chained audit entry."""
        redacted = redact_fn(raw_text) if redact_fn else raw_text
        timestamp = time.strftime("%H:%M:%S")
        entry_text = f"[{timestamp}] {redacted}"

        with self._db_lock:
            row = self._db.execute("SELECT hash, i FROM audit ORDER BY i DESC LIMIT 1").fetchone()
            prev_hash, idx = (row[0], row[1] + 1) if row else ("0" * 64, 0)
            entry_hash = hashlib.sha256((prev_hash + entry_text).encode("utf-8")).hexdigest()
            self._db.execute(
                "INSERT INTO audit (i, text, prev, hash) VALUES (?, ?, ?, ?)",
                (idx, entry_text, prev_hash, entry_hash)
            )
            self._db.commit()

        with self._lock:
            self._audit_mem.appendleft(entry_text)

        return entry_text

    def get_recent_memory_audit(self) -> List[str]:
        with self._lock:
            return list(self._audit_mem)

    def query_audit_trail(self, query: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
        """Query audit trail rows with search filter and integrity status."""
        q = (query or "").lower().strip()
        with self._db_lock:
            rows = self._db.execute("SELECT i, text, prev, hash FROM audit ORDER BY i ASC").fetchall()

        # Check chain integrity
        prev_hash = "0" * 64
        chain_ok = True
        first_bad: Optional[int] = None

        for i, text, p, h in rows:
            expected = hashlib.sha256((p + text).encode("utf-8")).hexdigest()
            if p != prev_hash or h != expected:
                chain_ok = False
                first_bad = i
                break
            prev_hash = h

        # Apply search filter
        matched_rows = [r for r in rows if not q or q in r[1].lower()]
        display_rows = [
            dict(i=r[0], text=r[1], hash=r[3][:12])
            for r in matched_rows[-limit:]
        ][::-1]

        return {
            "chain_ok": chain_ok,
            "first_bad": first_bad,
            "count": len(rows),
            "matched": len(matched_rows),
            "rows": display_rows,
        }

    def count_rollback_events(self) -> int:
        """Count total rollback entries in the audit trail."""
        with self._db_lock:
            row = self._db.execute(
                "SELECT COUNT(*) FROM audit WHERE text LIKE ?",
                ("%ROLLED BACK%",)
            ).fetchone()
            return int(row[0]) if row else 0

    def get_audit_lines(self) -> List[str]:
        """Fetch all raw text audit lines in ascending order."""
        with self._db_lock:
            rows = self._db.execute("SELECT text FROM audit ORDER BY i ASC").fetchall()
            return [r[0] for r in rows]

    # ---- Cost Optimization Report Persistence ----

    def save_cost_report(self, report: Dict[str, Any]) -> None:
        """Persist an immutable Cost Optimization Report snapshot in SQLite."""
        info = report.get("report_information") or {}
        overview = report.get("cost_overview") or {}
        comparison = report.get("cost_comparison") or {}
        resources = report.get("resource_level_analysis") or []
        findings = report.get("cost_optimization_findings") or []

        report_id = str(info.get("report_id") or "")
        if not report_id:
            raise ValueError("report_id is required to persist cost report.")

        snapshot_json = json.dumps(report, default=str)
        with self._db_lock:
            self._db.execute(
                "INSERT OR REPLACE INTO cost_reports ("
                "report_id, title, generated_at, reporting_period, service_filter, "
                "environment, currency, pricing_version, total_monthly_cost, "
                "potential_monthly_savings, optimized_monthly_cost, "
                "resource_count, findings_count, snapshot_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    report_id,
                    str(info.get("report_title") or "ThreatGuard Cost Optimization Report"),
                    str(info.get("generated_at") or ""),
                    str(info.get("reporting_period") or "monthly"),
                    str(info.get("service_filter") or "all"),
                    str(info.get("environment") or "Moto Simulated Cloud"),
                    str(info.get("currency") or "USD"),
                    str(info.get("pricing_dataset_version") or "unknown"),
                    float(overview.get("estimated_monthly_cost") or 0.0),
                    float(comparison.get("potential_monthly_savings") or 0.0),
                    float(comparison.get("optimized_estimated_monthly_cost") or 0.0),
                    len(resources),
                    len(findings),
                    snapshot_json,
                ),
            )
            self._db.commit()

    def list_cost_reports(
        self,
        service_filter: Optional[str] = None,
        reporting_period: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List stored Cost Optimization Report metadata ordered newest first."""
        clauses: List[str] = []
        params: List[Any] = []
        if service_filter:
            clauses.append("LOWER(service_filter) = ?")
            params.append(service_filter.strip().lower())
        if reporting_period:
            clauses.append("LOWER(reporting_period) = ?")
            params.append(reporting_period.strip().lower())

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT report_id, title, generated_at, reporting_period, service_filter, "
            "environment, currency, pricing_version, total_monthly_cost, "
            "potential_monthly_savings, optimized_monthly_cost, resource_count, findings_count "
            f"FROM cost_reports {where_sql} ORDER BY generated_at DESC, rowid DESC LIMIT ?"
        )
        params.append(max(1, min(200, int(limit))))

        with self._db_lock:
            rows = self._db.execute(sql, tuple(params)).fetchall()

        return [
            {
                "report_id": r[0],
                "title": r[1],
                "generated_at": r[2],
                "reporting_period": r[3],
                "service_filter": r[4],
                "environment": r[5],
                "currency": r[6],
                "pricing_version": r[7],
                "total_monthly_cost": r[8],
                "potential_monthly_savings": r[9],
                "optimized_monthly_cost": r[10],
                "resource_count": r[11],
                "findings_count": r[12],
            }
            for r in rows
        ]

    def get_cost_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full immutable snapshot for a previously generated report."""
        with self._db_lock:
            row = self._db.execute(
                "SELECT snapshot_json FROM cost_reports WHERE report_id = ?",
                (report_id,),
            ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None

    def close(self) -> None:
        """Safely close database connections."""
        with self._db_lock:
            try:
                self._db.close()
            except Exception:
                pass
