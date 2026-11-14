"""Streaming 5-minute rolling window feature aggregator for CloudGuardian.

Extracts all 12 behavioral features in real time per principal identity:
- call_count
- call_velocity
- error_ratio
- unique_services
- unique_events
- enumeration_ratio
- sensitive_count
- iam_change_count
- first_service_ratio
- first_ip
- off_hours
- event_entropy

Cold-start handling: until a principal has >= 3 previous windows, history features
remain neutral to prevent false alarms on newly registered principals.
"""
from collections import Counter
from datetime import datetime, timezone
import math
import threading
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np

from backend.ml_engine.pipeline import FEATURES, READ, SENSITIVE


class StreamingWindowAggregator:
    """Thread-safe streaming aggregator building 5-minute windows and extracting 12 behavioral features."""

    def __init__(self, window_minutes: int = 5):
        self._lock = threading.RLock()
        self.window_minutes = window_minutes

        # Current window events per principal: {principal: [event_dict, ...]}
        self._active_windows: Dict[str, List[Dict[str, Any]]] = {}
        # Active window timestamp per principal: {principal: datetime}
        self._window_starts: Dict[str, datetime] = {}
        # Historical profile per principal: {principal: {"svc": set, "ips": set, "hours": Counter, "counts": list}}
        self._history: Dict[str, Dict[str, Any]] = {}

    def _floor_time(self, dt: datetime) -> datetime:
        """Floor datetime to the nearest window_minutes boundary in UTC."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        minute = (dt.minute // self.window_minutes) * self.window_minutes
        return dt.replace(minute=minute, second=0, microsecond=0)

    def _get_history(self, principal: str) -> Dict[str, Any]:
        """Retrieve or initialize historical baseline profile for principal."""
        if principal not in self._history:
            self._history[principal] = {
                "svc": set(),
                "ips": set(),
                "hours": Counter(),
                "counts": [],
            }
        return self._history[principal]

    def _compute_features(
        self,
        principal: str,
        events: List[Dict[str, Any]],
        win_start: datetime,
    ) -> Dict[str, float]:
        """Compute the 12 behavioral features for an event batch within a window."""
        h = self._get_history(principal)
        n = len(events)
        if n == 0:
            return {f: 0.0 for f in FEATURES}

        names = [e["event"] for e in events]
        services = {e["service"] for e in events if e.get("service")}
        ips = {e["ip"] for e in events if e.get("ip")}
        errors = [e["error"] for e in events]
        cnt = Counter(names)

        warm = len(h["counts"]) >= 3
        prev = float(np.mean(h["counts"])) if h["counts"] else float(n)

        call_count = float(n)
        call_velocity = (float(n) / (prev + 1.0)) if warm else 1.0
        error_ratio = float(sum(errors)) / float(n)
        unique_services = float(len(services))
        unique_events = float(len(cnt))
        enumeration_ratio = sum(1 for x in names if any(x.startswith(r) for r in READ)) / float(n)
        sensitive_count = float(sum(1 for x in names if x in SENSITIVE))
        iam_change_count = float(
            sum(
                1 for e in events
                if e.get("service") == "iam" and not any(e["event"].startswith(r) for r in READ)
            )
        )
        first_service_ratio = (
            float(len(services - h["svc"])) / float(max(len(services), 1))
            if warm else 0.0
        )
        first_ip = float(bool(ips - h["ips"])) if warm else 0.0
        off_hours = float(h["hours"][win_start.hour] == 0) if warm else 0.0
        event_entropy = -sum((c / n) * math.log2(c / n) for c in cnt.values())

        return {
            "call_count": call_count,
            "call_velocity": call_velocity,
            "error_ratio": error_ratio,
            "unique_services": unique_services,
            "unique_events": unique_events,
            "enumeration_ratio": enumeration_ratio,
            "sensitive_count": sensitive_count,
            "iam_change_count": iam_change_count,
            "first_service_ratio": first_service_ratio,
            "first_ip": first_ip,
            "off_hours": off_hours,
            "event_entropy": event_entropy,
        }

    def add_event(
        self,
        principal: str,
        event_name: str,
        service: str,
        event_time: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        error: bool = False,
    ) -> Tuple[Dict[str, float], bool]:
        """Add a single event to the streaming window.

        Returns:
            (features_dict: Dict[str, float], window_rolled: bool)
        """
        with self._lock:
            dt = event_time or datetime.now(timezone.utc)
            w_start = self._floor_time(dt)
            rolled = False

            # Check if this principal's active window has rolled over
            cur_start = self._window_starts.get(principal)
            if cur_start is not None and w_start > cur_start:
                # Close previous window and update history
                prev_events = self._active_windows.get(principal, [])
                if prev_events:
                    h = self._get_history(principal)
                    h["svc"] |= {e["service"] for e in prev_events if e.get("service")}
                    h["ips"] |= {e["ip"] for e in prev_events if e.get("ip")}
                    h["hours"][cur_start.hour] += 1
                    h["counts"].append(len(prev_events))
                self._active_windows[principal] = []
                rolled = True

            self._window_starts[principal] = w_start
            event_record = {
                "event": event_name,
                "service": service.split(".")[0],
                "ip": source_ip,
                "error": 1 if error else 0,
                "time": dt,
            }
            self._active_windows.setdefault(principal, []).append(event_record)

            # Compute features for current active window
            events = self._active_windows[principal]
            features = self._compute_features(principal, events, w_start)
            return features, rolled

    def get_current_features(self, principal: str) -> Dict[str, float]:
        """Return the current 12-feature vector for principal's active window."""
        with self._lock:
            events = self._active_windows.get(principal, [])
            w_start = self._window_starts.get(principal, self._floor_time(datetime.now(timezone.utc)))
            return self._compute_features(principal, events, w_start)

    def reset(self) -> None:
        """Reset all in-memory windows and history."""
        with self._lock:
            self._active_windows.clear()
            self._window_starts.clear()
            self._history.clear()
