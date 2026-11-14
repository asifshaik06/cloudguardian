"""Unified event ingestion pipeline connecting Pydantic validation,
rolling window aggregation, and runtime ML anomaly detection.
"""
from datetime import datetime, timezone
import logging
from typing import Any, Callable, Dict, Optional, Tuple
import uuid

from backend.ingestion.event_schema import Event
from backend.ingestion.validator import validate
from backend.ml_engine.detector import RuntimeDetector
from backend.ml_engine.window_aggregator import StreamingWindowAggregator
from backend.state import StateStore

logger = logging.getLogger("cloudguardian.stream")


class EventStreamPipeline:
    """End-to-end ingestion and scoring pipeline."""

    def __init__(
        self,
        store: StateStore,
        aggregator: Optional[StreamingWindowAggregator] = None,
        detector: Optional[RuntimeDetector] = None,
        on_anomaly: Optional[Callable[[str, list], None]] = None,
    ):
        self.store = store
        self.aggregator = aggregator or StreamingWindowAggregator()
        self.detector = detector or RuntimeDetector()
        self.on_anomaly = on_anomaly

    def ingest(
        self,
        event_name: str,
        service: str,
        principal_id: str,
        country: str = "IN",
        source: str = "simulator",
        source_ip: Optional[str] = None,
        error_code: Optional[str] = None,
        event_time: Optional[datetime] = None,
        aws_region: str = "us-east-1",
        event_id: Optional[str] = None,
    ) -> Tuple[Optional[Event], Optional[Dict[str, Any]]]:
        """Ingest, validate, aggregate, and score an event through the pipeline.

        Returns:
            (validated_event, detection_result)
        """
        now_dt = event_time or datetime.now(timezone.utc)
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=timezone.utc)

        raw = {
            "event_id": event_id or f"ev-{uuid.uuid4().hex[:12]}",
            "event_time": now_dt,
            "event_source": f"{service}.amazonaws.com" if not service.endswith(".com") else service,
            "event_name": event_name,
            "principal_id": principal_id,
            "source_ip": source_ip or "10.0.0.1",
            "aws_region": aws_region,
            "error_code": error_code,
            "source": source,
        }

        # 1. Pydantic schema validation & deduplication
        ev = validate(raw)
        if ev is None:
            logger.debug("Rejected or duplicate event: %s", raw["event_id"])
            return None, None

        # 2. Append to dashboard and telemetry storage
        time_str = ev.event_time.strftime("%H:%M:%S")
        self.store.append_event({
            "t": time_str,
            "name": ev.event_name,
            "src": ev.event_source.split(".")[0],
            "user": ev.principal_id,
            "country": country,
            "mode": "Live AWS" if source == "live" else "Simulator",
        })

        # 3. Add to rolling window aggregator
        features, _ = self.aggregator.add_event(
            principal=ev.principal_id,
            event_name=ev.event_name,
            service=ev.event_source.split(".")[0],
            event_time=ev.event_time,
            source_ip=ev.source_ip,
            error=bool(ev.error_code),
        )

        # 4. Multi-detector ML scoring with TreeSHAP explanations
        det_result = self.detector.score_window(features)
        kind = "attack" if det_result["is_anomaly"] else "baseline"

        self.store.log_telemetry_event(
            name=ev.event_name,
            src=ev.event_source.split(".")[0],
            user=ev.principal_id,
            country=country,
            kind=kind,
            mode="Live AWS" if source == "live" else "Simulator",
        )
        self.store.add_anomaly_score(det_result["score"], kind)

        # 5. Trigger finding on anomaly
        if det_result["is_anomaly"]:
            self.store.set_anomaly_active(True)
            if self.on_anomaly:
                self.on_anomaly("key", det_result["explanations"])

        return ev, det_result
