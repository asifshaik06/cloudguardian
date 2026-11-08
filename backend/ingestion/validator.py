import logging
from pydantic import ValidationError
from .event_schema import Event

log = logging.getLogger("cloudguardian.ingest")
_seen = set()


def reset():
    _seen.clear()


def validate(raw):
    """Return an Event, or None if the record is invalid or a duplicate. Never raises."""
    try:
        ev = Event(**raw)
    except (ValidationError, TypeError) as e:
        log.warning("rejected event: %s", str(e)[:200])
        return None
    if ev.event_id in _seen:
        log.info("duplicate event %s skipped", ev.event_id)
        return None
    _seen.add(ev.event_id)
    return ev
