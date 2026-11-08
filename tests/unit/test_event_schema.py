from backend.ingestion.validator import validate, reset

GOOD = dict(event_id="e1", event_time="2026-11-08T10:00:00", event_source="s3.amazonaws.com",
            event_name="PutBucketPolicy", principal_id="user-001", source_ip="192.0.2.10",
            aws_region="ap-south-1", source="simulator")


def setup_function():
    reset()


def test_valid_event_is_accepted_and_time_is_utc():
    ev = validate(GOOD)
    assert ev is not None
    assert ev.event_time.utcoffset().total_seconds() == 0


def test_missing_field_is_rejected():
    bad = {k: v for k, v in GOOD.items() if k != "event_name"}
    assert validate(bad) is None


def test_duplicate_is_skipped():
    assert validate(GOOD) is not None
    assert validate(GOOD) is None


def test_unknown_source_is_rejected():
    assert validate({**GOOD, "event_id": "e2", "source": "magic"}) is None


def test_garbage_does_not_crash():
    assert validate({"event_time": "not a date"}) is None
    assert validate("not a dict") is None
