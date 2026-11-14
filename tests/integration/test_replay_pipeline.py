"""Integration tests for CloudTrail Log Replay and Streaming Pipeline:
- Pydantic schema validation & deduplication during live ingestion
- Dataset listing API
- Replaying real attack datasets (Splunk S3 Public Bucket & Splunk Bedrock)
- Authentication and error handling on replay endpoints
"""
import pytest
from app import app, pipeline, store
from backend.security import AUTH_HEADER, get_active_api_key


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers():
    return {AUTH_HEADER: get_active_api_key()}


def test_pipeline_ingest_validates_and_stores():
    ev, res = pipeline.ingest(
        event_name="ListBuckets",
        service="s3",
        principal_id="test-analyst",
        country="US",
        source="simulator",
    )
    assert ev is not None
    assert ev.event_name == "ListBuckets"
    assert ev.principal_id == "test-analyst"
    assert res is not None
    assert "scores" in res


def test_replay_datasets_listing_api(client):
    resp = client.get("/api/replay/datasets")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) >= 3
    dataset_ids = [d["id"] for d in data]
    assert "splunk_s3_public_bucket" in dataset_ids
    assert "splunk_bedrock" in dataset_ids
    assert "splunk_security_scanner" in dataset_ids


def test_replay_splunk_s3_attack(client, auth_headers):
    resp = client.post("/api/replay/splunk_s3_public_bucket", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["events_replayed"] > 0
    assert "splunk_s3_public_bucket.json" in data["dataset"]

    # Verify audit log recorded the replay
    audit_res = store.query_audit_trail(query="REPLAY completed")
    assert audit_res["count"] > 0


def test_replay_splunk_bedrock(client, auth_headers):
    resp = client.post("/api/replay/splunk_bedrock", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["events_replayed"] > 0


def test_replay_unauthorized_returns_401(client):
    resp = client.post("/api/replay/splunk_bedrock")
    assert resp.status_code == 401


def test_replay_unknown_dataset_returns_404(client, auth_headers):
    resp = client.post("/api/replay/nonexistent_dataset", headers=auth_headers)
    assert resp.status_code == 404
    data = resp.get_json()
    assert data["ok"] is False
    assert "Unknown dataset" in data["error"]
