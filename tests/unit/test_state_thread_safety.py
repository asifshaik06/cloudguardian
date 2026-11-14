"""Unit tests for ThreadSafeStateStore and SQLite Hash-Chained Audit Trail:
- Concurrent state reads and mutations (preventing dict size change errors)
- Cryptographic hash-chaining verification
- Database tampering detection
- Rollback event counting
"""
import concurrent.futures
import hashlib
import os
import sqlite3
import tempfile
import threading
import time
import pytest

from backend.state import StateStore


@pytest.fixture
def temp_store():
    # Create temporary database file for test isolation
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    store = StateStore(db_path=path, check_same_thread=False)
    yield store
    store.close()
    import gc
    gc.collect()
    for _ in range(5):
        try:
            if os.path.exists(path):
                os.remove(path)
            for ext in ("-wal", "-shm"):
                f = path + ext
                if os.path.exists(f):
                    os.remove(f)
            break
        except PermissionError:
            time.sleep(0.1)


def test_state_store_findings_crud(temp_store):
    # Create finding
    temp_store.set_finding("s3", {"id": "s3", "status": "pending", "title": "S3 Public"})
    f = temp_store.get_finding("s3")
    assert f is not None
    assert f["status"] == "pending"

    # Update finding
    updated = temp_store.update_finding("s3", status="fixed", verified=True)
    assert updated["status"] == "fixed"
    assert updated["verified"] is True

    # Retrieve all findings
    all_f = temp_store.get_all_findings()
    assert len(all_f) == 1
    assert all_f[0]["id"] == "s3"

    # Pop finding
    popped = temp_store.pop_finding("s3")
    assert popped["id"] == "s3"
    assert temp_store.get_finding("s3") is None


def test_concurrent_finding_reads_and_writes_no_race_crash(temp_store):
    """Verify that multiple threads concurrently reading and modifying findings
    never raise 'RuntimeError: dictionary changed size during iteration'."""
    stop_event = threading.Event()
    errors = []

    def writer_task(worker_id):
        keys = ["s3", "ct", "sg", "key", f"worker-{worker_id}"]
        while not stop_event.is_set():
            try:
                for k in keys:
                    temp_store.set_finding(k, {"id": k, "status": "pending", "val": worker_id})
                    temp_store.update_finding(k, status="fixed", verified=True)
                    if worker_id % 2 == 0:
                        temp_store.pop_finding(k)
            except Exception as e:
                errors.append(e)

    def reader_task():
        while not stop_event.is_set():
            try:
                # Iterate across all findings via snapshot method
                findings = temp_store.get_all_findings()
                for f in findings:
                    _ = f.get("status")
                # Also read dictionary map
                f_map = temp_store.get_findings_map()
                for k, v in f_map.items():
                    _ = v.get("val")
            except Exception as e:
                errors.append(e)

    threads = []
    # 5 writer threads and 5 reader threads
    for i in range(5):
        threads.append(threading.Thread(target=writer_task, args=(i,)))
        threads.append(threading.Thread(target=reader_task))

    for t in threads:
        t.start()

    # Run intense concurrent mutations for 0.5 seconds
    time.sleep(0.5)
    stop_event.set()

    for t in threads:
        t.join(timeout=2.0)

    # Assert no dictionary mutation race conditions occurred
    assert len(errors) == 0, f"Encountered concurrency errors: {errors}"


def test_sqlite_audit_hash_chain_integrity(temp_store):
    # Add series of audit entries
    temp_store.append_audit_entry("Entry 1: System Boot")
    temp_store.append_audit_entry("Entry 2: Attack Detected")
    temp_store.append_audit_entry("Entry 3: Remediation Approved")
    temp_store.append_audit_entry("Entry 4: Verified Cloud State")

    # Verify audit query and cryptographic chain
    res = temp_store.query_audit_trail()
    assert res["count"] == 4
    assert res["chain_ok"] is True
    assert res["first_bad"] is None
    assert len(res["rows"]) == 4


def test_sqlite_audit_tamper_detection(temp_store):
    # Add entries
    temp_store.append_audit_entry("Log 0")
    temp_store.append_audit_entry("Log 1")
    temp_store.append_audit_entry("Log 2")

    # Verify before tampering
    res_before = temp_store.query_audit_trail()
    assert res_before["chain_ok"] is True

    # Tamper with row 1 directly in SQLite
    db_path = temp_store._db_path
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("UPDATE audit SET text = '[00:00:00] MALICIOUS_TAMPER' WHERE i = 1")
        conn.commit()
    finally:
        conn.close()

    # Query audit trail and verify tampering is flagged
    res_after = temp_store.query_audit_trail()
    assert res_after["chain_ok"] is False
    assert res_after["first_bad"] == 1


def test_concurrent_audit_writes(temp_store):
    """Verify that multiple threads can concurrently append audit entries
    without database lock contention and the resulting hash chain remains valid."""
    def worker(worker_id):
        for i in range(15):
            temp_store.append_audit_entry(f"Worker {worker_id} event {i}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    res = temp_store.query_audit_trail(limit=200)
    assert res["count"] == 75
    assert res["chain_ok"] is True


def test_count_rollback_events(temp_store):
    assert temp_store.count_rollback_events() == 0
    temp_store.append_audit_entry("ROLLED BACK s3 to its pre-fix state")
    temp_store.append_audit_entry("Normal audit entry")
    temp_store.append_audit_entry("ROLLED BACK sg to its pre-fix state")
    assert temp_store.count_rollback_events() == 2
