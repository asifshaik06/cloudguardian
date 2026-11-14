# Project log

## 2026-11-08
- Done: project setup, secret protection, working simulator demo, GitHub repository, README.
- Done (Day 1): validated Pydantic event schema and 5 passing tests.
- Done (Day 2): wrote design decisions.
- Blocked: nothing.
- Next (Day 3): download flaws.cloud logs, record source, hash, size, and licence in datasets\metadata.

## Day 4
- Done: multi-dataset evaluation (controlled, 3 Splunk files, 2 flaws chunks).
- Finding: generated baseline does not match real logs (alert rates 6 to 82 percent).
- Next: review top flaws alerts, fix SENSITIVE list from real data, collect real benign baseline in the live AWS run.

## Day 5
- Found: Z-score missed Splunk S3 public bucket because sensitive features had zero variance in baseline.
- Applied variance floor (documented in decisions.md).
- flaws.cloud top alerts: bursts from one identity with 100 percent errors, manual review pending.

- Day 6: 20-seed controlled benchmark done. F1: Z-score 0.838, IF 0.772, OCSVM 0.764, LOF 0.573. Z-score advantage partly a generator artifact. Final detector choice waits for real benign baseline.

## Day 7 (Phase 1: Security Hardening & System Stability)
- Done: Decoupled monolithic globals into dedicated modules (backend/security.py, backend/state.py, backend/aws_guard.py).
- Done: Implemented ThreadSafeStateStore with RLock, snapshot isolation against concurrent dict iteration crashes, and serialized SQLite WAL access.
- Done: Added token and session-cookie authentication for control endpoints (/api/attack, /api/decide, /api/rollback) with HTTP 401/403/400/404 handling.
- Done: Implemented Telegram user ID verification and callback payload validation to prevent unauthorized remediation approvals.
- Done: Implemented Live AWS safeguards (blocking automatic setup() in live mode unless CG_ALLOW_LIVE_SETUP=1; adding CG_DRY_RUN simulation support).
- Done: Expanded test suite from 5 to 54 automated tests across unit and integration suites (100% passing).
- Next: Phase 2 (Runtime ML pipeline unification with baseline_v1.joblib and TreeSHAP explainability).
