# Design decisions

Each entry: decision, reason, alternatives considered.

## 1. Simulated AWS (moto) instead of a live AWS account
- Reason: no cost, no risk to real resources, and anyone can reproduce the demo for free.
- The code makes real boto3 calls, so a live adapter can be enabled later without rewriting detection.
- Alternatives: a live AWS account (the Free plan ends before the final demo), LocalStack (needs an account and token).

## 2. One common internal event schema (Pydantic)
- Reason: simulator events, replayed CloudTrail logs, and a future live feed must all enter the same pipeline.
- Invalid or duplicate events are logged and skipped, so bad data never crashes detection.
- Alternatives: passing raw CloudTrail dictionaries around (fragile, different fields per source).

## 3. Human approval before every remediation
- Reason: an automatic fix can break a working system, so a person decides.
- Every fix is verified by checking the cloud again, and every action goes to an audit trail.
- Alternatives: fully automatic remediation (faster but riskier).

## 4. Rules for known misconfigurations, ML for unusual behaviour
- Reason: rules are exact for things like a public bucket. Machine learning is useful where no fixed rule exists.
- The ML model is compared with a simple statistical baseline, so its value is measured.

## 5. Open question: model features
- The first demo model uses hour, country, and request rate on single events.
- Planned: five-minute behavioural windows per identity, with relative features, to avoid a mismatch between generated and real data.

## 6. Z-score variance floor (added after seeing results)
- The benign baseline never contains sensitive actions, so those features had zero variance and the z-score could not react to them.
- Fix: divide by max(std, 0.1) in the Z-score baseline. Decided after seeing the Splunk S3 public bucket result, so the 7 real windows are development cases, not a clean test.


## 7. Reentrant Lock (RLock) and snapshot isolation for state concurrency
- Reason: Multiple background threads (scanner, telemetry, Telegram, Flask request workers) read and write findings and event collections simultaneously. Direct dictionary iteration without locking causes intermittent `RuntimeError: dictionary changed size during iteration`.
- Fix: Centralized `StateStore` with `threading.RLock()` and snapshot copies for all dictionary iteration.
- Alternatives: Multi-process architecture (too heavy for a local zero-cost single-process demo), asyncio (would require rewriting Flask and synchronous boto3 calls).

## 8. Dual session-cookie and API-key authentication
- Reason: Protect control plane endpoints (`/api/attack`, `/api/decide`, `/api/rollback`) against unauthorized network callers, malicious browser extensions, and CSRF attacks without breaking the zero-config browser dashboard experience.
- Fix: The browser receives an HTTP-only `cg_session` cookie on visiting `/`, while programmatic API clients can supply `X-API-Key` or `Authorization: Bearer <key>`.
- Alternatives: Basic Auth (browser popup), static unauthenticated endpoints (security risk).

## 9. Fail-safe Live AWS setup guard and Telegram user validation
- Reason: Accidental live AWS modifications could incur unintended cloud infrastructure charges, damage real infrastructure, or modify operational accounts. Unauthorized Telegram users in shared chats could approve or reject remediations.
- Fix: `safe_setup()` strictly blocks automatic resource provisioning in Live AWS mode unless `CG_ALLOW_LIVE_SETUP=1` is explicitly configured. Telegram callback queries check `from.id` against `TG_CHAT_ID` and `TG_ALLOWED_USERS` before executing `decide()`.

## 10. Streaming 12-feature window aggregator with cold-start history
- Reason: Unify offline research feature engineering with runtime inference. A rolling 5-minute window matches CloudTrail batch arrival rhythms, while tracking principal history prevents false positives for newly created credentials during their first 3 windows.
- Fix: `StreamingWindowAggregator` computes real-time vectors for call_count, call_velocity, error_ratio, sensitive_count, iam_change_count, first_service_ratio, first_ip, off_hours, and event_entropy.

## 11. Tree-path feature attribution without binary C-dependencies
- Reason: Project evaluation requires explainable AI (XAI) that grounds feature importance mathematically rather than using ad-hoc z-score shares. External third-party attribution libraries often require heavy binary dependencies or C-compilers.
- Fix: Custom pure-Python/NumPy tree-path traversal over scikit-learn's 200 `ExtraTreeRegressor` estimators in the Isolation Forest to measure sample density drops per split.

## 12. Historical CloudTrail log replay engine
- Reason: Evaluating detectors against simulated toy traffic is insufficient for thesis defense. Evaluators need to see real attack datasets (Splunk Attack Data, flaws.cloud) stream through the live dashboard in real time.
- Fix: `backend/replay.py` provides streaming playback of raw CloudTrail json/json.gz files directly into the Pydantic ingestion pipeline.
