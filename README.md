# CloudGuardian

Explainable AI-assisted cloud security platform. B.Tech CSE (AI & ML) final year project, 2026-27.

CloudGuardian watches a cloud account for security problems, explains each one in plain English,
and fixes it only after a human approves. Everything runs against a local AWS emulator (moto),
so it needs no AWS account and costs nothing.

## What it does today

- Real boto3 calls against a simulated AWS account (S3, CloudTrail, EC2 security groups, IAM).
- Attack simulator: public S3 bucket, CloudTrail switched off, SSH open to the world, stolen access key.
- Detection: a continuous scanner checks live resource state against CIS-style rules,
  and an Isolation Forest flags unusual access-key behaviour.
- Plain-English explanations: what happened, why it matters, and how the system knew.
- Human-approved remediation: approve or reject in the dashboard or verified Telegram, then the fix is applied
  and verified by checking the cloud again.
- Cryptographic hash-chained audit trail (SQLite in WAL mode) with tamper verification and rollback.
- Thread-safe state architecture protecting against concurrent race conditions.
- Authenticated control plane: session-cookie and `X-API-Key` token verification.
- Safe Live AWS safeguards: automatic resource provisioning is strictly blocked on live accounts without explicit operator flags.
- Comprehensive test suite (54 unit and integration tests).

## Run locally (Windows PowerShell)

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt python-dotenv
    moto_server -p 5000        # terminal 1: fake AWS (restart it for a clean account)
    python app.py              # terminal 2
    # open http://localhost:8000

Copy `.env.example` to `.env` for local settings.

## Running Tests

Run the full automated test suite (54 tests):

    python -m pytest

## Security notes

- **API Protection:** Control endpoints (`/api/attack`, `/api/decide`, `/api/rollback`) require authentication via session cookie or `X-API-Key` header.
- **Telegram Verification:** Callback actions are verified against `TG_CHAT_ID` and `TG_ALLOWED_USERS`. Unauthorized users are rejected and audited.
- **AWS Live Protection:** Running with `CG_LIVE_AWS=1` will **never** automatically provision resources unless `CG_ALLOW_LIVE_SETUP=1` is explicitly set. Attack simulation is strictly disabled in live mode.
- **Dry-Run Mode:** Enable `CG_DRY_RUN=1` to simulate remediations without modifying cloud infrastructure.
- **Secret Masking:** Account numbers, access keys, and Telegram tokens are redacted before writing to audit logs.

## Roadmap

- [x] Phase 1: Security Hardening, Thread Safety, API Auth & Safe AWS Mode (Completed, 54 passing tests)
- [x] Phase 2: ML Engine & XAI Unification — 12-Feature Windowing, TreeSHAP, baseline_v1.joblib, CloudTrail Replay (Completed, 65 passing tests)
- [ ] Phase 3: IAM Capability Graph & Attack Path Simulation (NetworkX blast radius)
- [ ] Phase 4: Infrastructure as Code (Terraform) and CI/CD Quality Gates

## Status

Phase 2 Complete. Unified 12-feature ML detection engine, TreeSHAP explainability, and CloudTrail log replay active.
