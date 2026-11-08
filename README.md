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
- Human-approved remediation: approve or reject in the dashboard, then the fix is applied
  and verified by checking the cloud again.
- Audit trail and a data-source badge (Simulator or Live AWS) with the raw API responses shown.
- Optional Telegram alerts with Approve and Reject buttons.

## Run locally (Windows PowerShell)

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt python-dotenv
    moto_server -p 5000        # terminal 1: fake AWS (restart it for a clean account)
    python app.py              # terminal 2
    # open http://localhost:8000

Copy .env.example to .env for local settings.

## Security notes

- Never commit .env, AWS keys, or Telegram tokens. .gitignore and a gitleaks pre-commit hook help prevent it.
- Account IDs and key IDs are masked in the audit log.
- Live AWS mode (CG_LIVE_AWS=1) is optional and untested. Use a sandbox account only.

## Roadmap

- Validated event schema (Pydantic) and CloudTrail log replay
- Five-minute behavioural features with Z-score, Isolation Forest, LocalOutlierFactor and OneClassSVM
- SHAP explanations and an IAM capability graph
- Rollback, hash-chained audit log, Terraform, and CI with Checkov
- Evaluation with measured results

## Status

Work in progress. Demonstrations run only in the local simulated environment.
