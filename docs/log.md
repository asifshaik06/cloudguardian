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
