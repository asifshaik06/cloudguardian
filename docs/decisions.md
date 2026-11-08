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
