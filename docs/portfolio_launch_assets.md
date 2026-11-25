# ThreatGuard — Professional Portfolio and Viva Launch Assets

- **Author:** Asif Shaik
- **Degree:** B.Tech Computer Science and Engineering (Artificial Intelligence and Machine Learning)
- **Academic Year:** 2026-2027
- **Repository:** https://github.com/asifshaik06/threatguard
- **Local Platform:** http://127.0.0.1:8000
- **Offline Cloud Simulator:** http://127.0.0.1:5000 (Moto AWS Emulator)

---

## 1. Executive Project Summary

ThreatGuard is an evidence-driven cloud security monitoring and threat detection platform engineered to solve critical structural visibility gaps in enterprise cloud infrastructure: multi-hop IAM privilege escalation, alert fatigue, unexplainable machine learning, and unverified automated remediations.

Unlike conventional Cloud Security Posture Management (CSPM) tools that flag isolated misconfigurations, ThreatGuard implements an asynchronous 10-stage defense-in-depth pipeline:
1. Streaming CloudTrail management and data plane event ingestion with schema validation.
2. Identity-grouped sliding-window feature aggregation extracting a 12-dimensional behavioral vector.
3. Unsupervised Isolation Forest anomaly scoring calibrated at decision threshold tau = 0.610.
4. Custom Tree-Path Information Gain Attribution providing plain-English reasoning without third-party blackbox libraries.
5. Deterministic IAM capability multigraph modeling in NetworkX discovering multi-hop privilege escalation trajectories.
6. Quantitative transitive blast radius calculation evaluating reachable assets and exposed records.
7. Evidence-backed finding synthesis with MITRE ATT&CK and NIST CSF control mappings.
8. Dynamic composite 0-100% security posture scoring.
9. Human-in-the-loop remediation governance enforcing operator authentication and side-by-side policy diff review.
10. Independent two-phase closed-loop verification (PASS/PARTIAL/FAIL) and tamper-evident SHA-256 cryptographic hash-chaining stored in SQLite Write-Ahead Logging (WAL) mode.

The platform operates against a local Moto AWS emulator for zero-cost, risk-free academic examination and local testing, while supporting live AWS accounts through strict opt-in environment configuration.

---

## 2. LinkedIn Launch Announcement Draft

Below is an engineering-first launch post designed for software engineering networks, cloud security specialists, and technical recruiters. It avoids artificial hype and focuses strictly on architectural design, algorithmic choices, and verifiable implementation.

```markdown
Over the past several months, I have been engineering ThreatGuard, my B.Tech final-year capstone project in AI and Machine Learning: an evidence-driven cloud security monitoring and threat detection system.

The core motivation came from observing how enterprise cloud environments actually get compromised. Most breaches do not occur because an attacker compromises root directly; they happen because complex, overlapping IAM policies create subtle multi-hop privilege escalation paths (e.g. intern-dev -> dev-role -> cicd-deployer -> admin-role). Traditional CSPMs alert on isolated symptoms, treat machine learning as an unexplainable black box, and rely on blind automated fixes without verifying if the underlying attack vector was eliminated.

ThreatGuard solves these challenges through an end-to-end 10-stage defense-in-depth pipeline:

- Deterministic IAM Capability Graph: Built with NetworkX 3.x, modeling principals, assume-role trust relationships, and condition keys to discover multi-hop privilege escalation paths via shortest-path graph algorithms.
- Quantitative Blast Radius Formulation: Computes transitive reachability, quantifying reachable resources, sensitive data records, and administrative rights exposed from any compromised identity.
- 12-Feature Streaming Feature Pipeline: Aggregates CloudTrail telemetry per IAM identity over sliding windows, extracting call velocity, error ratio, enumeration ratio, and Shannon event entropy.
- Calibrated ML Detection (tau = 0.610): Uses an Isolation Forest ensemble calibrated against controlled synthetic benchmarks to balance precision and recall.
- Explainable AI (XAI) Attribution: Uses custom Tree-Path Information Gain Attribution to compute exact feature contributions and plain-English narratives without third-party blackbox libraries.
- Human-in-the-Loop Remediation: Enforces role-based operator authorization and side-by-side configuration diff reviews before modifying any cloud resource.
- Independent Verification (PASS/PARTIAL/FAIL): Re-queries cloud infrastructure and re-evaluates graph reachability post-remediation to independently confirm risk elimination, with snapshot-based one-click rollback.
- Tamper-Evident Ledger: Stores every detection, operator approval, and remediation state mutation in an append-only SQLite WAL database secured with SHA-256 cryptographic hash-chaining.

The entire system runs locally against an offline Moto AWS simulator (IAM, S3, CloudTrail, EC2, EBS, STS) on localhost:5000, allowing complete reproducible testing without cloud bills, and supports live AWS integration via strict safety guards.

The full codebase, architecture documentation, 287 automated tests, and guided viva demonstration are publicly available on GitHub:
https://github.com/asifshaik06/threatguard

I would welcome technical feedback from cloud architects, security engineers, and DevOps professionals.

#CloudSecurity #DevSecOps #IAM #MachineLearning #Python #NetworkX #CyberSecurity #EngineeringPortfolio
```

---

## 3. Resume and Portfolio Descriptions

### A. Resume Bullet Points (Software Engineer / Security Engineer)

- Engineered ThreatGuard, an evidence-driven cloud security platform in Python 3.12, integrating a 10-stage pipeline across telemetry ingestion, NetworkX graph traversal, Isolation Forest anomaly scoring, and cryptographic auditing.
- Developed a deterministic IAM capability graph using NetworkX to identify multi-hop privilege escalation paths (e.g., 3-hop escalation to AdministratorAccess) and quantify transitive blast radius across cloud assets.
- Implemented streaming sliding-window feature extraction (12 behavioral dimensions) and calibrated an Isolation Forest detector (tau = 0.610) with custom Tree-Path XAI attribution, achieving explainable detection without third-party blackbox dependencies.
- Designed a human-in-the-loop remediation workflow with side-by-side policy diffs, independent two-phase closed-loop verification (PASS/PARTIAL/FAIL), snapshot rollback, and a SHA-256 hash-chained SQLite WAL ledger.
- Authored a comprehensive testing and validation suite of 287 automated pytest tests, secret scanning hooks, and strict WCAG AA accessible frontend interfaces.

### B. Portfolio Website Paragraph

```markdown
ThreatGuard is an open-source, evidence-driven cloud threat detection and posture monitoring system engineered in Python and vanilla JavaScript. Built as a B.Tech final-year capstone project in AI & ML, the platform combines deterministic graph intelligence (NetworkX directed multigraphs) for multi-hop IAM attack-path discovery with unsupervised machine learning (Isolation Forest calibrated at tau = 0.610) for behavioral anomaly detection. ThreatGuard enforces closed-loop operational governance: automated configuration diff generation, human-in-the-loop approval, independent post-remediation verification (PASS/PARTIAL/FAIL), and a SHA-256 cryptographic hash-chained SQLite audit ledger. The platform runs against an offline local Moto AWS emulator for zero-cost academic demonstration and features a responsive, WCAG AA-compliant SOC dashboard.
```

### C. LinkedIn "Featured Project" Blurb

```markdown
ThreatGuard — AI-Based Cloud Security Monitoring and Threat Detection System
An evidence-driven cloud security operations platform featuring NetworkX IAM privilege escalation pathfinding, calibrated Isolation Forest anomaly detection with Tree-Path explainability, human-approved remediation with independent post-fix verification, and a tamper-evident SHA-256 audit ledger. Tested with 287 automated pytest tests and compatible with local Moto AWS emulation and live cloud environments.
```

---

## 4. Recruiter and Engineering Hiring Manager Pitch

### What Makes ThreatGuard Stand Out from Typical Student Projects?

1. **Closed-Loop Verification, Not Blind Automation**: Most student security projects stop at alerting or trigger uncontrolled Lambda functions that blindly modify resources. ThreatGuard requires authenticated operator approval, displays exact side-by-side policy diffs, executes remediations against the cloud infrastructure, and independently re-queries the resource and IAM graph to verify that the attack path is truly eliminated (PASS/PARTIAL/FAIL).
2. **Deterministic Graph Intelligence for Multi-Hop IAM Paths**: Rather than relying on static syntax linters, ThreatGuard models AWS IAM policies as a directed multigraph in NetworkX. It evaluates AssumeRole trust policies, attached managed policies, and condition keys to discover transitive privilege escalation paths (e.g. `user/intern-dev` -> `role/dev-role` -> `role/cicd-deployer` -> `role/admin-role`).
3. **Calibrated Machine Learning with Native Explainability**: Instead of importing a standard classifier and reporting arbitrary accuracy, ThreatGuard implements a 12-feature streaming behavioral pipeline, establishes an empirically calibrated threshold $\tau = 0.610$ against controlled synthetic benchmarks, and computes exact feature attribution via Tree-Path Information Gain without external blackbox dependencies.
4. **Cryptographic Non-Repudiation**: State-mutating actions, findings, approvals, and verification timestamps are chained in an append-only SQLite WAL ledger using SHA-256 block hashing ($H_n = \text{SHA-256}(H_{n-1} \parallel \text{payload}_n)$), allowing instantaneous mathematical validation of ledger integrity.
5. **Engineering Rigor**: 287 passing automated pytest tests, zero hardcoded cloud credentials, strict pre-commit secret scanning, full WCAG AA contrast compliance, zero emoji policy enforcement, and complete offline Moto simulation reproducibility.

---

## 5. Five-Minute Live Demonstration Script (Viva & Technical Interviews)

### Minute 0:00 - 1:00: Problem Context & Architecture Overview
- **Screen**: `#portfolio` or `#architecture`
- **Actions**:
  - Show the project identity, problem statement, and 10-stage pipeline flowchart.
  - Explain the core differentiator: commercial CSPMs alert on isolated symptoms; ThreatGuard connects streaming telemetry, IAM attack paths, calibrated ML anomaly detection, verified human-approved remediation, and cryptographic auditing.
  - Highlight that the platform is currently connected to an offline Moto AWS simulator (`127.0.0.1:5000`), demonstrating zero-cost, fully reproducible execution.

### Minute 1:00 - 2:00: Telemetry Ingestion & Attack Simulation
- **Screen**: `#overview` and `#lab`
- **Actions**:
  - On `#overview`, point out the live Posture Score ring gauge, event throughput, and active KPI cards (Alerts, Incidents, Remediations).
  - Navigate to `#lab` (Simulation Lab). Select Scenario 1 (Privilege Escalation via Insecure AssumeRole) or Scenario 3 (Public S3 Bucket Policy Exposure) and execute the simulated attack against Moto.
  - Return to `#overview`: point out how the posture score recalculates dynamically as new security findings are synthesized.

### Minute 2:00 - 3:00: IAM Capability Graph & Multi-Hop Path Tracing
- **Screen**: `#graph` (IAM Attack Graph)
- **Actions**:
  - Show the force-directed NetworkX topology map containing IAM users, roles, policies, and sensitive resource nodes.
  - Select `user/intern-dev` in the principal selector.
  - Point to the Attack Path Narrative panel: demonstrate the 3-hop privilege escalation path (`intern-dev` -> `dev-role` -> `cicd-deployer` -> `admin-role`).
  - Highlight the Transitive Blast Radius panel: explain how $B(p) = w_r \cdot |R(p)| + w_d \cdot D(p) + w_a \cdot A(p)$ quantifies the compromise scope.

### Minute 3:00 - 4:00: Calibrated ML Detection & Explainable AI (XAI)
- **Screen**: `#threats` (Detection and XAI)
- **Actions**:
  - Display the streaming Anomaly Score chart showing real-time scored event windows plotted against the calibrated threshold $\tau = 0.610$.
  - Show the Controlled Benchmark comparing Isolation Forest against One-Class SVM, LOF, and Random Cut Forest.
  - Inspect an active threat alert: point out the Tree-Path Information Gain feature attribution bars and plain-English narrative explaining exactly which behavioral features (e.g. call velocity, enumeration ratio) triggered the detection.

### Minute 4:00 - 5:00: Verified Remediation, Rollback & Cryptographic Audit
- **Screen**: `#remediation` and `#audit`
- **Actions**:
  - On `#remediation`, select a pending task (e.g. `REM-0001`: Revoke Insecure Wildcard Trust).
  - Review the side-by-side policy diff (Current vs Proposed).
  - Sign in via Operator Login modal (`admin` session).
  - Approve and execute the remediation.
  - Point to the verification result: highlight the `[PASS]` badge and independent audit timestamp confirming that the attack path was re-evaluated and confirmed closed.
  - Demonstrate single-click rollback and show the rollback count metric incrementing.
  - Navigate to `#audit`: display the SHA-256 chained block hashes, click "Verify Hash Chain", and confirm mathematical integrity.

---

## 6. Screenshot Capture Checklist

Capture the following 8 clean screenshots at 1920x1080 resolution (Dark theme recommended) for LinkedIn and technical portfolio presentations:

| No. | Module / View | URL Route | Key Visual Elements to Highlight |
| :-: | :--- | :--- | :--- |
| 1 | Portfolio Executive View | `#portfolio` | ThreatGuard logo, hero overview, problem statement, and 14 technical highlight cards. |
| 2 | SOC Overview Dashboard | `#overview` | Posture ring gauge (e.g. 100%), 6 operational KPI cards, real-time ECharts anomaly timeline, and resource health. |
| 3 | IAM Attack Graph | `#graph` | Force-directed NetworkX topology, highlighted 3-hop attack path for `user/intern-dev`, and Transitive Blast Radius card. |
| 4 | ML Detection & XAI | `#threats` | Anomaly score timeline with $\tau = 0.610$ threshold line, 4-detector benchmark chart, and Tree-Path attribution card. |
| 5 | Simulation Lab | `#lab` | 12 attack scenario cards, MITRE ATT&CK technique tags, and simulated attack launch triggers. |
| 6 | Evidence-Backed Findings | `#findings` | Findings table with severity badges, MITRE tactic tags, and expanded evidence drawer with raw CloudTrail JSON. |
| 7 | Verified Remediation | `#remediation` | Side-by-side configuration diff, operator approval controls, `[PASS]` independent verification badge, and rollback button. |
| 8 | Tamper-Evident Audit Ledger | `#audit` | Chained SHA-256 block hashes, WAL status indicator, and cryptographic "Verify Hash Chain" [PASS] confirmation. |

---

## 7. Viva Examiner Technical Q&A Preparation

### Q1: Why did you build an IAM graph instead of querying AWS IAM Access Analyzer?
**Answer**: AWS IAM Access Analyzer identifies cross-account external access to specific resources, but it does not trace multi-hop transitive privilege escalation paths within an account or organization (e.g. Identity A assuming Role B, which can pass Role C to an EC2 instance that assumes Role D). ThreatGuard constructs a complete directed multigraph using NetworkX, modeling both direct permissions and trust policies to run Dijkstra and BFS shortest-path algorithms that discover non-obvious multi-hop escalation trajectories.

### Q2: Why Isolation Forest over supervised deep learning?
**Answer**: Cloud control plane logs exhibit severe class imbalance (99.99%+ of events are benign) and novel attack techniques do not resemble historical training labels. Supervised models overfit to known attack patterns and fail on zero-day attacks. Isolation Forest isolates anomalies by randomly partitioning feature space; anomalous points require substantially fewer partitions to isolate. Combined with empirical calibration ($\tau = 0.610$) and Tree-Path attribution, it delivers high throughput, low memory footprint, and native interpretability.

### Q3: Why is independent post-remediation verification necessary?
**Answer**: In cloud security, an API call returning HTTP 200 does not prove that a security risk is resolved. For example, modifying an IAM policy may leave an active session token valid, or an S3 bucket policy fix may still leave bucket ACLs publicly readable. ThreatGuard enforces closed-loop verification: after remediation execution, it independently re-queries the cloud provider for raw configuration state and re-traverses the IAM reachability graph. If reachability persists, the task is marked `PARTIAL` or `FAIL`.

### Q4: How does the SHA-256 hash-chain ledger prevent tampering?
**Answer**: The audit trail implements a blockchain-inspired linked ledger stored in SQLite WAL mode. Each audit row computes its hash as $H_n = \text{SHA-256}(H_{n-1} \parallel \text{timestamp} \parallel \text{action} \parallel \text{payload})$. If an attacker with direct database access alters any past record or deletes a row, the cryptographic chain is broken. The "Verify Hash Chain" function re-computes every hash from the genesis block to detect any retroactively modified or inserted entries.
