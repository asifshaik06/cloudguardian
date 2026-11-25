# ThreatGuard – AI-Based Cloud Security Monitoring and Threat Detection System

**AI-Based Cloud Security Monitoring, IAM Attack-Path Intelligence, and Verified Incident Response**

ThreatGuard is an enterprise-grade cloud security operations and posture management platform designed for Amazon Web Services (AWS) architectures. It combines deterministic Center for Internet Security (CIS) compliance checking with unsupervised machine learning anomaly detection, calculates multi-hop identity privilege escalation graphs, explains detections through decision-tree feature attribution, and enforces human-in-the-loop remediations that are independently verified against live infrastructure.

The platform operates in an isolated environment using a local AWS emulator (`moto`), eliminating external cloud infrastructure costs while providing deterministic reproducibility for security engineers, cloud architects, and security operations teams.

---

## Table of Contents

- [1. Project Overview](#1-project-overview)
- [2. Problem Statement](#2-problem-statement)
- [3. Project Objectives](#3-project-objectives)
- [4. Key Features](#4-key-features)
- [5. System Architecture](#5-system-architecture)
- [6. Technology Stack](#6-technology-stack)
- [7. Project Directory Structure](#7-project-directory-structure)
- [8. Dashboard Module Walkthrough](#8-dashboard-module-walkthrough)
- [9. Machine Learning Detection Methodology](#9-machine-learning-detection-methodology)
- [10. Twelve-Dimensional Feature Engineering](#10-twelve-dimensional-feature-engineering)
- [11. Explainable AI (XAI) Methodology](#11-explainable-ai-xai-methodology)
- [12. IAM Attack-Path Analysis](#12-iam-attack-path-analysis)
- [13. Blast-Radius Analysis](#13-blast-radius-analysis)
- [14. Alert and Incident Lifecycle](#14-alert-and-incident-lifecycle)
- [15. Attack Simulation Architecture](#15-attack-simulation-architecture)
- [16. Human-in-the-Loop Remediation](#16-human-in-the-loop-remediation)
- [17. Independent Verification and Rollback](#17-independent-verification-and-rollback)
- [18. Security Posture Scoring](#18-security-posture-scoring)
- [19. Tamper-Evident Audit Ledger](#19-tamper-evident-audit-ledger)
- [20. FinOps Cost Intelligence and Demo Scenario](#20-finops-cost-intelligence-and-demo-scenario)
- [21. Operator Authentication and Access Control](#21-operator-authentication-and-access-control)
- [22. Installation and Configuration](#22-installation-and-configuration)
- [23. Running the Application](#23-running-the-application)
- [24. Running Automated Tests and Quality Verification](#24-running-automated-tests-and-quality-verification)
- [25. Security Scanning](#25-security-scanning)
- [26. REST API Documentation](#26-rest-api-documentation)
- [27. Security and Simulator Limitations](#27-security-and-simulator-limitations)
- [28. Future Improvements](#28-future-improvements)
- [29. License and Project Attribution](#29-license-and-project-attribution)

---

## 1. Project Overview

Modern cloud environments are heavily identity-centric. As organizations scale infrastructure on AWS, perimeter-based security models become ineffective. Cloud security operations teams require platforms that can continuously monitor infrastructure configurations, analyze identity trust relationships, detect behavioral anomalies in management API activity, and remediate confirmed risks with auditability.

ThreatGuard unifies these operational requirements into a single cohesive architecture. By combining behavioral API analytics, graph theory, deterministic compliance rules, and closed-loop verification, ThreatGuard provides security operations teams with complete situational awareness across their cloud estate.

---

## 2. Problem Statement

Enterprise cloud security operations face four fundamental operational challenges:

1. **Alert Fatigue and Lack of Context:** Traditional SIEM platforms generate high volumes of isolated alerts without correlating related activities or providing clear explanations of anomalous behavior.
2. **Hidden Multi-Hop Privilege Escalation:** Static IAM analyzers evaluate user policies in isolation. Attackers frequently exploit combinations of seemingly low-risk permissions across intermediate roles to move laterally and achieve administrative access.
3. **Unverified Automated Remediation:** Automated "self-healing" systems frequently declare success based solely on whether an API call returned an HTTP 200 response, without verifying that the underlying misconfiguration was truly eliminated in the cloud environment.
4. **Unreliable Audit Trails:** Forensic investigations require high confidence that recorded security events, approvals, and remediation actions have not been altered or deleted after the fact.

---

## 3. Project Objectives

- **Deliver Transparent Anomaly Detection:** Implement calibrated unsupervised machine learning to detect behavioral deviations in CloudTrail management events while providing mathematically grounded feature attribution for every detection.
- **Model Identity Relationships Graphically:** Construct an in-memory directed multigraph of all IAM principals, permissions, and trust relationships to identify transitive privilege escalation vectors before attackers exploit them.
- **Enforce Verified Remediation:** Implement a human-in-the-loop approval workflow where remediation actions are verified through direct cloud state probing rather than execution assumptions.
- **Guarantee Audit Integrity:** Maintain a tamper-evident audit ledger using cryptographic hash chaining to provide mathematically verifiable proof of operational history.
- **Provide Safe Offline Operation:** Execute entirely against local cloud emulation to enable safe, reproducible testing without cloud vendor costs or credential exposure.

---

## 4. Key Features

- **Hybrid Detection Pipeline:** Integrates deterministic CIS AWS Foundation Benchmark rule scanning with statistical and machine learning anomaly detection engines.
- **Calibrated Isolation Forest:** An unsupervised ensemble of 200 isolation trees calibrated to a 1.0% baseline false positive rate ($\tau = 0.610$) on 12-dimensional temporal feature vectors.
- **Tree-Path Information Gain Attribution:** Calculates the exact decision-tree split contribution for each feature along the isolation path, explaining detections without external black-box approximations.
- **NetworkX IAM Attack Graph:** Directed multigraph modeling of IAM users, roles, policies, and AWS service boundaries with cycle-safe pathfinding and blast-radius quantification.
- **Closed-Loop Remediation:** Enforces four distinct remediation phases (`Pending` -> `Approved` -> `Applied` -> `Verified [PASS]`) with pre-remediation and post-remediation configuration diffs.
- **Independent State Verification:** Post-remediation verification queries cloud APIs directly to prove vulnerability elimination before updating posture state.
- **Atomic 1-Click Rollback:** Automatically captures pre-remediation configurations to allow instant state reversal with cryptographic logging.
- **Tamper-Evident SHA-256 Ledger:** SQLite-backed audit log linked with SHA-256 hash chaining, enabling dynamic mathematical verification of chain integrity.
- **Attack Simulation Lab:** Built-in scenario execution engine allowing operators to simulate real attack chains and evaluate custom IAM policies in an isolated sandbox.
- **Cost Intelligence and AWS Optimization:** Evaluates simulated AWS infrastructure (`EC2`, `EBS`, `S3`, `IAM`, `CloudTrail`, `STS`) against a configurable local pricing dataset (`backend/cost/pricing_dataset.json`) to produce resource-level cost estimates, explicit status indicators, and optimization findings with deduplicated savings.
- **In-Dashboard Cost Optimization Reports:** Generates structured 11-section reports and plain-text narratives persisted in SQLite (`cost_reports`), paired with a compact collapsible Report History bar above a full-width Report Detail view (no external PDF/CSV export endpoints).
- **Operator-Controlled FinOps Demo Scenario:** Optional, idempotent Moto scenario inside Simulation Lab (`#lab`) provisioning tagged EC2 instances, attached/unattached EBS volumes, and populated S3 buckets with full lifecycle reset support while preserving baseline `safe_setup()` resources.
- **High-Resolution Responsive SOC Dashboard:** Single-page interface featuring 2X supersampled Canvas graphics, native vector SVG charts, and responsive layouts verified across desktop, laptop, tablet, and mobile viewports.

---

## 5. System Architecture

ThreatGuard is structured into five operational stages:

```mermaid
flowchart TD
    subgraph INGESTION["1. Telemetry Ingestion and Emulation"]
        MOTO["Moto AWS Simulator (Port 5000)<br>Emulates S3, IAM, EC2, CloudTrail, STS"]
        PROBES["Boto3 SDK Probes and Collectors"]
        REPLAY["CloudTrail Telemetry Replay Engine"]
        MOTO --> PROBES
        REPLAY --> PROBES
    end

    subgraph DETECTION["2. Hybrid Detection Pipeline"]
        CIS["CIS Benchmark Rule Scanner<br>(S3, CloudTrail, Security Groups, IAM)"]
        AGG["Temporal 12-Feature Window Aggregator<br>(5-Minute Sliding Identity Windows)"]
        IFOREST["Isolation Forest (200 Trees)<br>Calibrated Threshold Tau = 0.610"]
        BENCH["Multi-Model Evaluation Benchmark<br>(LOF, One-Class SVM, Z-Score)"]
        PROBES --> CIS
        PROBES --> AGG
        AGG --> IFOREST
        AGG --> BENCH
    end

    subgraph GRAPH_XAI["3. Graph Intelligence and Explainable AI"]
        NX["NetworkX IAM Capability Graph<br>(Directed Multigraph)"]
        PATHS["Cycle-Safe DFS Pathfinding<br>(Privilege Escalation Chains)"]
        BLAST["Dynamic Blast-Radius Quantification"]
        XAI["Tree-Path Information Gain Attribution<br>(Mathematical Decision Contributions)"]
        CIS --> NX
        PROBES --> NX
        NX --> PATHS
        NX --> BLAST
        IFOREST --> XAI
    end

    subgraph RESPONSE["4. Incident Response and Closed-Loop Remediation"]
        ALERTS["SOC Alerts Console<br>(Status Lifecycle and Escalation)"]
        INCIDENTS["Incident Workspace<br>(Evidence Snapshot Preservation)"]
        HITL["Human-in-the-Loop Operator Authorization Gate"]
        VERIFY["Independent Post-Remediation Cloud Verifier<br>(Probes Live Infrastructure)"]
        ROLLBACK["1-Click Atomic State Rollback Engine"]
        CIS --> ALERTS
        IFOREST --> ALERTS
        PATHS --> ALERTS
        ALERTS --> INCIDENTS
        ALERTS --> HITL
        HITL --> VERIFY
        VERIFY --> ROLLBACK
    end

    subgraph AUDIT["5. Cryptographic Governance and Posture"]
        POSTURE["Authoritative Posture Score (0-100%)<br>(Severity-Weighted Risk Deductions)"]
        LEDGER["Tamper-Evident SHA-256 Hash-Chained Ledger<br>(Cryptographic Verification)"]
        VERIFY --> POSTURE
        VERIFY --> LEDGER
        ROLLBACK --> LEDGER
    end
```

In parallel with security detection, the **Cost Intelligence & FinOps Pipeline** (`backend/cost/`) queries the active Moto/AWS clients, maps observed resources onto the versioned pricing configuration, synthesizes classified optimization findings (`confirmed` vs `inferred`), routes approved cost actions (`FIN-*`) through the shared HITL remediation verifier, and snapshots immutable 11-section reports to SQLite.

---

## 6. Technology Stack

| Component | Technology | Version | Functional Role |
| :--- | :--- | :--- | :--- |
| **Backend Framework** | Python / Flask | 3.12 / 3.1.3 | Core application server, REST APIs, session and CSRF control |
| **Frontend Architecture**| HTML5 / CSS3 / JavaScript | ES6+ / Native | Responsive single-page SOC and FinOps interface, reactive view controllers, modal dialogs |
| **Cloud Simulation** | Moto | 5.2.5 | Local standalone AWS emulator providing EC2, EBS, S3, IAM, CloudTrail, and STS |
| **AWS SDK** | Boto3 / Botocore | 1.43.126 | Resource configuration probing, FinOps inventory collection, and independent remediation verification |
| **Graph Modeling** | NetworkX | 3.7 | In-memory directed multigraph analysis, pathfinding, and blast radius |
| **Machine Learning** | Scikit-Learn / Joblib | 1.9.1 / 1.6.0 | Isolation Forest, Local Outlier Factor, One-Class SVM, model artifact persistence |
| **Data Validation** | Pydantic | 2.14.3 | Declarative schema validation, event models, and scenario definitions |
| **Numerical Computing** | NumPy / SciPy / Pandas | 2.5.4 / 1.18.1 / 3.1.1 | Feature aggregation, matrix math, statistical threshold calibration |
| **Data Visualization** | Apache ECharts | 6.1.0 | Vector SVG charts and 2X supersampled Canvas timelines, attack graphs, and spend breakdowns |
| **Data Persistence** | SQLite (WAL mode) | 3.x | SOC store, incident records, immutable `cost_reports` snapshots, and SHA-256 audit ledger |
| **Testing and Security**| Pytest / Secret & Quality Scripts | 9.2.0 | 287-test automated regression suite, emoji audit, secret scanning, and Gitleaks pre-commit integration |

---

## 7. Project Directory Structure

```
threatguard/
|-- app.py                      # Flask entry point and lifecycle orchestration
|-- requirements.txt            # Core Python dependencies
|-- AGENTS.md                   # Operational guidelines and safety invariants
|-- .env.example                # Environment configuration template
|-- .pre-commit-config.yaml     # Pre-commit secret scanning hooks
|-- backend/                    # Core backend service modules
|   |-- aws_guard.py            # Local Moto endpoint isolation and lockout
|   |-- dashboard_api.py        # Aggregated telemetry and posture endpoints
|   |-- posture.py              # Security posture score calculation engine
|   |-- replay.py               # CloudTrail telemetry replay processor
|   |-- security.py             # Auth verification and bounded key reader
|   |-- state.py                # Thread-safe in-memory state store & SQLite ledger/reports
|   |-- telemetry.py            # Background loops and metrics service
|   |-- cost/                   # FinOps Cost Intelligence, optimization, and demo scenario
|   |   |-- api.py
|   |   |-- demo_scenario.py
|   |   |-- estimator.py
|   |   |-- inventory.py
|   |   |-- optimizer.py
|   |   |-- pricing.py
|   |   |-- pricing_dataset.json
|   |   |-- remediation.py
|   |   |-- reports.py
|   |-- graph/                  # IAM capability graph and attack pathfinder
|   |   |-- api.py
|   |   |-- blast_radius.py
|   |   |-- escalation.py
|   |   |-- iam_graph.py
|   |   |-- policy_evaluator.py
|   |-- ingestion/              # CloudTrail event processing
|   |   |-- event_schema.py
|   |   |-- stream.py
|   |   |-- validator.py
|   |-- ml_engine/              # Behavioral anomaly detection and XAI
|   |   |-- detector.py
|   |   |-- pipeline.py
|   |   |-- window_aggregator.py
|   |   |-- xai.py
|   |-- scenarios/              # Attack simulation and policy workbench
|   |   |-- api.py
|   |   |-- definitions.py
|   |   |-- models.py
|   |   |-- remediation.py
|   |   |-- session.py
|   |-- soc/                    # SOC operations and hash-chained ledger
|       |-- api.py
|       |-- models.py
|       |-- store.py
|-- docs/                       # Architecture records and benchmark logs
|   |-- decisions.md
|   |-- log.md
|   |-- multi_seed_results.md
|   |-- results_table.md
|-- models/                     # Trained ML model artifacts
|   |-- baseline_v1.joblib
|-- reports/                    # Quality assurance audit reports
|   |-- independent_qa_audit.md
|-- scripts/                    # Training, validation, quality, and security scripts
|   |-- gitleaks_precommit.py
|   |-- make_table.py
|   |-- multi_seed.py
|   |-- train_eval.py
|   |-- docs/
|   |-- quality/
|   |-- security/
|   |-- testing/
|-- static/                     # Single-page application frontend
|   |-- index.html
|   |-- charts.js
|   |-- views.js
|   |-- logo.svg
|   |-- vendor/
|       |-- echarts.min.js
|-- tests/                      # Automated test suite (287 tests)
    |-- integration/            # Workflow, security hardening, Cost API & UI audit tests (12 files)
    |-- unit/                   # Component isolation unit tests (17 files)
```

### Test Suite Organization

The 287-test automated regression suite is organized into two test scopes:

- **Unit Tests (`tests/unit/` — 17 modules, 151 tests):** Validates component logic in isolation, including AWS endpoint lockout guards (`test_aws_safety`), blast radius exposure scoring (`test_blast_radius`), Cost Intelligence pricing, resource estimation, optimization findings, remediation verification, and FinOps Demo idempotency/live-guard isolation (`test_cost_intelligence`), cycle-safe privilege escalation pathfinding (`test_escalation`), CloudTrail event schema parsing (`test_event_schema`), IAM capability multigraph construction (`test_iam_graph`), anomaly scoring determinism (`test_ml_score_reproducibility`), decision threshold enforcement at $\tau = 0.610$ (`test_ml_threshold_enforcement`), model inference pipelines (`test_ml_unification`), deterministic IAM policy evaluation (`test_policy_evaluator`), security posture recovery lifecycles (`test_posture_and_remediation_lifecycle`), scenario catalog templates (`test_scenario_definitions`), remediation verification (`test_scenario_remediation`), session sandboxing (`test_scenario_session`), API authentication security and SessionStore CSRF enforcement (`test_security`), SQLite hash-chained persistence (`test_soc_store`), and thread-safe state concurrency (`test_state_thread_safety`).
- **Integration Tests (`tests/integration/` — 12 modules, 136 tests):** Validates multi-service interactions across HTTP routes and mock AWS infrastructure, including alerts inspection workflows (`test_alerts_page_audit`), core Flask REST endpoints (`test_api_endpoints`), Cost Intelligence APIs, report persistence, HITL remediation, and FinOps Demo workflow (`test_cost_api`), IAM graph and attack-path APIs (`test_graph_api`), alert-to-incident escalation workflows (`test_incident_escalation`), incident filtering state transitions (`test_incident_filtering`), playground remediation lifecycles (`test_playground_remediation`), CloudTrail replay ingestion pipelines (`test_replay_pipeline`), attack simulation lab execution APIs (`test_scenario_api`), SOC operations endpoints (`test_soc_api`), end-to-end authentication hardening and CSRF validation (`test_security_hardening`), and comprehensive university evaluation readiness audits (`test_university_evaluator_audit`).

### Module Responsibility Reference

| Directory | Responsibility |
| :--- | :--- |
| `backend/cost/` | Collects simulated EC2, EBS, S3, IAM, CloudTrail, and STS inventory, estimates monthly spend against configurable regional pricing rates, identifies FinOps optimization findings, executes/verifies cost remediations, renders 11-section reports, and manages the optional FinOps Demo Scenario. |
| `backend/graph/` | Builds the NetworkX IAM capability multigraph, computes dynamic blast radius exposure metrics, executes cycle-safe DFS privilege escalation pathfinding, and evaluates IAM policies with explicit `Deny` precedence. |
| `backend/ingestion/` | Ingests CloudTrail management events, validates syntactic and semantic schemas, normalizes UTC timestamps and principal identifiers, and streams parsed event batches into rolling observation windows. |
| `backend/ml_engine/` | Extracts 12 behavioral features across 5-minute sliding identity windows, executes Isolation Forest anomaly scoring against calibrated threshold $\tau = 0.610$, and computes Tree-Path Information Gain Attribution for explainable alerts. |
| `backend/scenarios/` | Manages predefined attack simulation scenarios (privilege escalation, S3 exfiltration, credential abuse), tracks isolated sandbox execution sessions, and validates human-in-the-loop policy remediation fixes. |
| `backend/soc/` | Manages the Security Operations Center store, coordinates alert triage and incident escalation workflows, records responder investigation notes, and appends state mutations to a SHA-256 hash-chained cryptographic ledger. |
| `static/` | Implements the responsive single-page application frontend featuring the dark/light SOC theme, reactive tab controllers, modal inspectors, collapsible FinOps report history, and 2X supersampled Apache ECharts visualizations. |
| `models/` | Houses the serialized 200-estimator Isolation Forest machine learning model artifact (`baseline_v1.joblib`) calibrated for 1.0% false alarm rate baseline operation. |
| `tests/` | Houses the complete 287-test automated regression suite covering unit component logic, API integration routes, Cost Intelligence, AWS safety isolation, security hardening, and closed-loop remediation workflows. |

---

## 8. Dashboard Module Walkthrough

The ThreatGuard single-page application is organized into 11 primary navigation modules plus integrated Cost Intelligence and architecture walkthrough views:

1. **Security Overview (`#overview`):** Central executive summary displaying the authoritative Security Posture Score, live telemetry status, quick-attack simulation buttons, synchronized telemetry charts, and a Cost Intelligence summary card.
2. **Alerts Management (`#alerts`):** Operational alert triage workspace displaying severity classifications, Isolation Forest anomaly scores, decision thresholds, feature attribution breakdowns, and alert status workflows (`New` -> `Investigating` -> `Resolved` -> `Suppressed`).
3. **Findings (`#findings`):** Comprehensive list of cloud misconfigurations discovered by the continuous CIS benchmark scanner, providing affected resource details, detection latencies, and mitigation recommendations.
4. **Incident Management (`#incidents`):** Formal incident investigation console featuring preserved forensic evidence snapshots, MITRE ATT&CK technique mappings, responder notes, and active versus closed tab filtering.
5. **IAM Attack Graph (`#graph`):** Interactive NetworkX force-directed graph modeling identity permissions, lateral movement vectors, confirmed privilege escalation paths, and dynamic blast radius metrics.
6. **Detection and XAI (`#threats`):** Machine learning transparency center displaying model cards, real-time 12-dimensional feature values, model benchmark comparisons, and threshold calibration curves.
7. **Simulation Lab (`#lab`):** Security testing and FinOps simulation suite containing the Attack Scenario Library (12 scenarios), the interactive IAM Policy Workbench, custom scenario builder, and the operator-controlled **FinOps Demo Scenario** tab.
8. **Remediation and Verification (`#remediation`):** Closed-loop remediation console for both security (`REM-*`) and FinOps optimization (`FIN-*`) tasks, displaying pending proposals, configuration diffs, human approval controls, independent cloud verification results, and 1-click rollback triggers.
9. **Inventory and Posture (`#inventory`):** Catalog of monitored cloud assets (`EC2`, `EBS`, `S3`, `IAM`, `CloudTrail`), compliance statuses, raw API evidence, and direct links to Cost Intelligence (`#cost`) and Optimization Reports.
10. **Event Viewer (`#events`):** Raw telemetry log stream displaying ingested CloudTrail management events with category filtering and JSON event inspection drawers.
11. **Audit and Evaluation (`#audit`):** Cryptographic governance ledger displaying SHA-256 hash-chained event records and providing dynamic mathematical verification of chain integrity.
12. **Cost Intelligence & AWS Optimization (`#cost`):** Dedicated FinOps workspace accessible from Overview, Inventory & Posture, Simulation Lab, or direct `#cost` routing, providing three views:
    - **Overview & Breakdown:** KPI cards, spend status indicators, service-wise breakdown chart/table, resource-level property vs. usage basis table, and before-and-after spend comparison.
    - **Optimization Findings:** Classified FinOps opportunities (`confirmed` vs `inferred`) with supporting JSON evidence, savings basis, and one-click staging into the Remediation queue.
    - **Reports & History:** Compact collapsible Report History panel (`Show History` / `Hide History`) above a full-width 11-section Cost Optimization Report Detail panel with plain-text narrative toggle and preserved historical SQLite snapshots.

Visual assets included in the repository: brand header and emblem PNG/SVG graphics reside under `static/img/` and `static/logo.svg`. Live dashboard views can be inspected interactively across desktop, laptop, tablet, and mobile viewports when running locally (`#overview`, `#cost`, `#lab`, `#architecture`, `#demo`, `#portfolio`).

---

## 9. Machine Learning Detection Methodology

ThreatGuard employs an ensemble of unsupervised anomaly detection models trained on temporal behavioral features extracted from AWS CloudTrail logs.

### Model Ensemble Components

1. **Isolation Forest (Primary Operational Model):**
   An ensemble of $T = 200$ isolation trees ($iTrees$) that recursively partition feature space using randomized orthogonal cuts. Anomalies isolate with significantly shorter path lengths than normal behavior.
2. **Local Outlier Factor (LOF):**
   Computes local density deviation relative to $k$-nearest neighbors ($k=20$), identifying isolated spatial anomalies.
3. **One-Class Support Vector Machine (OCSVM):**
   Constructs a maximum-margin non-linear hyperplane enclosing standard operational behavior using a radial basis function (RBF) kernel.
4. **Z-Score Statistical Baseline:**
   Parametric baseline calculating standardized deviations ($\mu \pm 3\sigma$) across rolling metrics for comparative evaluation.

### Isolation Forest Formulation

The anomaly score $s(x, n)$ for an observation vector $x$ over a reference dataset of $n$ samples is given by:

$$s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$

Where $h(x)$ is the path length required to isolate sample $x$, $\mathbb{E}(h(x))$ is the average path length across all 200 trees, and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree:

$$c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$$

- When $s \to 1.0$: The sample is classified as an anomaly.
- When $s < 0.5$: The sample represents normal baseline behavior.

### Threshold Calibration

The operational decision threshold was calibrated on mixed CloudTrail benchmark traces targeting a **1.0% false alarm rate (FAR)** on benign baseline activity. This yields an operational threshold of:

$$\tau = 0.610$$

Observations with $s(x) > 0.610$ automatically generate high-confidence security alerts.

---

## 10. Twelve-Dimensional Feature Engineering

ThreatGuard extracts 12 numerical behavioral features aggregated over a sliding 5-minute identity window ($W_t = 300\text{s}$). The feature set combines call volume metrics, error ratios, permission and service access patterns, and novel entity indicators into a continuous observation vector.

### Feature Reference

| Index | Feature | Type | Description |
| :-: | :--- | :--- | :--- |
| 1 | `call_count` | Integer | Total number of API invocations in the current observation window. |
| 2 | `call_velocity` | Float | Rate of API calls relative to historical baseline mean ($\bar{N}_{\text{hist}} + 1$ smoothing; defaults to 1.0 until $\ge 3$ historical windows). |
| 3 | `error_ratio` | Float [0, 1] | Proportion of API calls returning an error code (e.g., `AccessDenied`), indicating unauthorized probing. |
| 4 | `unique_services` | Integer | Number of distinct AWS service namespaces accessed (`s3`, `iam`, `sts`, etc.). |
| 5 | `unique_events` | Integer | Number of distinct API action names invoked during the observation window. |
| 6 | `enumeration_ratio` | Float [0, 1] | Proportion of reconnaissance actions (`List*`, `Describe*`, `Get*`). |
| 7 | `sensitive_count` | Integer | Number of high-impact security actions invoked (`GetObject`, `AuthorizeSecurityGroupIngress`). |
| 8 | `iam_change_count` | Integer | Number of mutating IAM actions invoked (`Attach*Policy`, `CreateAccessKey`), excluding read calls. |
| 9 | `first_service_ratio` | Float [0, 1] | Fraction of services accessed that were never previously accessed by this identity. |
| 10 | `first_ip` | Binary {0, 1} | Flag indicating if at least one previously unseen source IP occurred in the observation window. |
| 11 | `off_hours` | Binary {0, 1} | Flag indicating activity during an hour of the day never previously observed for this identity (defaults to 0.0 until $\ge 3$ historical windows). |
| 12 | `event_entropy` | Float $\ge 0$ | Shannon entropy of the invoked action distribution, quantifying activity dispersion. |

### Mathematical Feature Definitions

For an identity observation window $W_t$ containing $N_t$ events:

| Feature | Mathematical Definition |
| :--- | :--- |
| `call_count` | $N_t = \sum_{e \in W_t} 1$ |
| `call_velocity` | $V_t = \frac{N_t}{\bar{N}_{\text{hist}} + 1}$ (warm-up default: 1.0) |
| `error_ratio` | $E_t = \frac{1}{N_t} \sum_{e \in W_t} \mathbf{1}[e.\text{errorCode} \neq \emptyset]$ |
| `unique_services` | $S_t = \vert \{e.\text{service} \mid e \in W_t\} \vert$ |
| `unique_events` | $A_t = \vert \{e.\text{action} \mid e \in W_t\} \vert$ |
| `enumeration_ratio` | $R_t = \frac{1}{N_t} \sum_{e \in W_t} \mathbf{1}[e.\text{action} \in \mathcal{A}_{\text{enum}}]$ |
| `sensitive_count` | $K_t = \sum_{e \in W_t} \mathbf{1}[e.\text{action} \in \mathcal{A}_{\text{sensitive}}]$ |
| `iam_change_count` | $P_t = \sum_{e \in W_t} \mathbf{1}[e.\text{action} \in \mathcal{A}_{\text{iam-mod}}]$ |
| `first_service_ratio` | $F_t = \frac{1}{N_t} \sum_{e \in W_t} \mathbf{1}[e.\text{service} \notin \mathcal{S}_{\text{hist}}]$ |
| `first_ip` | $`\mathbf{1}[\mathcal{IP}_t \setminus \mathcal{IP}_{\text{hist}} \neq \emptyset]`$ |
| `off_hours` | $\mathbf{1}[w.\text{hour} \notin \mathcal{H}_{\text{hist}}]$ (warm-up default: 0.0) |
| `event_entropy` | $H_t = -\sum_{i=1}^{M} p_i \log_2 p_i$ |

---

## 11. Explainable AI (XAI) Methodology

To explain detections without external black-box dependencies or performance overhead, ThreatGuard implements **Tree-Path Information Gain Attribution**.

For an observation vector $x$, the attribution score for feature $f$ is computed by traversing all decision trees in the Isolation Forest ensemble and summing the information isolation gain at each node where feature $f$ was the splitting attribute:

$$\text{Attribution}(f) = \frac{1}{T} \sum_{t=1}^{T} \sum_{k \in \text{Splits}(t, f)} \frac{\max\left(0, \log_2(n_{\text{parent}}(k)) - \log_2(n_{\text{child}}(k) + 1)\right)}{h_t(x)}$$

Where $n_{\text{parent}}(k)$ is the sample count before the split, $n_{\text{child}}(k)$ is the sample count in the branch traversed by $x$, and $h_t(x)$ is the total isolation depth in tree $t$.

The resulting attributions are normalized to percentage shares and presented in the alert inspector alongside the raw observed feature values.

> **Implementation Note:** This method calculates exact decision-tree split sample density reductions and standardized feature deviations directly from the Isolation Forest estimator trees, without relying on external approximations or third-party game-theoretic attribution libraries.

---

## 12. IAM Attack-Path Analysis

ThreatGuard models cloud identities and permissions as a directed multigraph $G = (V, E)$ using NetworkX:

- **Vertices ($V$):** IAM Users, Roles, Policies, and AWS Services.
- **Edges ($E$):** Specific permissions and trust boundaries (`can_assume_role`, `has_policy`, `allows_action`, `passes_role`).

### Privilege Escalation Pathfinding

The graph engine executes a cycle-safe depth-first search (`dfs_escalation_paths`) to discover lateral movement vectors from low-privilege principals to administrative roles:

1. **Cycle Prevention:** Tracks visited states to prevent infinite traversal loops in cyclic role-assumption chains.
2. **Explicit Deny Evaluation:** Integrates policy evaluation rules to verify that candidate paths are not blocked by explicit `Deny` statements or Service Control Policies (SCPs).
3. **Escalation Primitives Analyzed:**
   - `sts:AssumeRole` lateral movement
   - `iam:PassRole` compute delegation
   - `iam:CreateAccessKey` privilege cloning
   - `iam:AttachUserPolicy` / `iam:AttachRolePolicy` administrative elevation

> **Graph Exploitability Boundary:** Graph reachability demonstrates that a structural permission chain exists in policy definitions. It indicates potential privilege escalation paths, which must be cross-referenced with resource policies and session context to determine live exploitability.

---

## 13. Blast-Radius Analysis

When an identity or resource is compromised, ThreatGuard quantifies its operational blast radius:

$$\text{Blast Radius} = \frac{|\text{Reachable Critical Targets}(v)|}{|V_{\text{critical-assets}}|} \times 100\%$$

The blast-radius engine evaluates:
- **Direct Exposure:** S3 buckets, EC2 instances, and databases directly accessible via identity policies.
- **Transitive Exposure:** Critical assets reachable through intermediate role assumptions or privilege escalation transitions.

---

## 14. Alert and Incident Lifecycle

Security events progress through a structured, auditable lifecycle:

```mermaid
flowchart TD
    subgraph AL["Alert Lifecycle"]
        direction TB
        RAW["Raw Event Ingestion"] --> HYB{"Hybrid Detection Engine"}
        HYB -->|"CIS Rule Match"| NEW["Alert Created<br/>Status: NEW"]
        HYB -->|"ML Anomaly Score > 0.610"| NEW
        NEW --> INV["Investigating<br/>Active SOC Triage"]
        NEW --> SUP["Suppressed<br/>Muted or Filtered"]
        NEW --> RES["Resolved<br/>Addressed Directly"]
    end

    subgraph IL["Incident Lifecycle"]
        direction TB
        INV -->|"Escalate to Incident<br/>Preserves Evidence Snapshot & MITRE Tags"| ACT["Incident Created<br/>Status: ACTIVE"]
        ACT -->|"Investigation Notes Added"| CNT["Incident Contained"]
        CNT -->|"Remediation Verified [PASS]"| CLS["Incident Closed<br/>Appended to Cryptographic Ledger"]
    end
```

---

## 15. Attack Simulation Architecture

The Attack Simulation Lab allows security engineers to safely test cloud security posture without impacting production workloads:

- **Predefined Scenario Library:** Includes scenarios such as excessive privilege assignment (`privesc-excessive-iam`), public data exposure (`data-exfiltration-s3`), and credential theft (`imds-credential-abuse`).
- **Isolated Execution Sandboxes:** Scenarios execute in isolated run sessions with independent state tracking.
- **Interactive Policy Workbench:** Built-in JSON editor enabling operators to author, validate, and test least-privilege IAM policy corrections against live graph models.

---

## 16. Human-in-the-Loop Remediation

ThreatGuard implements a **Human-in-the-Loop (HITL)** governance model. The platform does not execute unapproved autonomous remediation scripts:

1. **Remediation Proposal:** When an attack or misconfiguration is detected, the system generates a `RemediationTask` in `PENDING` status.
2. **Configuration Diff Inspection:** Operators review side-by-side diffs showing the current "Before" state and the proposed "Expected After" state.
3. **Explicit Operator Approval:** A human operator must explicitly authorize the fix, recording operator identity (`approved_by`) and approval timestamp (`approved_at`).
4. **Targeted Execution:** The approved remediation script executes specifically against the affected cloud resource.

---

## 17. Independent Verification and Rollback

### Mandatory Independent Cloud Verification

ThreatGuard never assumes a remediation was successful based solely on script execution. Following fix execution, an independent verification module interrogates the AWS emulator directly:

- **S3 Public Exposure:** Queries `s3.get_public_access_block` to verify all four lock settings are active.
- **CloudTrail Logging:** Queries `cloudtrail.get_trail_status` to verify logging is active.
- **Security Group Rules:** Queries `ec2.describe_security_groups` to confirm `0.0.0.0/0` ingress rules are revoked.
- **IAM Access Keys:** Queries `iam.list_access_keys` to confirm compromised keys are deactivated (`Inactive`).

Only when the independent cloud probe returns `VerificationState.PASS` is the task marked `Verified` and the Security Posture Score restored.

### Atomic 1-Click Rollback

If a remediation action causes operational disruption, operators can trigger an atomic rollback. ThreatGuard restores the pre-remediation configuration captured in `before_config` and executes an independent verification probe to ensure the prior state is safely restored.

---

## 18. Security Posture Scoring

The Security Posture Score ($P \in [0, 100]$) is calculated in `backend/posture.py` using an authoritative severity-weighted deduction schedule:

$$P = \max\left(0, 100 - \sum_{k \in \mathcal{K}} \text{Penalty}(k)\right)$$

| Resource Rule ($k$) | Monitored Control | Severity Level | Penalty Deduction | Cloud State Verification Method |
| :--- | :--- | :---: | :---: | :--- |
| **`ct`** | AWS CloudTrail Logging Active | **Critical** | **30 points** | `cloudtrail.get_trail_status()['IsLogging'] == True` |
| **`s3`** | S3 Bucket Public Access Block | **High** | **25 points** | `s3.get_public_access_block()` confirms 4 lock flags enabled |
| **`sg`** | EC2 Security Group Ingress | **High** | **25 points** | `ec2.describe_security_groups()` confirms no open ingress |
| **`key`** | IAM Access Key Credential Hygiene | **High** | **20 points** | `iam.list_access_keys()` confirms key status is `Inactive` |

- **Clean Baseline:** When all controls are verified, the score is exactly **100%**.
- **All Controls Failed:** The score drops to **0%**.
- **Dynamic Response:** Remediating any control immediately recovers its points upon independent verification.

---

## 19. Tamper-Evident Audit Ledger

All operational events (detections, alert status updates, incident notes, approvals, remediations, and rollbacks) are recorded to an append-only SQLite ledger operating in Write-Ahead Logging (WAL) mode.

Each entry is cryptographically linked to its predecessor using SHA-256 hash chaining:

$$\text{Hash}_i = \text{SHA256}\left(\text{Index}_i \parallel \text{Timestamp}_i \parallel \text{Action}_i \parallel \text{Hash}_{i-1}\right)$$

The audit interface provides an automated verification tool that traverses the chain from the genesis record to the latest entry, confirming that no entries have been modified, inserted, or removed.

> **Governance Notice:** The audit ledger provides **tamper-evident, cryptographically verifiable** storage. It is stored within a relational SQLite database rather than a decentralized distributed blockchain.

---

## 20. FinOps Cost Intelligence and Demo Scenario

ThreatGuard extends cloud posture governance into FinOps cost analysis through the `backend/cost/` engine (`inventory.py`, `pricing.py`, `estimator.py`, `optimizer.py`, `remediation.py`, `reports.py`, `demo_scenario.py`, and `api.py`).

### 20.1 Resource-Level Cost Estimation and Explicit Statuses

`collect_resource_inventory()` queries only verified local Moto/AWS operations across **EC2**, **EBS**, **S3**, **IAM**, **CloudTrail**, and **STS** (excluding terminated EC2 instances and deleted EBS volumes), and `pricing.py` matches observed attributes against `backend/cost/pricing_dataset.json` (`2026.11-aws-finops-v1`, region `us-east-1`). Every estimated resource and service receives an explicit estimation classification:

- **`Calculated`:** Rate applied directly to observed capacity or byte volume (for example, provisioned EBS GB-month or observed S3 object bytes).
- **`Estimate based on assumptions`:** Cost derived from configured monthly runtime assumptions (default `730` hours/month for running EC2 instances).
- **`Zero usage observed` / `Zero eligible spend`:** Resource exists in Moto with zero billable runtime or zero stored bytes (for example, empty baseline S3 buckets or stopped EC2 compute).
- **`Governance only`:** IAM principals and policies do not receive fabricated direct AWS infrastructure compute/storage charges.
- **`Pricing unavailable` / `Resource unavailable`:** Missing rate or unavailable service metadata is flagged explicitly rather than silently masquerading as zero cost.

> **Estimation Notice:** All monetary figures reported by Cost Intelligence are configurable pricing-based estimates derived from `backend/cost/pricing_dataset.json` and configured monthly operating-hour assumptions — **they are not actual AWS billing invoices, Cost Explorer charges, or real CloudWatch utilization telemetry**.

### 20.2 Optimization Findings and In-Dashboard Reports

`optimizer.py` classifies optimization findings into **`confirmed`** (directly observed configuration waste, such as an `available` unattached EBS volume or missing FinOps ownership tags) and **`inferred`** (opportunities pending external utilization validation, such as EC2 rightsizing or S3 lifecycle transitions) while deduplicating overlapping savings.

`reports.py` builds full **11-section Cost Optimization Reports** persisted as immutable JSON snapshots in the SQLite `cost_reports` table (`Report Information`, `Executive Summary`, `Cost Overview`, `Service-Wise Cost Analysis`, `Resource-Level Analysis`, `Cost Optimization Findings`, `Optimization Recommendations`, `Before-and-After Cost Comparison`, `Remediation Summary`, `Final Assessment`, and `Methodology and Limitations`). Reports are strictly rendered inside the dashboard (both structured responsive tables and plain-text narrative view, with a collapsible Report History header above full-width report details) and expose **no PDF, CSV, or external export endpoints**.

### 20.3 Operator-Controlled FinOps Demo Scenario

Default `safe_setup()` initializes only minimal baseline simulator assets (two empty S3 buckets, one IAM user, one CloudTrail trail, and one EC2 security group), yielding a verified `USD 0.00` monthly estimate. To demonstrate end-to-end FinOps analysis and remediation, operators can optionally load the **FinOps Demo Scenario** (`#lab` -> **FinOps Demo Scenario**):

1. **Operator-Controlled Loading (`Load FinOps Demo Scenario`):** Requires operator authentication (`POST /api/cost/demo-scenario/load`). Never provisions demo resources automatically on server startup, and executes idempotently when triggered repeatedly.
2. **Provisioned Moto Resources (Tagged `ThreatGuardScenario=finops-demo`):**
   - **EC2 (`2` instances):** `finops-demo-compute-worker` (`t3.large`, `running`, missing `Owner` tag) and `finops-demo-batch-standby` (`m5.large`, `stopped`, `Owner=finops-batch-team`).
   - **EBS (`4` volumes):** Two `8 GB gp2` root volumes (`in-use`), one explicit `100 GB gp3` attached volume (`finops-demo-standby-data`), and one explicit `80 GB gp2` unattached volume (`finops-demo-orphaned-vol`).
   - **S3 (`2` populated buckets):** `finops-demo-analytics-data` (`12,582,912` bytes across 2 objects, Versioning enabled, no lifecycle policy) and `finops-demo-archive-logs` (`3,145,728` bytes across 2 objects, Versioning disabled, `STANDARD_IA` lifecycle configured).
   - **IAM & CloudTrail:** Reuses existing simulator baseline identities (`user/intern-dev`) and telemetry (`main-trail`) without fabricating CloudTrail billing records.
3. **Inspection & Cost Refresh (`Inspect Scenario Resources`, `Refresh Cost Intelligence`):** Displays live Moto IDs/states/tags and recomputes service-wise spend, findings, and optimization reports.
4. **Closed-Loop FinOps Remediation:** Staging any eligible finding (`FIN-*`) creates a `RemediationTask` requiring human approval, verified execution against Moto (`delete_unattached_ebs_volume`, `apply_s3_lifecycle_policy`, or tag/lifecycle actions), independent cloud verification (`PASS`), hash-chained audit logging, and updated realized savings in Before-and-After report comparisons.
5. **Selective Reset (`Reset FinOps Demo Scenario`):** `POST /api/cost/demo-scenario/reset` removes only resources tagged `ThreatGuardScenario=finops-demo`, restoring Moto to its baseline state while preserving baseline `safe_setup()` resources and historical SQLite reports.

---

## 21. Operator Authentication and Access Control

ThreatGuard implements a defense-in-depth authorization model that clearly separates public observation from privileged operational control. The platform enforces least-privilege role boundaries, cryptographic session tokens, anti-CSRF validation, and strict offline simulation safety guards.

### 21.1 Core Concepts: Master API Key, Operator Credential, and Session Cookie

Understanding the security model requires distinguishing between the three authentication tokens used in ThreatGuard:

| Entity | Purpose | Storage & Lifetime | Transmission Mechanism |
| :--- | :--- | :--- | :--- |
| **Master API Key** (`CG_API_KEY` / `_ACTIVE_API_KEY`) | Server-side root authorization secret for machine-to-machine, CLI, and automated test suite access. | Stored server-side in environment variable `CG_API_KEY` or file `.cg_key` (`chmod 0600`). Persistent across server restarts. | Sent in `X-API-Key` or `Authorization: Bearer <token>` HTTP request headers. Never exposed to browser scripts. |
| **Operator Access Credential** | Secret submitted by human operators into the web dashboard login dialog to authenticate a privileged session. | Entered into the client dialog; validated server-side in constant time against the master API key. Never stored in browser storage. | Sent once via `POST /api/auth/login` payload `{"key": "<credential>"}`. Cleared from memory immediately after submission. |
| **Session Cookie** (`cg_session`) | Ephemeral server-managed browser session token issued upon successful operator authentication. | Managed server-side in `SessionStore` (thread-safe, 8-hour rolling TTL). Client stores as an `HttpOnly`, `SameSite=Lax` cookie. | Handled automatically by the browser with `credentials: "include"`. Inaccessible to JavaScript to prevent XSS credential theft. |
| **Anti-CSRF Token** (`X-CSRF-Token`) | Cryptographically random per-session token tied to the authenticated operator session. | Stored in memory within the active browser tab; validated server-side against the session record. | Sent in `X-CSRF-Token` header on state-modifying requests (`POST`, `PUT`, `DELETE`). |

### 21.2 Public Viewer Access (Public Observer Mode)

By default, ThreatGuard runs in **Public Observer Mode** (`[PUBLIC DEMO]`). Unauthenticated visitors, university examiners, and external evaluators have unrestricted read-only visibility into:

- Operational security posture scores and telemetry throughput graphs (`#overview`).
- Streaming CloudTrail event records and raw event JSON drawers (`#events`).
- Security findings catalog, rule traces, and evidence payloads (`#findings`).
- Full SOC alert investigation queues and severity distributions (`#alerts`).
- Security incident lifecycle workspaces and timeline notes (`#incidents`).
- Detection model card, feature definitions, and controlled benchmark curves (`#threats`).
- Complete IAM capability graph topology, multi-hop attack paths, and blast-radius reports (`#graph`).
- Tamper-evident SHA-256 cryptographic audit ledger and chain verification (`#audit`).
- Architectural, cost, and presentation views (`#cost`, `#architecture`, `#demo`, `#portfolio`).

Public observer requests require no credentials, set no tracking cookies, and never expose internal infrastructure secrets or cloud account credentials.

### 21.3 IAM Attack Graph Read-Only Access

The IAM capability graph engine (`/api/graph`, `/api/graph/paths/<principal_id>`, `/api/graph/all-paths`, `/api/graph/blast-radius/<target_id>`, `/api/graph/stats`) is strictly classified as a read-only analytical subsystem. Public visitors can:

- Zoom, pan, and filter nodes across users, roles, policies, and cloud resources.
- Select arbitrary principals (e.g. `user/intern-dev`) to compute and visualize multi-hop privilege escalation trajectories to `role/admin-role`.
- Calculate transitive blast radius metrics, inspecting reachable resources and exposed sensitive data tallies.

Graph exploration does not modify cloud configurations or database state and therefore does not require operator authorization.

### 21.4 Privileged Operations Requiring Operator Authorization

Operator authentication elevates the session to authorize state-modifying operational actions. Unauthenticated requests to any of the following endpoints fail with HTTP 401 Unauthorized:

1. **Attack Simulation & FinOps Demo Control:** Triggering misconfiguration attacks (`/api/attack/<resource_id>`), launching isolated attack lab scenarios (`/api/scenarios/<id>/launch`), and loading or resetting the FinOps Demo Scenario (`/api/cost/demo-scenario/load`, `/api/cost/demo-scenario/reset`).
2. **Cost Optimization Reporting & Remediation Staging:** Generating persisted Cost Optimization Reports (`/api/cost/reports/generate`) and staging cost remediation tasks (`/api/cost/findings/<id>/remediate`).
3. **Remediation Approval:** Authorizing proposed remediation task diffs via `/api/remediations/<id>/approve`.
4. **Remediation Execution:** Dispatching approved remediation playbooks against the cloud environment via `/api/remediations/<id>/apply`.
5. **Configuration Rollback:** Restoring pre-remediation configuration snapshots via `/api/remediations/<id>/rollback`.
6. **Incident Lifecycle Escalation:** Progressing incident stages (Triage $\to$ Investigation $\to$ Containment $\to$ Remediation $\to$ Verification $\to$ Closed) or appending forensic notes via `/api/incidents/<id>/action`.

### 21.5 Operator Credential Configuration, Storage, and Generation Procedure

ThreatGuard automatically manages operator credentials according to strict security invariants:

1. **Automatic Credential Initialization:**
   On server startup, `backend/security.py` checks for an existing credential in the following order:
   - Environment variable `CG_API_KEY`: If present and matching valid token format (16-256 alphanumeric characters), it is adopted as the active key.
   - Persistent secret file `.cg_key`: If the file exists at project root (`C:\cloudguardian\.cg_key`), its token is safely loaded (bounded file read $\le 1024$ bytes).
   - Dynamic token generation: If neither is found, the server automatically generates a high-entropy 24-byte hex token (`secrets.token_hex(24)`), writes it to `.cg_key`, and sets file permissions to owner-only read/write (`0600`).
2. **Explicit Operator Key Configuration:**
   Administrators can explicitly define a known operator credential by setting `CG_API_KEY` in the local `.env` configuration file or shell environment:
   ```powershell
   $env:CG_API_KEY = "<your-operator-token>"
   ```
3. **Credential Storage Safety Rules:**
   - `.cg_key` and `.env` are strictly excluded from version control via `.gitignore` and `.dockerignore`.
   - Never commit, push, or publish credentials, API keys, or `.cg_key` files.
   - Pre-commit secret scanning hooks (`python scripts/security/scan_secrets.py`) enforce zero exposed secrets across all tracked files.

### 21.6 Operator Login and Logout Workflow

1. **Initiate Login:** Click the **Operator Login** button in the top-right header navigation. The modal dialog opens, focusing the password input.
2. **Enter Credential:** Enter the configured operator access credential into the dialog.
3. **Submit Authentication:** Click **Authenticate** (or press Enter). The client sends `POST /api/auth/login` containing `{"key": "<credential>"}`.
   - The submit button is locked during transit to prevent duplicate in-flight requests.
   - The backend validates the credential in constant time (`secrets.compare_digest`) to prevent timing side-channel attacks.
4. **Session Establishment:** Upon successful verification (HTTP 200):
   - The server creates an 8-hour session in `SessionStore` and returns an `HttpOnly`, `SameSite=Lax` session cookie (`cg_session`) along with a per-session `csrf_token`.
   - The UI updates the header badge to `[OPERATOR]` (`class="tg ok"`), replaces "Operator Login" with "Logout", and enables privileged controls.
   - A confirmation toast displays: *"Operator authenticated successfully."*
5. **Termination (Logout):** Click **Logout**. The client submits `POST /api/auth/logout`.
   - The server removes the session from memory and issues an expired `Set-Cookie` header.
   - The UI immediately reverts to `[PUBLIC DEMO]` mode and restores the "Operator Login" button.

### 21.7 Session Expiration and Automatic Reconciliation

- **Server-Side TTL:** Operator sessions have an 8-hour maximum lifetime (`28800` seconds).
- **In-Memory Cleanup:** Expired sessions are lazily purged during active lookups and session creations.
- **Client-Side Polling:** The web dashboard periodically verifies session validity via `/api/auth/session` every 30 seconds.
- **Graceful Downgrade:** If a session expires while an operator is viewing the dashboard, the client automatically downgrades the interface to Public Observer Mode without reloading the page or losing current view state.
- **Unauthorized Action Interception:** If an operator attempts a privileged action after session expiry, the request fails with HTTP 401. The frontend intercepts the 401 response, shows an informative notification (*"Operator authentication required for this action."*), and re-opens the login dialog.

### 21.8 Cross-Site Request Forgery (CSRF) Protection

State-changing HTTP requests originating from browser sessions are strictly guarded against CSRF attacks:

- Upon authentication, the server generates a cryptographically random 24-byte hex token stored in the server session record and delivered in the login JSON response.
- Browser scripts store this token in memory (`window.CG_CSRF_TOKEN`) and attach it to privileged fetch requests in the `X-CSRF-Token` header.
- The server validates that the header token matches the registered token of the active session cookie (`is_csrf_valid(req)`).
- Any mutating request from a browser session that omits `X-CSRF-Token` or supplies an invalid token is rejected with **HTTP 403 Forbidden** (`CSRF validation failed: missing or invalid CSRF token`).
- Programmatic API requests supplying the master API key via `X-API-Key` or `Authorization: Bearer` are exempt from CSRF checks.

### 21.9 Local Moto Simulator and AWS Safety Guards

ThreatGuard provides multi-layer isolation to prevent accidental mutation of real-world cloud resources:

- **Isolated Local Emulation:** Operates against a local Moto AWS emulator running on `http://127.0.0.1:5000`, providing zero-cost, fully reproducible IAM, S3, CloudTrail, and EC2 simulation.
- **Boto3 Endpoint Interception (`backend/aws_guard.py`):** Forces Boto3 clients to connect exclusively to the local Moto emulator using mock credentials (`AKIAIOSFODNN7EXAMPLE`) and region `us-east-1`.
- **Live AWS Safety Guard (`CG_ALLOW_LIVE_SETUP=1`):** Any attempt to execute mutating provisioning scripts against a live AWS account without explicitly opting in via `CG_ALLOW_LIVE_SETUP=1` raises a fatal `RuntimeError`, guaranteeing that live cloud environments cannot be modified accidentally.

### 21.10 Troubleshooting Authentication Issues

- **HTTP 401 Unauthorized on Login:** Verify that the entered credential matches `CG_API_KEY` (if defined in environment) or the exact token stored in `.cg_key`. Ensure there are no leading or trailing whitespace characters.
- **HTTP 403 Forbidden on Privileged Action:** Indicates a CSRF validation failure. Refresh the browser page or re-authenticate to obtain a fresh CSRF token. Ensure third-party browser extensions are not stripping `X-CSRF-Token` request headers.
- **Session Lost on Browser Restart:** By design, session cookies are scoped to the browser session and server memory. Re-authenticating via the Operator Login dialog re-establishes an operator session.
- **Cannot Locate `.cg_key`:** The file is created automatically at the repository root upon the first execution of `python app.py`. If lost or deleted, restarting the application server generates a new token automatically.

### 21.11 Security Precautions

- Never commit `.cg_key`, `.env`, or credential files to GitHub or public repositories.
- Run `python scripts/security/scan_secrets.py` before committing changes to verify zero secret exposure.
- In production deployments, ensure ThreatGuard runs behind a reverse proxy enforcing TLS/HTTPS with the `Secure` cookie flag enabled.
- For multi-operator enterprise environments, rotate the master API key periodically by updating `CG_API_KEY` and restarting the application daemon.

---

## 22. Installation and Configuration

### System Prerequisites
- **Operating System:** Windows 10/11, macOS, or Linux
- **Python:** Version 3.11 or 3.12 (Python 3.12 verified in local environment)
- **Git:** Version 2.30+

### Verified Windows Setup (Existing `.venv` or Clean Clone)

```powershell
# 1. Activate the Python virtual environment
.\.venv\Scripts\Activate.ps1

# If initializing a fresh environment:
# python -m venv .venv
# .\.venv\Scripts\Activate.ps1
# python -m pip install --upgrade pip

# 2. Install package dependencies
pip install -r requirements.txt

# 3. Copy environment configuration template
Copy-Item .env.example .env
```

### Environment Variables (`.env.example`)

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `AWS_ENDPOINT_URL` | `http://127.0.0.1:5000` | Local Moto simulator endpoint used by `backend/aws_guard.py`. |
| `CG_LIVE_AWS` | `0` | Keeps execution isolated to local Moto (`1` opts into live read probes). |
| `CG_ALLOW_LIVE_SETUP` | `0` | Must be explicitly set to `1` to permit mutating live AWS operations. |
| `CG_DRY_RUN` | `0` | Enables dry-run mode for guarded cloud operations. |
| `CG_MASK_IDS` | `1` | Controls identifier masking inside exported/rendered telemetry views. |
| `CG_BUCKET` | `student-records-demo` | Baseline S3 bucket initialized by `safe_setup()`. |
| `CG_API_KEY` | *(auto-generated)* | Optional operator token; auto-generated into local `.cg_key` when unset. |
| `CG_BASELINE` | `1` | Enables baseline telemetry replay generation when running in simulator mode. |

---

## 23. Running the Application

ThreatGuard operates with a decoupled two-process architecture (local Moto simulator + Flask application server). Two terminal sessions are required:

### Terminal 1 — Start the Moto AWS Emulator

```powershell
.venv\Scripts\python.exe -m moto.server -p 5000
```
*Wait until Moto outputs:* `* Running on http://127.0.0.1:5000`

### Terminal 2 — Start the ThreatGuard Application

```powershell
.venv\Scripts\python.exe app.py
```
*Wait until Flask outputs:* `* Running on http://127.0.0.1:8000`

### Local Service URLs

- **ThreatGuard Dashboard:** `http://127.0.0.1:8000` (also reachable at `http://localhost:8000`)
- **Local Moto AWS Simulator:** `http://127.0.0.1:5000`

### Interactive Dashboard Views

- **Security Overview (`#overview`):** `http://127.0.0.1:8000/#overview` — Posture score, event throughput, active KPIs, and Cost Intelligence summary.
- **Cost Intelligence & Optimization (`#cost`):** `http://127.0.0.1:8000/#cost` — Resource-level estimates, FinOps findings, collapsible Report History, and 11-section reports.
- **Simulation Lab & FinOps Demo (`#lab`):** `http://127.0.0.1:8000/#lab` — Attack Simulation Library (12 scenarios), IAM Policy Workbench, and operator-controlled FinOps Demo Scenario.
- **Portfolio, Viva & Architecture Views (`#portfolio`, `#demo`, `#architecture`):** Guided walkthroughs and technical pipeline documentation.

### Common Startup Troubleshooting

- **Port 5000 Already in Use:** If another process occupies port 5000, free the port or configure `AWS_ENDPOINT_URL` to match the simulator port.
- **PowerShell Execution Policy:** If virtual environment activation fails with `Script Execution Disabled`, run:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
  ```
- **Moto Connection Refused:** Ensure Terminal 1 displays `Running on http://127.0.0.1:5000` before starting `app.py`.

---

## 24. Running Automated Tests and Quality Verification

ThreatGuard maintains an automated regression suite with **287 tests** (`151` unit tests across 17 modules and `136` integration tests across 12 modules).

```powershell
# Run the complete regression test suite (287 tests)
.venv\Scripts\python.exe -m pytest tests/ -q

# Run Cost Intelligence unit & integration suites
.venv\Scripts\python.exe -m pytest tests/unit/test_cost_intelligence.py tests/integration/test_cost_api.py -q

# Run security hardening and university evaluator audit checks
.venv\Scripts\python.exe -m pytest tests/integration/test_security_hardening.py tests/integration/test_university_evaluator_audit.py -q

# Run repository quality, documentation, and formatting audits
.venv\Scripts\python.exe scripts/quality/scan_emoji.py
.venv\Scripts\python.exe scripts/docs/validate_readme.py
.venv\Scripts\python.exe scripts/quality/validate_math.py
git diff --check
```

### Latest Recorded Verification Run

*(Reflects the latest verified run on branch `main`; re-run after future code changes rather than treating as a permanent guarantee.)*

- **Automated Test Suite:** `287 passed` (`tests/ -q`).
- **Unicode Emoji Audit:** Passed (`0` emoji characters detected across `115` scanned files).
- **Secret Scan:** Passed (`0` exposed secrets detected across `96` tracked files).
- **Formatting Diff Check:** `git diff --check` exited with code `0`.
- **Live Browser QA:** Passed with `0` console errors and `0` failed HTTP requests across desktop (`1920x1080`, `1440x900`), laptop (`1280x800`, `1024x768`), tablet (`768x1024`), and mobile (`390x844`) viewports, including interactive verification of the collapsible Report History and full-width Report Detail panel.

---

## 25. Security Scanning

To verify that no credentials, API tokens, or private keys are introduced into the repository, ThreatGuard provides both a native Python secret scanner and a Gitleaks pre-commit wrapper:

```powershell
.venv\Scripts\python.exe scripts/security/scan_secrets.py
.venv\Scripts\python.exe scripts/gitleaks_precommit.py
```

---

## 26. REST API Documentation

### Core State and Telemetry

| Method | Endpoint | Description | Authentication |
| :--- | :--- | :--- | :---: |
| `GET` | `/` | Web dashboard single-page interface | None |
| `GET` | `/api/auth/session` | Inspect session authentication state (no secrets returned) | None |
| `POST`| `/api/auth/login` | Authenticate operator, issue HttpOnly session and CSRF token | None (Valid Credential) |
| `POST`| `/api/auth/logout` | Invalidate operator session and clear session cookie | None |
| `GET` | `/api/state` | Global posture score, resources, findings, events | None |
| `GET` | `/api/rules` | Benchmark compliance security rules catalog | None |
| `GET` | `/api/ml` | Model card metadata, evaluation benchmark results | None |
| `GET` | `/api/events` | Ingested CloudTrail event stream | None |
| `GET` | `/api/audit` | Cryptographic hash-chained audit ledger | None |
| `POST`| `/api/attack/<res>` | Trigger simulated misconfiguration attack | **Required** |

### SOC Alerts and Incidents

| Method | Endpoint | Description | Authentication |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/alerts` | List all SOC alerts with status and severity filters | None |
| `GET` | `/api/alerts/<id>` | Detailed alert view including ML explanations | None |
| `POST`| `/api/alerts/<id>/action` | Update alert status (`acknowledge`, `investigate`, etc.) | **Required** |
| `POST`| `/api/alerts/<id>/escalate` | Promote alert to formal incident with evidence snapshot | **Required** |
| `GET` | `/api/incidents` | List active or all security incidents | None |
| `GET` | `/api/incidents/<id>` | Detailed incident view with preserved alert evidence | None |
| `POST`| `/api/incidents` | Create a new incident record manually | **Required** |
| `POST`| `/api/incidents/<id>/action` | Advance incident lifecycle stage or append notes | **Required** |

### IAM Graph and Blast Radius

| Method | Endpoint | Description | Authentication |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/graph` | Full IAM capability graph topology (nodes and edges) | None |
| `GET` | `/api/graph/all-paths` | Discovered privilege escalation paths | None |
| `GET` | `/api/graph/paths/<principal>` | Specific escalation paths for a given identity | None |
| `GET` | `/api/graph/blast-radius/<target>` | Downstream reachability and asset exposure calculation | None |

### Remediation and Simulation Lab

| Method | Endpoint | Description | Authentication |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/scenarios` | Catalog of attack scenarios | None |
| `POST`| `/api/scenarios/<id>/launch` | Launch scenario in an isolated sandbox | **Required** |
| `POST`| `/api/scenarios/validate-policy`| Syntactically and semantically validate IAM policy JSON | **Required** |
| `GET` | `/api/remediations` | List remediation tasks with status filters | None |
| `POST`| `/api/remediations/<id>/approve`| Grant human approval for a remediation fix | **Required** |
| `POST`| `/api/remediations/<id>/apply` | Execute fix and trigger independent cloud verifier | **Required** |
| `POST`| `/api/remediations/<id>/rollback`| Restore pre-remediation configuration | **Required** |

### Cost Intelligence & FinOps Demo

| Method | Endpoint | Description | Authentication |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/cost/overview` | Resource-level estimates, service breakdown, savings, and findings | None |
| `GET` | `/api/cost/pricing` | Active configurable regional pricing dataset metadata and rates | None |
| `GET` | `/api/cost/reports` | List persisted historical Cost Optimization Report summaries | None |
| `GET` | `/api/cost/reports/<id>` | Fetch full 11-section Cost Optimization Report snapshot | None |
| `POST` | `/api/cost/reports/generate` | Generate and persist a new 11-section report snapshot | **Required** |
| `POST` | `/api/cost/findings/<id>/remediate` | Stage an approved HITL RemediationTask for a FinOps finding | **Required** |
| `GET` | `/api/cost/demo-scenario` | Inspect loaded `ThreatGuardScenario=finops-demo` Moto resources | None |
| `POST` | `/api/cost/demo-scenario/load` | Idempotently provision optional FinOps Demo resources in Moto | **Required** |
| `POST` | `/api/cost/demo-scenario/reset` | Selectively remove FinOps Demo resources while preserving baseline | **Required** |

### Architecture and Guided Viva Documentation

| Method | Endpoint | Description | Authentication |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/architecture` | 10-stage pipeline, technology stack, and 14 engineering highlights | None |
| `GET` | `/api/demo` | 17-step presentation script and 21-step guided viva sequence | None |

---

## 27. Security and Simulator Limitations

- **Moto Is a Local Simulator, Not Live AWS:** ThreatGuard runs against the local Moto AWS emulator (`http://127.0.0.1:5000`). Automated mutating setup against live AWS is blocked by default unless explicitly opted in via `CG_ALLOW_LIVE_SETUP=1`.
- **Pricing & Usage Estimate Assumptions:** Cost figures depend on the configured regional rates in `backend/cost/pricing_dataset.json` and configured monthly operating hours (default `730` hours/month). **Reported USD figures are engineering estimates, not actual AWS billing invoices, Cost & Usage Reports (CUR), or AWS Cost Explorer charges.**
- **Simulator Telemetry & Billing API Gaps:** Moto does not provide every AWS utilization metric (such as historical CloudWatch CPU/RAM time-series) or billing API. Findings whose validation depends on external utilization metrics are explicitly classified as `inferred` rather than guaranteed savings.
- **Model Training Scope:** The baseline anomaly detection model (`models/baseline_v1.joblib`) was pre-trained on synthetic CloudTrail sequences combined with unlabelled `flaws.cloud` benchmark traces. Transferability to enterprise multi-tenant environments requires domain-specific threshold calibration.
- **Relational Storage:** The cryptographic audit ledger and immutable cost report snapshots provide tamper-evident storage within SQLite (WAL mode) rather than a distributed consensus blockchain.

---

## 28. Future Improvements

- **Multi-Cloud Posture Coverage:** Extend graph modeling and policy evaluation to Microsoft Azure Resource Manager and Google Cloud Platform Cloud IAM.
- **Streaming Ingestion:** Implement distributed Apache Kafka or AWS Kinesis event streaming ingestion for high-throughput enterprise environments.
- **Enterprise Identity Integration:** Support external identity provider integration with Okta, Azure Entra ID, and Google Workspace.

---

## 29. License and Project Attribution

Developed as an academic capstone project for the **Bachelor of Technology in Computer Science & Engineering (Artificial Intelligence & Machine Learning)** degree program (Academic Year 2026-2027).

**License:** Released under the [MIT License](https://opensource.org/licenses/MIT) for educational, research, and non-commercial security evaluation purposes.
