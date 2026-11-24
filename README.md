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
- [20. Moto Simulator and AWS Safety Architecture](#20-moto-simulator-and-aws-safety-architecture)
- [21. Installation and Configuration](#21-installation-and-configuration)
- [22. Running the Application](#22-running-the-application)
- [23. Running Automated Tests](#23-running-automated-tests)
- [24. Security Scanning](#24-security-scanning)
- [25. REST API Documentation](#25-rest-api-documentation)
- [26. Security Limitations and Scope Boundaries](#26-security-limitations-and-scope-boundaries)
- [27. Future Improvements](#27-future-improvements)
- [28. License and Project Attribution](#28-license-and-project-attribution)

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
- **High-Resolution SOC Dashboard:** Modern single-page interface featuring 2X supersampled Canvas graphics and native vector SVG charts for data readability.

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

---

## 6. Technology Stack

| Component | Technology | Version | Functional Role |
| :--- | :--- | :--- | :--- |
| **Backend Framework** | Python / Flask | 3.12 / 3.1.3 | Core application server, REST APIs, session control |
| **Frontend Architecture**| HTML5 / CSS3 / JavaScript | ES6+ / Native | Single-page SOC interface, reactive view controllers, modal dialogs |
| **Cloud Simulation** | Moto | 5.2.5 | Local standalone AWS emulator providing S3, IAM, EC2, CloudTrail, and STS |
| **AWS SDK** | Boto3 / Botocore | 1.43.126 | Resource configuration probing and independent remediation verification |
| **Graph Modeling** | NetworkX | 3.7 | In-memory directed multigraph analysis, pathfinding, and blast radius |
| **Machine Learning** | Scikit-Learn / Joblib | 1.9.1 / 1.6.0 | Isolation Forest, Local Outlier Factor, One-Class SVM, model artifact persistence |
| **Data Validation** | Pydantic | 2.14.3 | Declarative schema validation, event models, and scenario definitions |
| **Numerical Computing** | NumPy / SciPy / Pandas | 2.5 / 1.18 / 3.1 | Feature aggregation, matrix math, statistical threshold calibration |
| **Data Visualization** | Apache ECharts | 6.1.0 | SVG scatter charts and 2X supersampled Canvas timelines/graphs |
| **Data Persistence** | SQLite (WAL mode) | 3.x | SOC store, incident records, and SHA-256 hash-chained audit ledger |
| **Testing and Security**| Pytest / Gitleaks | 9.2.0 / 8.x | 272-test automated regression suite and pre-commit secret scanning |

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
|   |-- state.py                # Thread-safe in-memory state store
|   |-- telemetry.py            # Background loops and metrics service
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
|-- models/                     # Trained ML model artifacts
|   |-- baseline_v1.joblib
|-- reports/                    # Quality assurance audit reports
|   |-- independent_qa_audit.md
|-- scripts/                    # Training, benchmarking, and secret scans
|   |-- gitleaks_precommit.py
|   |-- multi_seed.py
|   |-- train_eval.py
|-- static/                     # Single-page application frontend
|   |-- index.html
|   |-- charts.js
|   |-- views.js
|   |-- logo.svg
|   |-- vendor/
|       |-- echarts.min.js
|-- tests/                      # Automated test suite (272 tests)
    |-- integration/            # Workflow, security hardening, and end-to-end API tests (11 files)
    |-- unit/                   # Component isolation unit tests (16 files)
```

### Test Suite Organization

The 272-test automated regression suite is organized into two test scopes:

- **Unit Tests (`tests/unit/` — 16 modules, 142 tests):** Validates component logic in isolation, including AWS endpoint lockout guards (`test_aws_safety`), blast radius exposure scoring (`test_blast_radius`), cycle-safe privilege escalation pathfinding (`test_escalation`), CloudTrail event schema parsing (`test_event_schema`), IAM capability multigraph construction (`test_iam_graph`), anomaly scoring determinism (`test_ml_score_reproducibility`), decision threshold enforcement at $\tau = 0.610$ (`test_ml_threshold_enforcement`), model inference pipelines (`test_ml_unification`), deterministic IAM policy evaluation (`test_policy_evaluator`), security posture recovery lifecycles (`test_posture_and_remediation_lifecycle`), scenario catalog templates (`test_scenario_definitions`), remediation verification (`test_scenario_remediation`), session sandboxing (`test_scenario_session`), API authentication security and SessionStore CSRF enforcement (`test_security`), SQLite hash-chained persistence (`test_soc_store`), and thread-safe state concurrency (`test_state_thread_safety`).
- **Integration Tests (`tests/integration/` — 11 modules, 130 tests):** Validates multi-service interactions across HTTP routes and mock AWS infrastructure, including alerts inspection workflows (`test_alerts_page_audit`), core Flask REST endpoints (`test_api_endpoints`), IAM graph and attack-path APIs (`test_graph_api`), alert-to-incident escalation workflows (`test_incident_escalation`), incident filtering state transitions (`test_incident_filtering`), playground remediation lifecycles (`test_playground_remediation`), CloudTrail replay ingestion pipelines (`test_replay_pipeline`), attack simulation lab execution APIs (`test_scenario_api`), SOC operations endpoints (`test_soc_api`), end-to-end authentication hardening and CSRF validation (`test_security_hardening`), and comprehensive university evaluation readiness audits (`test_university_evaluator_audit`).

### Module Responsibility Reference

| Directory | Responsibility |
| :--- | :--- |
| `backend/graph/` | Builds the NetworkX IAM capability multigraph, computes dynamic blast radius exposure metrics, executes cycle-safe DFS privilege escalation pathfinding, and evaluates IAM policies with explicit `Deny` precedence. |
| `backend/ingestion/` | Ingests CloudTrail management events, validates syntactic and semantic schemas, normalizes UTC timestamps and principal identifiers, and streams parsed event batches into rolling observation windows. |
| `backend/ml_engine/` | Extracts 12 behavioral features across 5-minute sliding identity windows, executes Isolation Forest anomaly scoring against calibrated threshold $\tau = 0.610$, and computes Tree-Path Information Gain Attribution for explainable alerts. |
| `backend/scenarios/` | Manages predefined attack simulation scenarios (privilege escalation, S3 exfiltration, credential abuse), tracks isolated sandbox execution sessions, and validates human-in-the-loop policy remediation fixes. |
| `backend/soc/` | Manages the Security Operations Center store, coordinates alert triage and incident escalation workflows, records responder investigation notes, and appends state mutations to a SHA-256 hash-chained cryptographic ledger. |
| `static/` | Implements the single-page application frontend featuring the dark graphite SOC theme, reactive tab controllers, modal inspectors, and 2X supersampled Apache ECharts timelines and graph visualizations. |
| `models/` | Houses the serialized 200-estimator Isolation Forest machine learning model artifact (`baseline_v1.joblib`) calibrated for 1.0% false alarm rate baseline operation. |
| `tests/` | Houses the complete 272-test automated regression suite covering unit component logic, API integration routes, AWS safety isolation, security hardening, and closed-loop remediation workflows. |

---

## 8. Dashboard Module Walkthrough

The ThreatGuard single-page application is structured into 11 dedicated functional modules:

1. **Security Overview (`#overview`):** Central executive summary displaying the authoritative Security Posture Score, live telemetry status, quick-attack simulation buttons, and six synchronized high-DPI telemetry charts.
2. **Alerts Management (`#alerts`):** Operational alert triage workspace displaying severity classifications, Isolation Forest anomaly scores, decision thresholds, feature attribution breakdowns, and alert status workflows (`New` -> `Investigating` -> `Resolved` -> `Suppressed`).
3. **Findings (`#findings`):** Comprehensive list of cloud misconfigurations discovered by the continuous CIS benchmark scanner, providing affected resource details, detection latencies, and mitigation recommendations.
4. **Incident Management (`#incidents`):** Formal incident investigation console featuring preserved forensic evidence snapshots, MITRE ATT&CK technique mappings, responder notes, and active versus closed tab filtering.
5. **IAM Attack Graph (`#graph`):** Interactive NetworkX force-directed graph modeling identity permissions, lateral movement vectors, confirmed privilege escalation paths, and dynamic blast radius metrics.
6. **Detection and XAI (`#threats`):** Machine learning transparency center displaying model cards, real-time 12-dimensional feature values, model benchmark comparisons, and threshold calibration curves.
7. **Simulation Lab (`#lab`):** Security testing suite allowing operators to launch predefined attack scenarios, analyze isolated execution runs, and author least-privilege IAM policies using an interactive JSON workbench with syntax validation.
8. **Remediation and Verification (`#remediation`):** Closed-loop remediation console displaying pending proposals, side-by-side configuration diffs, human approval controls, independent cloud verification results, and 1-click rollback triggers.
9. **Inventory and Posture (`#inventory`):** Catalog of all monitored cloud assets (S3 buckets, IAM users, security groups, CloudTrail trails) showing resource compliance statuses and configuration metadata.
10. **Event Viewer (`#events`):** Raw telemetry log stream displaying ingested CloudTrail management events with category filtering and JSON event inspection drawers.
11. **Audit and Evaluation (`#audit`):** Cryptographic governance ledger displaying SHA-256 hash-chained event records and providing dynamic mathematical verification of chain integrity.

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

## 20. Moto Simulator, AWS Safety and Authentication Architecture

ThreatGuard is designed for safe, zero-cost operation using local cloud emulation with enterprise-grade access controls:

- **Isolated Emulation:** Uses `moto.server` running on `http://127.0.0.1:5000` to emulate AWS APIs locally.
- **Defensive Isolation Guard (`backend/aws_guard.py`):** Intercepts Boto3 client initialization and forces all service endpoints to localhost using mock credentials (`AKIAIOSFODNN7EXAMPLE`) and region `us-east-1`. In addition, fast socket probes (<250ms) and short timeouts ensure non-blocking startup and offline resilience even when the Moto simulator process is offline.
- **Live AWS Safe Lockout:** Any attempt to run mutating provisioning scripts against live AWS without setting `CG_ALLOW_LIVE_SETUP=1` raises a fatal `RuntimeError`, preventing accidental modification of real cloud environments.
- **Secure Authentication and Session Hardening:**
  - **Public Demonstration Mode (`[PUBLIC DEMO]`):** Unauthenticated visitors have read-only visibility into posture scores, telemetry streams, findings, IAM graph topologies, and audit ledgers without exposing master API keys, internal credentials, or AWS account secrets.
  - **Server-Side Session Store (`SessionStore`):** Generates cryptographically secure 256-bit session IDs stored server-side with rolling TTLs, issued via `HttpOnly`, `SameSite=Lax` cookies (`cg_op_session`).
  - **Strict Anti-CSRF Token Enforcement:** Mutating operations (`POST`, `PUT`, `DELETE`, `PATCH`) triggered from authenticated browser sessions require a valid `X-CSRF-Token` header. Missing or forged tokens return `403 Forbidden`.
  - **Direct API Key Header Support:** Programmatic clients, test suites, and CI/CD pipelines providing `X-API-Key` headers are authenticated directly without requiring session cookies or CSRF tokens.
  - **Session Lifecycle APIs:** Provides `/api/auth/session` (session state check without secret leakage), `/api/auth/login` (operator credential verification and session issuance), and `/api/auth/logout` (server session termination).

---

## 21. Installation and Configuration

### System Prerequisites
- **Operating System:** Windows 10/11, macOS, or Linux
- **Python:** Version 3.11 or 3.12 (Python 3.12 recommended)
- **Git:** Version 2.30+

### Step-by-Step Setup

#### Windows PowerShell

```powershell
# 1. Clone repository
git clone https://github.com/asifshaik06/threatguard.git
cd threatguard

# 2. Create and activate Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip and install package dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. Copy environment configuration
Copy-Item .env.example .env
```

#### Linux / macOS

```bash
# 1. Clone repository
git clone https://github.com/asifshaik06/threatguard.git
cd threatguard

# 2. Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Upgrade pip and install package dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. Copy environment configuration
cp .env.example .env
```

---

## 22. Running the Application

ThreatGuard operates with a decoupled two-process architecture (local emulator + application server). Two terminal sessions are required:

### Terminal 1 — Start the Moto AWS Emulator

```powershell
.\.venv\Scripts\Activate.ps1
python -m moto.server -p 5000
```
*Wait until Moto outputs:* `* Running on http://127.0.0.1:5000`

### Terminal 2 — Start the ThreatGuard Application

```powershell
.\.venv\Scripts\Activate.ps1
python app.py
```
*Wait until Flask outputs:* `* Running on http://127.0.0.1:8000`

### Accessing the Dashboard

Open any standard web browser and navigate to:
```
http://localhost:8000
```

### Common Startup Troubleshooting

- **Port 5000 Already in Use:** If another process (e.g., macOS AirPlay Receiver) occupies port 5000, disable it or reconfigure `MOTO_PORT` in `.env`.
- **PowerShell Execution Policy:** If virtual environment activation fails with `Script Execution Disabled`, run:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
  ```
- **Moto Connection Refused:** Ensure Terminal 1 displays `Running on http://127.0.0.1:5000` before starting `app.py`.

---

## 23. Running Automated Tests

ThreatGuard maintains an automated regression suite with **272 tests** covering unit, integration, and security layers.

```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Run the complete test suite (272 tests)
python -m pytest tests/ -q

# Run specific unit test modules
python -m pytest tests/unit/test_posture_and_remediation_lifecycle.py
python -m pytest tests/unit/test_ml_score_reproducibility.py
python -m pytest tests/unit/test_iam_graph.py

# Run integration workflow tests
python -m pytest tests/integration/test_university_evaluator_audit.py
```

---

## 24. Security Scanning

To verify that no credentials, tokens, or private keys are introduced into the repository, ThreatGuard includes an automated secret scanner:

```powershell
python scripts/gitleaks_precommit.py
```

This utility integrates with the official Gitleaks Docker container and provides a native Python regex fallback scanner.

---

## 25. REST API Documentation

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

---

## 26. Security Limitations and Scope Boundaries

- **Emulation vs. Production Cloud:** ThreatGuard is intentionally designed and evaluated against Moto local cloud emulation. Real AWS live connectivity is limited to read-only posture assessment; automated write operations on live accounts require explicit `CG_ALLOW_LIVE_SETUP=1` flags.
- **Model Training Scope:** The baseline anomaly detection model (`models/baseline_v1.joblib`) was pre-trained on synthetic CloudTrail sequences combined with unlabelled `flaws.cloud` benchmark traces. Transferability to enterprise multi-tenant environments requires domain-specific threshold calibration.
- **Relational Storage:** The cryptographic audit ledger provides tamper-evident, verifiable logging within SQLite rather than a distributed consensus blockchain.

---

## 27. Future Improvements

- **Multi-Cloud Posture Coverage:** Extend graph modeling and policy evaluation to Microsoft Azure Resource Manager and Google Cloud Platform Cloud IAM.
- **Streaming Ingestion:** Implement distributed Apache Kafka or AWS Kinesis event streaming ingestion for high-throughput enterprise environments.
- **Enterprise Identity Integration:** Support external identity provider integration with Okta, Azure Entra ID, and Google Workspace.

---

## 28. License and Project Attribution

Developed as an academic capstone project for the **Bachelor of Technology in Computer Science & Engineering (Artificial Intelligence & Machine Learning)** degree program (Academic Year 2026-2027).

**License:** Released under the [MIT License](https://opensource.org/licenses/MIT) for educational, research, and non-commercial security evaluation purposes.
