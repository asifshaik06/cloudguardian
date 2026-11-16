# CloudGuardian 2.0

**Autonomous Cloud Threat Detection, IAM Attack-Path Intelligence, and Verified Incident Response**  
*Final-Year B.Tech Computer Science & Engineering (Artificial Intelligence & Machine Learning) Capstone Project, 2026-2027*

---

## 1. Executive Summary & Problem Statement

Modern cloud environments are dynamic, distributed, and identity-centric. As organizations migrate infrastructure to Amazon Web Services (AWS), security operations teams face three systemic challenges:

1. **Alert Fatigue & Opaque Machine Learning:** Traditional Security Information and Event Management (SIEM) systems generate high volumes of uncontextualized alerts. While Machine Learning (ML) can detect subtle behavioral anomalies, "black-box" models fail to explain their reasoning to Security Operations Center (SOC) analysts, leading to delayed triage and alert dismissal.
2. **Hidden Multi-Hop Privilege Escalation:** Cloud security posture tools frequently evaluate Identity and Access Management (IAM) configurations in isolation. Attackers, however, exploit chains of seemingly low-risk permissions (e.g., `iam:PassRole`, `sts:AssumeRole`, `iam:CreateAccessKey`) across multiple intermediary roles to laterally move and compromise critical cloud assets.
3. **Unverified & Fragile Remediation:** Automated remediation scripts often declare victory simply because an API call returned an HTTP 200 response, without verifying that the underlying cloud misconfiguration was actually eliminated, or without providing a safe mechanism to roll back destructive changes.

**CloudGuardian 2.0** is an enterprise-grade cloud security operations and autonomous defense platform engineered to solve these challenges. It continuously ingests AWS telemetry, evaluates deterministic CIS benchmarks, scores behavioral patterns using an ensemble of unsupervised ML models, explains every detection using mathematically grounded tree-path information-gain attributions, computes cycle-safe IAM privilege escalation graphs, and enforces closed-loop, human-approved remediations that are independently re-verified against live infrastructure before updating a tamper-evident, cryptographic audit ledger.

The system operates locally against an isolated AWS emulator (`moto`), requiring zero AWS account credentials, incurring zero cloud infrastructure costs, and providing 100% deterministic reproducibility for academic evaluation, viva defense, and security operations demonstration.

---

## 2. Key Features

- **Hybrid Detection Engine:** Unifies deterministic Center for Internet Security (CIS) compliance checks with an unsupervised 200-estimator Isolation Forest calibrated to a 1% false alarm baseline threshold ($\tau = 0.610$).
- **Mathematically Grounded Explainable AI (XAI):** Implements custom Tree-Path Information Gain Attribution to calculate feature split contributions along isolation tree paths, providing transparent explanations for every anomaly without relying on black-box heuristics or external SHAP dependencies.
- **Multi-Hop IAM Capability Graph:** Employs a NetworkX directed multigraph to model cloud identities, trust policies, and permission boundaries, discovering transitive privilege escalation vectors and quantifying dynamic blast radius metrics.
- **Human-in-the-Loop (HITL) Verified Remediation:** Enforces a four-stage remediation lifecycle (`Pending` -> `Approved` -> `Applied` -> `Independently Verified`). Fixes are never marked verified until an independent verifier directly interrogates the cloud state and returns `VerificationState.PASS`.
- **Atomic 1-Click Rollback:** Maintains pre-remediation configuration snapshots allowing operators to instantly restore infrastructure to its previous state with automated re-verification.
- **Tamper-Evident Forensic Audit Ledger:** Hash-chain verified event ledger where every state transition is sealed with SHA-256 cryptographic hashes ($\text{Hash}_i = \text{SHA256}(\text{Index}_i \parallel \text{Timestamp}_i \parallel \text{Action}_i \parallel \text{Hash}_{i-1})$), providing mathematical proof of non-tampering.
- **Dynamic Simulation Lab & Policy Workbench:** Interactive attack simulation suite allowing security engineers to launch synthetic attack scenarios (e.g., IAM credential theft, S3 data exfiltration, lateral role assumption), analyze real-time graph mutations, and test least-privilege policy fixes.
- **High-Resolution SOC Visualization:** High-DPI ECharts dashboard featuring 2X supersampled Canvas graphics and native vector SVG scatter plots for crisp, scalable data presentation across both Midnight Aurora Dark and Light themes.
- **Strict Defensive Isolation:** Built-in security guards restrict all network activity to localhost, sanitize sensitive telemetry, enforce session and API key authentication, and prevent accidental execution against live production AWS accounts.

---

## 3. System Architecture

CloudGuardian 2.0 is structured as an asynchronous, five-stage defense and governance pipeline:

```mermaid
flowchart TD
    subgraph INGESTION["1. Telemetry Ingestion & Cloud Emulation"]
        MOTO["Moto AWS Simulator (Port 5000)<br>Local S3, IAM, EC2, CloudTrail"]
        PROBES["Boto3 SDK Probes & Collectors"]
        REPLAY["CloudTrail Telemetry Replay Engine"]
        MOTO --> PROBES
        REPLAY --> PROBES
    end

    subgraph DETECTION["2. Hybrid Detection Pipeline"]
        CIS["CIS Benchmark Rule Scanner<br>(S3, CloudTrail, SG, IAM)"]
        AGG["Temporal 12-Feature Window Aggregator<br>(5-Minute Sliding Window)"]
        IFOREST["Isolation Forest (200 Trees)<br>Calibrated Threshold Tau = 0.610"]
        BENCH["Evaluation Benchmark Suite<br>(LOF, One-Class SVM, Z-Score)"]
        PROBES --> CIS
        PROBES --> AGG
        AGG --> IFOREST
        AGG --> BENCH
    end

    subgraph GRAPH_XAI["3. Graph Intelligence & Explainable AI"]
        NX["NetworkX IAM Capability Graph<br>(Directed Multigraph)"]
        PATHS["Cycle-Safe DFS Pathfinding<br>(Transitive Privilege Escalation)"]
        BLAST["Dynamic Blast Radius Quantification"]
        XAI["Tree-Path Information Gain Attribution<br>(Mathematical Decision Contributions)"]
        CIS --> NX
        PROBES --> NX
        NX --> PATHS
        NX --> BLAST
        IFOREST --> XAI
    end

    subgraph RESPONSE["4. Incident Response & Closed-Loop Remediation"]
        ALERTS["SOC Alerts Console<br>(Status Lifecycle & Escalation)"]
        INCIDENTS["Incident Workspace<br>(Evidence Snapshot Preservation)"]
        HITL["Human-in-the-Loop Operator Authorization Gate"]
        VERIFY["Independent Post-Remediation Cloud Verifier<br>(Probes Infrastructure State)"]
        ROLLBACK["1-Click Atomic State Rollback Engine"]
        CIS --> ALERTS
        IFOREST --> ALERTS
        PATHS --> ALERTS
        ALERTS --> INCIDENTS
        ALERTS --> HITL
        HITL --> VERIFY
        VERIFY --> ROLLBACK
    end

    subgraph AUDIT["5. Cryptographic Governance & Evaluation"]
        POSTURE["Authoritative Posture Score (0-100%)<br>(Severity-Weighted Deductions)"]
        LEDGER["Tamper-Evident SHA-256 Hash-Chained Ledger<br>(Cryptographic Non-Repudiation)"]
        VERIFY --> POSTURE
        VERIFY --> LEDGER
        ROLLBACK --> LEDGER
    end
```

---

## 4. Technology Stack

| Domain | Technology | Version | Purpose in CloudGuardian 2.0 |
| :--- | :--- | :--- | :--- |
| **Backend Framework** | Python / Flask | 3.12 / 3.1.3 | REST API services, session management, telemetry streaming |
| **Cloud Simulation** | Moto | 5.2.5 | In-memory standalone AWS emulator providing S3, IAM, EC2, CloudTrail, STS |
| **AWS SDK** | Boto3 / Botocore | 1.43.126 | Cloud state polling, resource manipulation, and independent verification |
| **Graph Analysis** | NetworkX | 3.7 | Directed multigraph modeling of IAM permissions, role assumption, and blast radius |
| **Machine Learning** | Scikit-Learn | 1.9.1 | Isolation Forest, Local Outlier Factor, One-Class SVM anomaly detection |
| **Numerical Computing** | NumPy / SciPy / Pandas | 2.5 / 1.18 / 3.1 | Temporal feature aggregation, statistical calibration, and vector math |
| **Model Serialization** | Joblib | 1.6.0 | Serialized baseline models (`models/baseline_v1.joblib`) and scalers |
| **Frontend UI** | HTML5 / CSS3 / Vanilla JS | ECMAScript 2022 | Single-page reactive SOC dashboard (zero external JavaScript frameworks) |
| **Data Visualization** | Apache ECharts | 6.1.0 | Vector SVG scatter charts and 2X supersampled Canvas timelines/graphs |
| **Database / Ledger** | SQLite (WAL mode) | 3.x | Persistent SOC store and tamper-evident SHA-256 hash-chained audit ledger |
| **Testing & Quality** | Pytest / Gitleaks | 9.2.0 / 8.x | 233-test regression suite, invariant verifiers, and automated secret scanning |

---

## 5. Project Directory Structure

```
C:\cloudguardian
|-- app.py                              # Flask application root, API routing, posture calculation hook
|-- requirements.txt                    # Python package dependencies
|-- README.md                           # Master project documentation
|-- .gitignore                          # Git exclusions (credentials, databases, virtual environments)
|-- backend/                            # Core backend architecture
|   |-- aws_guard.py                    # Endpoint isolation guard and safe live AWS lockout
|   |-- dashboard_api.py                # Dashboard state and helper endpoints
|   |-- posture.py                      # Authoritative 0-100% security posture calculation
|   |-- replay.py                       # CloudTrail telemetry replay pipeline
|   |-- security.py                     # API authentication, session validation, secret redaction
|   |-- state.py                        # Thread-safe in-memory state store and telemetry queues
|   |-- telemetry.py                    # Background telemetry loop and /api/metrics service
|   |-- graph/                          # IAM capability graph subsystem
|   |   |-- api.py                      # Graph REST endpoints (/api/graph/...)
|   |   |-- blast_radius.py             # Downstream asset exposure and reachability analysis
|   |   |-- escalation.py               # Cycle-safe DFS privilege escalation pathfinder
|   |   |-- iam_graph.py                # NetworkX directed multigraph builder and node models
|   |   |-- policy_evaluator.py         # IAM policy evaluator (Allow/Deny, conditions, wildcards)
|   |-- ingestion/                      # Telemetry ingestion subsystem
|   |   |-- event_schema.py             # CloudTrail event validation schemas
|   |   |-- stream.py                   # Ingestion streaming and dispatch pipeline
|   |   |-- validator.py                # Syntactic and semantic event validator
|   |-- ml_engine/                      # Machine learning and explainability subsystem
|   |   |-- detector.py                 # Multi-model anomaly detector inference engine
|   |   |-- pipeline.py                 # 12-dimensional feature transformation and scaling
|   |   |-- window_aggregator.py        # 5-minute sliding temporal identity window
|   |   |-- xai.py                      # Custom Tree-Path Information Gain Attribution
|   |-- scenarios/                      # Attack simulation lab subsystem
|   |   |-- api.py                      # Scenario lab REST endpoints (/api/scenarios/...)
|   |   |-- definitions.py              # Catalog of predefined attack scenario templates
|   |   |-- models.py                   # Pydantic schemas for scenarios, runs, and workbench
|   |   |-- remediation.py              # Policy workbench fix application and verification
|   |   |-- session.py                  # Isolated execution sandbox session manager
|   |-- soc/                            # Security operations center subsystem
|       |-- api.py                      # SOC REST endpoints (/api/alerts, /api/incidents, /api/remediations)
|       |-- models.py                   # SOC data models (Alerts, Incidents, Remediations)
|       |-- store.py                    # Persistent SOC store, hash-chain ledger, audit logs
|-- models/                             # Trained machine learning model artifacts
|   |-- baseline_v1.joblib              # 200-tree Isolation Forest, LOF, OCSVM, and feature metadata
|-- static/                             # Frontend assets (Single-Page Application)
|   |-- index.html                      # Primary HTML shell and Midnight Aurora theme definitions
|   |-- charts.js                       # ECharts mounting, SVG vector scatter, and Canvas renderers
|   |-- views.js                        # Reactive page views, modal controllers, inspector drawers
|   |-- logo.svg                        # CloudGuardian vector shield and cloud brand mark
|   |-- vendor/                         # Third-party vendor libraries
|       |-- echarts.min.js              # Bundled Apache ECharts 6.1.0 library
|-- tests/                              # Automated testing and verification suite (233 tests)
    |-- integration/                    # End-to-end integration workflows
    |   |-- test_alerts_page_audit.py
    |   |-- test_api_endpoints.py
    |   |-- test_incident_escalation.py
    |   |-- test_incident_filtering.py
    |   |-- test_playground_remediation.py
    |   |-- test_replay_pipeline.py
    |   |-- test_scenario_api.py
    |   |-- test_soc_api.py
    |   |-- test_university_evaluator_audit.py
    |-- unit/                           # Isolated component unit tests
        |-- test_aws_safety.py
        |-- test_blast_radius.py
        |-- test_escalation.py
        |-- test_iam_graph.py
        |-- test_ml_score_reproducibility.py
        |-- test_ml_unification.py
        |-- test_policy_evaluator.py
        |-- test_posture_and_remediation_lifecycle.py
        |-- test_scenario_definitions.py
        |-- test_scenario_remediation.py
        |-- test_security.py
        |-- test_soc_store.py
        |-- test_state_thread_safety.py
```

---

## 6. Module-by-Module Functional Explanations

The CloudGuardian 2.0 user interface is organized into 11 specialized operational views:

### 6.1 Security Overview (`#overview`)
The central executive cockpit displaying global threat metrics, live connection health, and quick-attack simulation triggers. Key components include:
- **Security Posture Score Widget:** Displays the authoritative 0-100% cloud health score calculated by `backend/posture.py`.
- **High-DPI Telemetry Charts:** Six synchronized visual panels:
  - *Posture History:* Step-line area chart tracking score evolution over time.
  - *Anomaly Score:* Native vector SVG scatter plot rendering 3.5px discrete observations with threshold boundary.
  - *Event Activity:* Dual-stacked bar chart of simulated baseline vs. attack activity.
  - *Detection Breakdown:* Donut chart quantifying detections across CIS rules vs. ML detectors.
  - *Severity Distribution:* Horizontal bar chart categorizing findings from Low to Critical.
  - *Remediation MTTR:* Mean Time to Remediate and throughput metrics.
- **Simulate Attack Buttons:** Interactive controls allowing operators to instantly introduce real misconfigurations (`s3`, `ct`, `sg`, `key`) into Moto.

### 6.2 Alerts Management (`#alerts`)
The tier-1 triage console for operational security alerts.
- Displays alert severity badges (Critical, High, Medium, Low), triggering mechanisms, and detection sources.
- **XAI Score Breakdown:** For ML alerts, reveals the Isolation Forest numerical anomaly score (e.g., $0.6959$), decision threshold ($0.610$), anomaly delta, and algorithm configuration.
- **Alert Status Lifecycle:** Operators can advance alerts through `New` -> `Investigating` -> `Resolved` -> `Suppressed`.
- **One-Click Incident Escalation:** Preserves raw telemetry evidence snapshots and promotes an alert to a formal incident.

### 6.3 Findings (`#findings`)
Detailed inventory of security compliance defects detected by the CIS benchmark scanner.
- Maps findings to CIS AWS Foundation Benchmarks (e.g., CIS 2.1.4 S3 Bucket Public Access Block).
- Inspector drawer provides technical descriptions, affected resource identifiers, detection latency ($t_{\text{detect}}$), and recommended remediation code snippets.

### 6.4 Incident Management (`#incidents`)
The collaborative workspace for formal incident investigation and response.
- **Evidence Preservation:** Deep-copies and permanently preserves the full detection context, MITRE ATT&CK technique mapping, and telemetry snapshot from the originating alert.
- **Incident Lifecycle Stages:** Tracks investigations across `Active` (`New` -> `Investigating` -> `Contained`) and `Closed` (`Resolved`) states.
- **Investigator Workspace:** Allows responders to append timestamped investigation notes, inspect linked findings, and jump directly to remediation proposals.
- **Active / All Filtering:** Tabbed filtering allows analysts to separate active investigations from closed historical records.

### 6.5 IAM Attack Graph (`#graph`)
Graph visualization representing identity permissions, trust boundaries, and multi-hop attack vectors.
- Built on NetworkX, rendering nodes for IAM Users, Roles, Policies, and AWS Services.
- **Privilege Escalation Pathfinding:** Discovers complex lateral movement chains (e.g., `intern-dev` -> `dev-role` -> `cicd-deployer` -> `admin-role`).
- **Path Tracing:** Highlights confirmed paths, numbers traversal steps, and displays directional arrows.
- **Dynamic Blast Radius:** Quantifies upstream accessibility and downstream resource reachability for any selected identity.

### 6.6 Detection and Explainable AI (`#threats`)
Deep-dive intelligence console into the underlying machine learning architecture.
- **Model Card Specifications:** Documentation of model architecture, training datasets (`flaws.cloud` traces), contamination rates, and window hyperparameters.
- **12-Dimensional Feature Inspector:** Visualizes real-time temporal feature values (`call_count`, `call_velocity`, `error_ratio`, etc.).
- **Multi-Model Benchmark:** Comparative performance metrics (Precision, Recall, F1-Score, False Alarm Rate) across Isolation Forest, Local Outlier Factor, One-Class SVM, and Z-Score.
- **Threshold Calibration Curve:** Interactive precision-recall trade-off curve demonstrating why $\tau = 0.610$ was selected.

### 6.7 Attack Simulation Lab (`#lab`)
Isolated playground for testing complex attack vectors and security policies.
- **Predefined Scenario Catalog:** Scenarios including `privesc-excessive-iam`, `data-exfiltration-s3`, and `imds-credential-abuse`.
- **Isolated Execution Runs:** Spawns sandbox runs with isolated configuration state.
- **Interactive Policy Workbench:** Built-in JSON editor with real-time IAM syntax validation (`/api/scenarios/validate-policy`) allowing operators to author and test least-privilege policies before deploying.

### 6.8 Remediation and Verification (`#remediation`)
Closed-loop remediation console managing human approval and verification.
- **Pending Approval Queue:** Displays remediation proposals generated by attacks or security findings.
- **Diff Inspector:** Side-by-side comparison of current "Before" configuration vs. proposed "Expected After" configuration.
- **Human Approval Gate:** Requires explicit operator authorization (`approved_by`, `approved_at`) before applying changes.
- **Independent Cloud Verification:** Directly queries Moto AWS APIs to verify vulnerability mitigation, updating status to `Verified [PASS]`.
- **1-Click Rollback:** Allows instant restoration to prior state with cryptographic audit logging.

### 6.9 Inventory and Posture (`#inventory`)
Comprehensive asset management and configuration posture audit.
- Inventories all monitored AWS cloud assets (S3 Buckets, IAM Users, EC2 Security Groups, CloudTrail Trails).
- Displays resource identifiers, compliance statuses, and last verification timestamps.

### 6.10 Event Viewer (`#events`)
Raw telemetry ingestion and forensic audit stream.
- Streams CloudTrail-style event records generated by the simulator and replay engines.
- Full-text search and category filtering (`All`, `Attack actions`, `Baseline traffic`).
- Expandable raw JSON event viewers for detailed forensic examination.

### 6.11 Audit and Evaluation (`#audit`)
Cryptographic governance and tamper-evident audit ledger.
- Lists all administrative actions, alert status transitions, incident notes, and remediation executions.
- **Tamper-Evident SHA-256 Hash Chain:** Displays cryptographic hashes linking each record to its predecessor.
- **Integrity Verifier:** Dynamically verifies the mathematical integrity of the hash chain, displaying a green `Chain Integrity: Valid` verification indicator.

---

## 7. AI/ML Methodology & Explainable AI (XAI)

### 7.1 12-Dimensional Temporal Feature Engineering
The ML anomaly detection engine aggregates raw CloudTrail event logs over a sliding 5-minute identity window ($W = 300\text{s}$) into a 12-dimensional numerical feature vector:

| # | Feature Name | Data Type | Mathematical Formulation | Security Operational Meaning |
| :-: | :--- | :--- | :--- | :--- |
| 1 | `call_count` | Integer | $N_t = \sum_{e \in W} 1$ | Total API invocations in current observation window. |
| 2 | `call_velocity` | Float | $V_t = N_t / \max(1, \mu_{\text{hist}})$ | Rate of API calls relative to identity's historical baseline. |
| 3 | `error_ratio` | Float [0, 1] | $E_t = \frac{1}{N_t} \sum [e.\text{status} = \text{Error}]$ | Fraction of failed calls (e.g., `AccessDenied`), indicating permission probing. |
| 4 | `unique_services` | Integer | $S_t = |\text{unique}(\{e.\text{service}\})|$ | Number of distinct AWS service namespaces accessed (`s3`, `iam`, `sts`). |
| 5 | `unique_events` | Integer | $A_t = |\text{unique}(\{e.\text{action}\})|$ | Number of distinct API actions invoked. |
| 6 | `enumeration_ratio` | Float [0, 1] | $R_t = \frac{1}{N_t} \sum [e.\text{action} \in \mathcal{A}_{\text{enum}}]$ | Proportion of reconnaissance actions (`List*`, `Describe*`, `Get*`). |
| 7 | `sensitive_count` | Integer | $K_t = \sum [e.\text{action} \in \mathcal{A}_{\text{sensitive}}]$ | High-impact API invocations (`GetObject`, `AuthorizeSecurityGroupIngress`). |
| 8 | `iam_change_count` | Integer | $P_t = \sum [e.\text{action} \in \mathcal{A}_{\text{iam\_mod}}]$ | Permission modification calls (`Attach*Policy`, `CreateAccessKey`). |
| 9 | `first_service_ratio`| Float [0, 1]| $F_t = \frac{1}{N_t} \sum [e.\text{service} \notin \mathcal{S}_{\text{hist}}]$ | Invocations targeting services never previously accessed by this identity. |
| 10 | `first_ip` | Binary {0, 1}| $\mathbf{1}[e.\text{src\_ip} \notin \mathcal{IP}_{\text{hist}}]$ | Flag indicating request originated from an unfamiliar IP address. |
| 11 | `off_hours` | Binary {0, 1}| $\mathbf{1}[e.\text{hour} \notin [8, 18]]$ | Flag indicating activity outside standard operational working hours. |
| 12 | `event_entropy` | Float $\ge 0$ | $H_t = -\sum_{i} p_i \log_2 p_i$ | Shannon entropy of action distribution; high entropy indicates erratic activity. |

### 7.2 Multi-Model Benchmark Suite
CloudGuardian evaluates detections across four distinct algorithmic paradigms:

1. **Isolation Forest (Primary Production Detector):**
   An ensemble of $T = 200$ isolation trees partitioning feature space using randomized orthogonal cuts. Anomalies are isolated near tree roots with short average path lengths $\mathbb{E}(h(x))$.
   The anomaly score $s(x, n)$ over dataset size $n$ is defined as:
   $$s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$
   Where $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree:
   $$c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$$
   - $s \to 1.0$: Confirmed anomaly (e.g., alert `ALT-0004` scores $0.6959$).
   - $s < 0.5$: Normal baseline behavior.

2. **Local Outlier Factor (LOF):**
   Measures local density deviation relative to $k$-nearest neighbors ($k=20$). Flags density-based spatial outliers such as isolated credential access from unusual subnets.

3. **One-Class Support Vector Machine (OCSVM):**
   Constructs a maximum-margin hyperplane in a non-linear kernel space ($\text{RBF}$ kernel) enclosing standard operational identities and identifying boundary violations.

4. **Z-Score Statistical Baseline:**
   Parametric baseline calculating standard deviations from rolling Gaussian distributions ($\mu \pm 3\sigma$). Serves as a benchmark for measuring non-parametric ML gains.

### 7.3 Anomaly Threshold Calibration
The operational decision threshold was calibrated on mixed baseline traces targeting a **1.0% false alarm rate (FAR)** on benign CloudTrail telemetry. This calibration yields $\tau = 0.610$. Any observation scoring $s(x) > 0.610$ triggers an automated SOC alert.

### 7.4 Explainable AI: Tree-Path Information Gain Attribution
To ensure 100% transparency without fabricating explanations or relying on heavy external dependencies, CloudGuardian uses **Tree-Path Information Gain Attribution**:

For an observation $x$, the attribution score for feature $f$ is computed by aggregating variance reduction (information gain) across all splits in all 200 isolation trees where feature $f$ was the splitting variable:

$$\text{Attribution}(f) = \frac{1}{T} \sum_{t=1}^{T} \sum_{k \in \text{Splits}(t, f)} \frac{\Delta \text{Depth}(k)}{h_t(x)}$$

Top contributing features are displayed in the alerts drawer with percentage attributions, strictly distinguishing model explanations from raw observed telemetry parameters.

---

## 8. IAM Attack-Path & Blast-Radius Methodology

CloudGuardian constructs a directed multigraph $G = (V, E)$ modeling AWS identity architecture:

- **Nodes ($V$):** Principals (IAM Users, Groups, Roles), Credentials (Access Keys), and Target Assets (S3 Buckets, EC2 Instances, Policies).
- **Edges ($E$):** Specific authorization relationships (`can_assume_role`, `has_inline_policy`, `attached_managed_policy`, `passes_role_to`).

### Cycle-Safe DFS Privilege Escalation Pathfinding
The pathfinding engine evaluates transitive reachability from untrusted entry identities (e.g., `intern-dev`) to administrative roles (`admin-role`):
1. **Cycle Prevention:** Maintains a visited state set preventing infinite loops in cyclic role-assumption chains.
2. **Explicit Deny Precedence:** Cross-references policy evaluation logic to ensure paths blocked by explicit `Deny` statements or SCPs are marked `BLOCKED`.
3. **Escalation Primitives Evaluated:**
   - `sts:AssumeRole` lateral movement
   - `iam:PassRole` combined with compute creation
   - `iam:CreateAccessKey` privilege cloning
   - `iam:AttachUserPolicy` administrative elevation

### Dynamic Blast Radius Quantification
For any selected identity or compromised asset, CloudGuardian calculates:
$$\text{Blast Radius} = \frac{|\text{Reachable Targets}(v)|}{|V_{\text{assets}}|} \times 100\%$$
Distinguishing direct access from transitive multi-hop compromise risks.

---

## 9. Closed-Loop Remediation & Independent Verification

### The 4-Stage Remediation Lifecycle
Automated remediations follow a strict, auditable lifecycle:

```
[Simulated Attack / Finding] 
       │
       ▼
[Stage 1: PENDING] ──> Proposal generated with before/after diffs
       │
       ▼ (Human Operator Authorization)
[Stage 2: APPROVED] ──> Operator logs approval with identity & timestamp
       │
       ▼
[Stage 3: APPLIED] ──> Remediation script executes against cloud API
       │
       ▼ (Independent Verification Probe)
[Stage 4: VERIFIED] ──> Infrastructure state verified as clean [PASS]
```

### Why Independent Verification is Mandatory
CloudGuardian never marks a remediation as `Verified` based merely on the execution status of the fix script. In cloud operations, API calls can succeed while configuration states lag or fail due to race conditions. An independent verification module directly queries the AWS infrastructure:
- **S3 Public Access:** Executes `s3.get_public_access_block` to confirm all four lock flags are `True`.
- **CloudTrail Logging:** Interrogates `cloudtrail.get_trail_status` to confirm `IsLogging == True`.
- **Security Group Ingress:** Inspects `ec2.describe_security_groups` to confirm no `0.0.0.0/0` ingress rules exist.
- **IAM Access Keys:** Evaluates `iam.list_access_keys` to confirm the key is deactivated (`Status="Inactive"`).

Only when the cloud state independently confirms the vulnerability is gone does the task transition to `VerificationState.PASS`.

### Atomic 1-Click Rollback
Every remediation task preserves its prior state in `before_config`. If an applied remediation disrupts operations, clicking **Rollback** executes the inverse operation and triggers an independent verification probe to ensure the prior state is safely restored.

---

## 10. Authoritative Security Posture Score Formulation

The global Security Posture Score ($P \in [0, 100]$) is computed in `backend/posture.py` by deducting severity-weighted penalties for any unresolved risk, active finding, or unverified remediation:

$$P = \max\left(0, 100 - \sum_{k \in \mathcal{K}} \text{Penalty}(k)\right)$$

| Resource Rule ($k$) | Monitored Control | Severity Level | Penalty Deduction | Cloud State Verification Method |
| :--- | :--- | :---: | :---: | :--- |
| **`ct`** | AWS CloudTrail Logging Active | **Critical** | **30 points** | `cloudtrail.get_trail_status(Name="demo-trail")['IsLogging'] == True` |
| **`s3`** | S3 Bucket Public Access Block | **High** | **25 points** | `s3.get_public_access_block` confirms all 4 public access blocks enabled |
| **`sg`** | EC2 Security Group Ingress | **High** | **25 points** | `ec2.describe_security_groups` confirms no open `0.0.0.0/0` ingress rules |
| **`key`** | IAM User Access Key Hygiene | **High** | **20 points** | `iam.list_access_keys` confirms key is `Inactive` or mitigated |

- **All Controls Verified & Compliant:** Posture Score = **100%**.
- **All Controls Compromised:** Posture Score = **0%**.
- **Partial Risk:** Deductions apply dynamically (e.g., S3 Public Exposure drops score from 100% to 75%).

---

## 11. Tamper-Evident Forensic Audit Ledger

All forensic state changes (finding detections, alert acknowledgments, incident notes, remediation approvals, and verification results) are recorded to an append-only SQLite ledger operating in Write-Ahead Logging (WAL) mode.

Each ledger entry is cryptographically bound to its predecessor via SHA-256 hash chaining:

$$\text{Hash}_i = \text{SHA256}\left(\text{Index}_i \parallel \text{Timestamp}_i \parallel \text{Action}_i \parallel \text{Hash}_{i-1}\right)$$

The audit console provides a one-click **Verify Ledger** function that traverses the chain from genesis to the latest record, verifying that no historical records have been inserted, deleted, or modified.

> **Forensic Governance Clarification:** The audit ledger is **tamper-evident** and **cryptographically verifiable**, rather than inherently immutable, as it operates within standard relational storage rather than a decentralized distributed blockchain.

---

## 12. Moto AWS Emulator Architecture & Defensive Safeguards

CloudGuardian 2.0 is built to run entirely offline against **Moto**, an open-source AWS emulation server:
- **Zero Cost & Zero Credentials:** No AWS billing account or access keys required.
- **Defensive Isolation Guard (`backend/aws_guard.py`):** Forces all Boto3 client connections to `http://127.0.0.1:5000` using mock credentials (`AKIAIOSFODNN7EXAMPLE`) and mock region (`us-east-1`).
- **Live AWS Safe Lockout:** Any attempt to execute mutating setup calls against real AWS infrastructure without setting `CG_ALLOW_LIVE_SETUP=1` raises a fatal `RuntimeError`, guaranteeing safety during testing.
- **REST API Authentication:** All mutating endpoints require valid authentication via the `X-API-Key` header or an authenticated session cookie.

---

## 13. Installation & Setup Guide

### 13.1 Prerequisites
- **Operating System:** Windows 10/11, macOS, or Linux
- **Python:** Version 3.11 or 3.12 (Python 3.12 recommended)
- **Git:** Installed and available in terminal path

### 13.2 Environment Setup (Windows PowerShell)

```powershell
# 1. Clone the repository
git clone https://github.com/asifshaik06/cloudguardian.git
cd C:\cloudguardian

# 2. Create and activate a Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip and install package dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 13.3 Starting CloudGuardian (Dual-Process Architecture)

CloudGuardian operates using two decoupled local background processes:

**Process 1 — Start the Moto AWS Emulator (Terminal 1):**
```powershell
# In terminal 1:
.\.venv\Scripts\Activate.ps1
python -m moto.server -p 5000
```
*Wait until Moto outputs: `* Running on http://127.0.0.1:5000`.*

**Process 2 — Start the CloudGuardian Flask Application (Terminal 2):**
```powershell
# In terminal 2:
.\.venv\Scripts\Activate.ps1
python app.py
```
*Wait until Flask outputs: `* Running on http://127.0.0.1:8000`.*

### 13.4 Accessing the SOC Dashboard
Open any modern web browser (Chrome, Edge, Firefox, Safari) and navigate to:
```
http://localhost:8000
```

---

## 14. Automated Testing & Verification Suite

CloudGuardian 2.0 maintains a 233-test regression suite covering unit, integration, and security layers.

### Executing Automated Tests

```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Run the complete test suite (233 tests)
python -m pytest tests/ -q

# Run specific unit test suites
python -m pytest tests/unit/test_posture_and_remediation_lifecycle.py
python -m pytest tests/unit/test_ml_score_reproducibility.py
python -m pytest tests/unit/test_iam_graph.py

# Run integration workflows
python -m pytest tests/integration/test_university_evaluator_audit.py
```

### Automated Secret Scanning
To verify that no private keys, AWS credentials, or API tokens are checked into Git:
```powershell
python scripts/gitleaks_precommit.py
```

---

## 15. Guided 5-Minute Viva Demonstration Sequence

For academic evaluators, university viva committees, and technical recruiters:

1. **Security Overview (`#overview`):**
   Observe the initial Security Posture Score at **100%**. Inspect the high-DPI charts.
2. **Simulate Cloud Misconfiguration (`#overview`):**
   Click **Simulate attack** under S3 Public Bucket. Observe the Posture Score drop to **75%** (-25 points) and a high-severity finding generated in `#findings`.
3. **ML Anomaly Investigation & XAI (`#alerts`):**
   Simulate IAM Key compromise. Open alert `ALT-0004` in `#alerts`. Demonstrate the 200-tree Isolation Forest anomaly score ($0.6959 > 0.610$) and the feature attribution breakdown.
4. **Escalate Alert to Incident (`#alerts` -> Escalate):**
   Click **Escalate to incident**. Verify that evidence is preserved and promoted to `#incidents`.
5. **IAM Capability Graph Tracing (`#graph`):**
   Click **Trace in graph**. Demonstrate the 4-hop lateral movement chain (`intern-dev` -> `dev-role` -> `cicd-deployer` -> `admin-role`) and view the dynamic blast radius.
6. **Simulation Lab Workbench (`#lab`):**
   Launch scenario `privesc-excessive-iam`. Edit the IAM policy in the Workbench, test validation, and apply the fix.
7. **Closed-Loop Verified Remediation (`#remediation`):**
   Navigate to `#remediation`. Open the pending task, inspect the before/after diffs, click **Approve Fix**, and then click **Apply & Independently Verify**. Verify that the cloud state check passes (`[PASS]`).
8. **Posture Recovery & Cryptographic Audit (`#overview` & `#audit`):**
   Return to `#overview` to see the Posture Score return to **100%**. Open `#audit` to verify the tamper-evident SHA-256 hash chain.

---

## 16. Scope Boundaries & Future Improvements

### Current Scope Boundaries
- **Emulated vs. Live Cloud:** CloudGuardian is intentionally optimized for offline Moto emulation. While read-only live AWS inspection is supported, automated remediation on live AWS requires setting `CG_ALLOW_LIVE_SETUP=1`.
- **Dataset Context:** The baseline ML detector was trained on benchmark traces from synthetic CloudTrail simulations and unlabelled `flaws.cloud` datasets.
- **Relational Ledger:** The cryptographic audit ledger is tamper-evident and hash-chained, stored in relational SQLite rather than a distributed consensus blockchain.

### Future Roadmap
- Multi-cloud posture coverage (Microsoft Azure Resource Manager, Google Cloud Platform Cloud IAM).
- Distributed OpenTelemetry streaming ingestion pipeline.
- Integration with external enterprise identity providers (Okta, Azure Entra ID).

---

## 17. Academic Context & License

This project was developed as a final-year Capstone Project for the **Bachelor of Technology in Computer Science & Engineering (Artificial Intelligence & Machine Learning)** degree program (Academic Year 2026-2027).

**License:** Released under the MIT License for educational, research, and non-commercial security evaluation purposes.
