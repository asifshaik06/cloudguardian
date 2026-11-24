# ThreatGuard — Independent QA Audit & Technical Validation Report

**Author:** Independent Senior QA Architect, Cloud Security Tester & External University Evaluator  
**Date:** November 14, 2026  
**Repository:** `C:\cloudguardian`  
**Branch:** `feature/dashboard-redesign-and-readiness`  
**Baseline Commit:** `636d9ab`  
**Target Evaluation:** University Final-Year B.Tech (AI & ML) Defense & External Technical Review  

---

## 1. Executive Summary & Audit Baseline

Prior internal testing claimed **160 passing unit tests and 100% external evaluation readiness**. An independent, rigorous black-box and white-box examination was conducted to verify these claims across all 11 system views, interactive elements, IAM graph calculations, simulation scenarios, and REST API endpoints.

### Audit Verdict: **CONDITIONALLY READY — 3 CRITICAL/HIGH DEFECTS DETECTED**
While the core architecture (NetworkX capability graph, ML threat detection pipeline, and responsive dashboard layout) is robust, **critical functional and security defects were uncovered that would immediately fail a live university defense or technical recruiter inspection**:

1. **[P1 - High] Simulation Lab Playground "Remediate" Action Broken:**  
   Clicking the `#btn-apply-recommended-fix` button in the Workbench Playground fails silently in the UI or throws an uncaught `ReferenceError: remediateRun is not defined`. Furthermore, `reanalyzeRun`, `verifyRun`, and `resetRun` are also completely undefined in frontend JavaScript.
2. **[P0 - Critical] Unauthenticated Operational REST APIs:**  
   Mutating SOC endpoints (`POST /api/remediations/<id>/approve`, `POST /api/remediations/<id>/apply`, `POST /api/incidents`, `POST /api/alerts/<id>/action`, `POST /api/scenarios/runs/<id>/remediate`) lack authentication enforcement (`@require_auth`). Any unauthenticated caller can approve/execute live cloud remediations or inject rogue incidents.
3. **[P1 - High] IAM Attack Graph Correctness & Classification Semantics:**  
   The primary graph pathfinding engine (`backend/graph/escalation.py`) relies solely on topological reachability via `nx.all_simple_paths` without executing deterministic policy evaluation (`PolicyEvaluator.classify_path`). Paths fail to evaluate condition keys, IP restrictions, or explicit Deny statements. Furthermore, the path classification vocabulary uses `Confirmed`, `Potential`, and `Theoretical` instead of the mandated `CONFIRMED`, `POTENTIAL`, `BLOCKED`, and `UNVERIFIED`.

---

## 2. Independent Verification Environment

- **Host Environment:** Windows (PowerShell)
- **Local Cloud Emulator:** Moto 5.0.12 daemon running isolated on `http://127.0.0.1:5000` (Task ID: `task-1044`)
- **Dashboard Web Server:** Flask WSGI server running on `http://127.0.0.1:8000` (Task ID: `task-1464`)
- **AWS Isolation:** Zero real AWS credentials; mocked account `123456789012`, region `us-east-1`
- **Baseline Test Suite Execution:**
  ```text
  160 passed in 164.38s (0:02:44) across 19 test files
  ```

---

## 3. Comprehensive Defect Register

| Defect ID | Page / Module | UI Element / Endpoint | Description | Reproduction Steps | Expected Result | Actual Result | Severity | Evidence |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| **BUG-001** | Simulation Lab (`#lab`) | `#btn-apply-recommended-fix` | Playground "Apply Recommended Fix" button fails due to missing JS handler and payload mismatch | 1. Navigate to `/#lab`<br>2. Select scenario<br>3. Open Playground tab<br>4. Click "Apply Recommended Fix" | Executes remediation, updates graph and verification card | `ReferenceError: remediateRun is not defined` or button click has no effect (`onclick = null`) | **P1 (High)** | Subagent Step 245-273: `typeof window.remediateRun === "undefined"`, `btn.onclick === null` |
| **BUG-002** | Simulation Lab (`#lab`) | `#btn-wb-reanalyze`, `#btn-wb-verify`, `#btn-wb-reset` | Workbench action buttons fail due to missing JS function declarations | 1. Navigate to `/#lab`<br>2. Click "Re-Analyze", "Verify State", or "Reset Scenario" | Calls respective REST endpoint and reloads state | Buttons fail with `ReferenceError: reanalyzeRun/verifyRun/resetRun is not defined` | **P1 (High)** | Static analysis of `views.js`: functions called in `bindLabEvents()` but never defined |
| **BUG-003** | SOC REST API | `POST /api/remediations/<id>/approve`, `apply` | Unauthenticated execution of cloud remediation actions | Send POST request without `X-API-Key` or session cookie to `/api/remediations/REM-0001/approve` | Returns HTTP 401 Unauthorized | Returns HTTP 200 OK; remediation is approved and applied | **P0 (Critical)** | `probe_auth.py`: HTTP 200 with `{"ok": true, "status": "APPROVED"}` without credentials |
| **BUG-004** | SOC REST API | `POST /api/incidents` | Unauthenticated injection of rogue security incidents | Send POST request with JSON payload to `/api/incidents` without auth | Returns HTTP 401 Unauthorized | Returns HTTP 201 Created; rogue incident stored in database | **P0 (Critical)** | `probe_auth.py`: HTTP 201 with `incident_id` generated without credentials |
| **BUG-005** | SOC REST API | `POST /api/alerts/<id>/action`, `escalate` | Unauthenticated alert triage and escalation | Send POST request to `/api/alerts/ALT-0001/action` without auth | Returns HTTP 401 Unauthorized | Returns HTTP 200/201 with alert status changed | **P0 (Critical)** | `probe_auth.py`: HTTP 200 with alert status mutated |
| **BUG-006** | IAM Attack Graph | `backend/graph/escalation.py` | Pathfinding bypasses deterministic policy evaluation | Call `/api/graph/paths/user/intern-dev` or `/api/graph/all-paths` | Returns paths with authorization classification (`CONFIRMED`, `BLOCKED`) | Returns topological paths without evaluating conditions or explicit Deny | **P1 (High)** | `escalation.py`: `nx.all_simple_paths` directly converted to dict without calling `PolicyEvaluator.classify_path` |
| **BUG-007** | IAM Data Model | `backend/scenarios/models.py` | Path classification enum vocabulary non-compliance | Inspect `PathClassification` enum | Contains `CONFIRMED`, `POTENTIAL`, `BLOCKED`, `UNVERIFIED` | Contains `Confirmed`, `Potential`, `Theoretical` | **P2 (Medium)** | `models.py:27`: missing `BLOCKED` and `UNVERIFIED` |
| **BUG-008** | Simulation API | `POST /api/scenarios/runs/<id>/remediate` | Payload format mismatch between frontend and backend | Frontend calls `remediateRun(run_id, expRem)` sending `{type: ...}` | Backend processes fix | Backend returns HTTP 400 (`"Request body must include an 'action' object."`) | **P2 (Medium)** | `api.py:140`: expects `{"action": {...}}`, frontend sends `{type: ...}` |

---

## 4. Deep-Dive Investigation: Bug 1 (Simulation Playground Remediation Failure)

### Technical Analysis
When an evaluator loads the Simulation Lab Workbench, the application initializes `WORKBENCH_TAB = "paths"`. The `#btn-apply-recommended-fix` button is only generated when `WORKBENCH_TAB === "remediation"`.

1. **Initial Event Binding Failure:**
   During the initial `bindLabEvents()` execution in `static/views.js`:
   ```javascript
   const bRecFix = $$("btn-apply-recommended-fix");
   if (bRecFix && ACTIVE_RUN) {
     bRecFix.onclick = () => remediateRun(ACTIVE_RUN.run_id, ACTIVE_RUN.definition.expected_remediation || { type: "generic_remediation" });
   }
   ```
   Because `WORKBENCH_TAB` is `"paths"`, `#btn-apply-recommended-fix` is not present in the DOM. `bRecFix` evaluates to `null`, and no event listener is attached.

2. **Tab Switch Re-render Destruction:**
   When the user clicks the "Playground" tab, `updateWorkbenchInspector()` is called:
   ```javascript
   function updateWorkbenchInspector() {
     const el = $$("workbench-inspector-body");
     if (el) el.innerHTML = renderWorkbenchInspector();
     // ... updates tab class names only!
   }
   ```
   This inserts the HTML `<button id="btn-apply-recommended-fix">`, but **never attaches an `onclick` listener**.

3. **Missing Function Declarations:**
   Even if the listener were attached, `remediateRun`, `reanalyzeRun`, `verifyRun`, and `resetRun` are **not defined anywhere** in `static/views.js` or `static/index.html`. Calling any of them throws:
   ```text
   Uncaught ReferenceError: remediateRun is not defined
   ```

4. **Backend Payload Mismatch:**
   In `backend/scenarios/api.py:140`:
   ```python
   payload = request.get_json(silent=True) or {}
   action = payload.get("action")
   if not action or not isinstance(action, dict):
       return jsonify({"error": "Request body must include an 'action' object."}), 400
   ```
   The frontend was written to pass `ACTIVE_RUN.definition.expected_remediation` directly as the body rather than wrapping it in `{"action": expected_remediation}`.

---

## 5. Deep-Dive Investigation: Bug 2 (Missing API Authentication)

### Empirical Vulnerability Demonstration
We executed an automated probe against the running Flask application on port 8000 without transmitting any credentials (`X-API-Key`, `Authorization`, or `cg_session` cookies):

```python
# Unauthenticated POST to Remediation Approval
resp = client.post("/api/remediations/REM-0001/approve", json={"approved_by": "unauthenticated_attacker"})
# Result: HTTP 200 OK -> Permitted!

# Unauthenticated POST to Live Remediation Execution
resp = client.post("/api/remediations/REM-0001/apply")
# Result: HTTP 200 OK -> Permitted!

# Unauthenticated POST to Incident Creation
resp = client.post("/api/incidents", json={"title": "Rogue Incident", "severity": "CRITICAL"})
# Result: HTTP 201 Created -> Injected!
```

### Root Cause
While legacy endpoints in `app.py` (`/api/attack/s3`, `/api/decide/s3/ok`, `/api/rollback/s3`) correctly implement `@require_auth`, the newly added blueprints in `backend/soc/api.py`, `backend/scenarios/api.py`, and `backend/graph/api.py` omit `@require_auth` on modifying HTTP methods (`POST`, `PUT`, `DELETE`).

---

## 6. Deep-Dive Investigation: Bug 3 (IAM Attack Graph Classification Semantics)

### Technical Analysis
In `backend/graph/escalation.py`, `find_escalation_paths` calculates simple graph reachability:
```python
paths = list(nx.all_simple_paths(g, source=source_id, target=tgt, cutoff=cutoff))
```
It wraps each path into an `AttackPath` object, but:
1. It **never invokes** `PolicyEvaluator.classify_path(graph_engine, p, context)`.
2. Paths blocked by an explicit `Deny` statement or failing condition keys (e.g., `aws:MultiFactorAuthPresent == true` when MFA is absent) are treated identically to confirmed paths.
3. The resulting path dictionaries lack a `classification` field, preventing the UI from distinguishing between verified compromises and blocked theoretical vectors.
4. The enum in `backend/scenarios/models.py` uses `Confirmed`, `Potential`, and `Theoretical` instead of the required specification:
   - `CONFIRMED`: All hops have verified Allow, valid trust, and satisfied conditions.
   - `POTENTIAL`: Authorized transitions requiring external compute context (e.g. `iam:PassRole` + `ec2:RunInstances`).
   - `BLOCKED`: Blocked by explicit Deny, boundary restriction, or failed condition.
   - `UNVERIFIED`: Ambiguous or unvalidated trust boundaries.

---

## 7. Working Features Register

The following components were audited and verified to be fully operational:

1. **System Navigation Rail:** Clean 11-item visible sidebar (Overview, Alerts, Findings, Incidents, IAM Attack Graph, Simulation Lab, Remediation, Inventory, Detection/XAI, Events, Audit). Architecture and Viva items are preserved in code but hidden from the primary rail.
2. **In-App Modal Dialogs:** Custom accessible dialogs (`promptModal`, `confirmModal`, `alertModal`, `showToast`) completely replaced all browser-native dialogs (`alert()`, `confirm()`, `prompt()`). Zero native dialog popups remain.
3. **12 Predefined Attack Scenarios:** All 12 scenarios (`privesc-excessive-iam`, `privesc-risky-trust`, `privesc-passrole-ec2`, `privesc-policy-version`, `resource-s3-public`, `resource-s3-wildcard`, `resource-kms-unrestricted`, `resource-ec2-ingress-ssh`, `lateral-compromised-dev`, `lateral-role-chaining`, `lateral-create-access-key`, `defense-evasion-cloudtrail`) successfully launch and execute in isolated Moto state.
4. **Interactive IAM Capability Graph:** ECharts force-directed graph with color-coded nodes (Users, Roles, Policies, Buckets, EC2, KMS), smooth curved edges, visible arrowheads, edge hover tooltips, zoom controls (+/-/Fit/Reset), and interactive attack-path tracing with red highlighting and numbered step badges.
5. **Detection & Explainable AI (XAI):** Isolation Forest, One-Class SVM, and Local Outlier Factor models with custom Tree-Path Information Gain Attribution.
6. **Tamper-Evident Audit Trail:** SQLite append-only audit store with SHA-256 cryptographic hash-chaining and independent integrity verification.
7. **Multi-Viewport Responsiveness:** Smooth layout adaptation across all 12 target viewports (1920x1080 down to 360x800) with off-canvas sidebar drawer on viewports `<= 1024px`.

---

## 8. Defect Remediation Plan (Phase 11 Execution Order)

To achieve 100% university evaluator readiness, the following fixes will be applied in strict sequence:

1. **Task 1: Secure All Operational REST APIs (Fix BUG-003, BUG-004, BUG-005)**
   - Add `@require_auth` to all state-mutating endpoints in `backend/soc/api.py`, `backend/scenarios/api.py`, and `backend/graph/api.py`.
   - Preserve read-only catalog queries while requiring authorization for execution, approvals, triage, and graph mutation.

2. **Task 2: Fix Simulation Lab Workbench & Remediation Actions (Fix BUG-001, BUG-002, BUG-008)**
   - In `static/views.js`, implement `remediateRun(runId, action)`, `reanalyzeRun(runId)`, `verifyRun(runId)`, and `resetRun(runId)`.
   - In `remediateRun`, wrap the action object in `{"action": action}` to match backend API expectations.
   - In `updateWorkbenchInspector()`, rebind all tab action buttons whenever tab content is dynamically updated.
   - Reload run state and capability graph post-remediation and display verification results.

3. **Task 3: Refine IAM Graph Policy Evaluation & Classification (Fix BUG-006, BUG-007)**
   - Update `PathClassification` in `backend/scenarios/models.py` to support `CONFIRMED`, `POTENTIAL`, `BLOCKED`, and `UNVERIFIED`.
   - Update `backend/graph/policy_evaluator.py` to classify explicit Deny and unmet conditions as `BLOCKED`.
   - Update `backend/graph/escalation.py` so that `find_escalation_paths` invokes `PolicyEvaluator.classify_path` and includes `classification`, `status`, and `reason` in every path dictionary.

4. **Task 4: Add Regression Tests & Verify Full Test Suite**
   - Add comprehensive tests in `tests/integration/test_remediation_playground_flow.py` and `tests/integration/test_operational_api_auth.py`.
   - Run complete pytest suite (target: 170+ passing tests).
   - Run Gitleaks secret scan.
   - Commit and push to `origin/feature/dashboard-redesign-and-readiness`.
