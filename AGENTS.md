# ThreatGuard — Agent Guidelines and Conventions

This document specifies mandatory conventions and operational rules for AI assistants, agents, and contributors working in the ThreatGuard repository.

---

## 1. Strict Emoji Prohibition Convention

**Never introduce emoji characters anywhere in ThreatGuard source code, frontend, backend, documentation, tests, assets, configuration or GitHub-facing files.**

- **Zero Tolerance:** No Unicode emoji characters (emoticons, pictographs, transport symbols, dingbats, or variation selectors) are permitted in any repository file.
- **UI Elements:** Use clean, professional monochrome SVG icons or CSS indicators where visual cues are required.
- **Labels and Badges:** Use concise textual badges (for example, `[ADMIN]`, `[SENSITIVE]`, `[ESCALATION]`, `[STANDARD]`, `[PASS]`, `[FAIL]`) rather than decorative symbols.
- **Technical Symbols:** Standard ASCII punctuation and legitimate technical notation (such as mathematical formulas in LaTeX, directional arrows `→`, and breadcrumb dots `·`) are acceptable when structurally necessary, but decorative emoji glyphs must never be introduced.

---

## 2. Architecture and Safety Invariants

- **Default Offline Emulation:** The platform operates against a local Moto AWS simulator on `http://127.0.0.1:5000`.
- **Live AWS Safety Guards:** Live AWS operations require explicit opt-in via environment flags (`CG_ALLOW_LIVE_SETUP=1`). Never bypass safety checks or hardcode cloud credentials.
- **Tamper-Evident Ledger:** Audit logs use SHA-256 cryptographic hash-chaining stored in SQLite. State-mutating operations must append to this ledger.
- **Human-in-the-Loop Remediation:** Remediation actions require human approval, verified execution against the simulator, and independent verification before updating security posture score.
- **Explainable Machine Learning:** Behavioral anomaly scoring is conducted via an Isolation Forest calibrated at threshold $\tau = 0.610$. Feature contributions are computed using custom Tree-Path Information Gain Attribution. Third-party attribution libraries are not used in production inference.

---

## 3. Git and Repository Safety Rules

- **Branch Isolation:** Perform all feature and bug-fix development on designated feature branches.
- **No Unapproved Operations:** Never commit, push to remote repositories, or merge branches without explicit user approval.
- **Never Overwrite or Discard Work:** Do not execute destructive Git operations (`git reset --hard`, `git clean -fd`, or force pushes).
- **Zero Secrets:** All commits must pass pre-commit secret scans (`scripts/gitleaks_precommit.py`). Never commit `.env` files, API keys, credentials, or session cookies.
- **Clean UTF-8 Formatting:** All text files must be encoded in pure UTF-8 without Byte Order Marks (BOM).

---

## 4. Verification and Testing Standards

Before proposing or finalizing any change:
1. Run the Unicode emoji audit scanner across the repository to verify zero emoji code points.
2. Run the test suite: `pytest tests/ -q` (all tests must pass).
3. Run the secret scanner: `python scripts/gitleaks_precommit.py`.
4. Run `git diff --check` to confirm clean formatting without trailing whitespace or merge artifacts.
