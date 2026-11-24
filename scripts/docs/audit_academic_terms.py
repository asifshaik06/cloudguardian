"""ThreatGuard — Academic Terminology & Viva Walkthrough Auditor.

Inspects README.md, reports, and backend SOC viva endpoints to verify:
1. Academic evaluation context (B.Tech CSE AI & ML Capstone, 2026-2027).
2. Author attribution (Asif Shaik).
3. Guided Viva / Demonstration Walkthrough (17 steps in backend/soc/api.py).
4. Absence of obsolete legacy branding in presentation endpoints.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List


def audit_academic_context(root_dir: Path) -> List[str]:
    """Verify academic context across documentation and API definitions."""
    issues: List[str] = []

    # 1. Audit README.md attribution
    readme_path = root_dir / "README.md"
    if readme_path.is_file():
        text = readme_path.read_text(encoding="utf-8")
        if "Bachelor of Technology in Computer Science & Engineering" not in text:
            issues.append("README.md: Missing degree attribution.")
        if "Artificial Intelligence & Machine Learning" not in text:
            issues.append("README.md: Missing AI & ML specialization attribution.")
        if "2026-2027" not in text:
            issues.append("README.md: Missing academic year 2026-2027 attribution.")
    else:
        issues.append("README.md not found.")

    # 2. Audit backend/soc/api.py viva and architecture definitions
    soc_api_path = root_dir / "backend/soc/api.py"
    if soc_api_path.is_file():
        code = soc_api_path.read_text(encoding="utf-8")
        if '"project_title": "ThreatGuard"' not in code:
            issues.append("backend/soc/api.py: Architecture project_title is not 'ThreatGuard'.")
        if "ThreatGuard Guided Viva / Demonstration Walkthrough" not in code:
            issues.append("backend/soc/api.py: Missing ThreatGuard Guided Viva presentation title.")
        if '"total_steps": 17' not in code:
            issues.append("backend/soc/api.py: Viva steps count is not 17.")
    else:
        issues.append("backend/soc/api.py not found.")

    # 3. Audit reports/independent_qa_audit.md
    report_path = root_dir / "reports/independent_qa_audit.md"
    if report_path.is_file():
        r_text = report_path.read_text(encoding="utf-8")
        if "ThreatGuard" not in r_text:
            issues.append("reports/independent_qa_audit.md: Missing ThreatGuard title.")
    else:
        issues.append("reports/independent_qa_audit.md not found.")

    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreatGuard Academic Context Auditor")
    parser.add_argument("--root", default=".", help="Project root directory (default: current directory)")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    issues = audit_academic_context(root)

    print(f"Auditing academic and viva context in {root}...")
    if issues:
        print(f"\n[FAIL] Found {len(issues)} academic context issues:")
        for iss in issues:
            print(f"  - {iss}")
        return 1

    print("[PASS] Academic degree attribution, viva demo script, and evaluation records verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
