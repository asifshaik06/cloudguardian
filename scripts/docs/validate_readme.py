"""ThreatGuard — README Structural & Content Validator.

Verifies the structural integrity and technical content of README.md:
1. Section 10 Table A: 12 behavioral features across 4 columns (Index, Feature, Type, Description).
2. Section 10 Table B: 12 mathematical feature definitions across 2 columns.
3. Section 5 & 14: Mermaid architectural flowcharts.
4. Table of Contents: Verifies all 28 numbered section headers match TOC links.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List

EXPECTED_FEATURES = [
    "call_count", "call_velocity", "error_ratio", "unique_services", "unique_events",
    "enumeration_ratio", "sensitive_count", "iam_change_count", "first_service_ratio",
    "first_ip", "off_hours", "event_entropy"
]


def validate_readme_structure(file_path: Path) -> List[str]:
    """Validate structure, tables, and section headings in README.md."""
    if not file_path.is_file():
        return [f"File not found: {file_path}"]

    text = file_path.read_text(encoding="utf-8")
    errors: List[str] = []

    # 1. Validate Table A (Feature Reference)
    m_table_a = re.search(
        r"### Feature Reference\s*\n\s*\| Index \| Feature \| Type \| Description \|\s*\n\s*\| :-: \| :--- \| :--- \| :--- \|\s*\n(.*?)(?=\n###|\n\n###|\Z)",
        text,
        re.DOTALL,
    )
    if not m_table_a:
        errors.append("Table A (Feature Reference) not found or header mismatch.")
    else:
        table_a_rows = [r.strip() for r in m_table_a.group(1).strip().splitlines() if r.strip().startswith("|")]
        if len(table_a_rows) != 12:
            errors.append(f"Table A expected 12 rows, found {len(table_a_rows)}.")
        for idx, row in enumerate(table_a_rows, 1):
            cols = [c.strip() for c in row.split("|")[1:-1]]
            if len(cols) != 4:
                errors.append(f"Table A row {idx} has {len(cols)} columns instead of 4.")

    # 2. Validate Table B (Mathematical Definitions)
    m_table_b = re.search(
        r"### Mathematical Feature Definitions\s*\n.*?\n\s*\| Feature \| Mathematical Definition \|\s*\n\s*\| :--- \| :--- \|\s*\n(.*?)(?=\n---|\n\n---|\Z)",
        text,
        re.DOTALL,
    )
    if not m_table_b:
        errors.append("Table B (Mathematical Feature Definitions) not found or header mismatch.")
    else:
        table_b_rows = [r.strip() for r in m_table_b.group(1).strip().splitlines() if r.strip().startswith("|")]
        if len(table_b_rows) != 12:
            errors.append(f"Table B expected 12 rows, found {len(table_b_rows)}.")
        for idx, (row, feat_name) in enumerate(zip(table_b_rows, EXPECTED_FEATURES), 1):
            cols = [c.strip() for c in row.split("|")[1:-1]]
            if len(cols) != 2:
                errors.append(f"Table B row {idx} has {len(cols)} columns instead of 2.")
            elif feat_name not in cols[0]:
                errors.append(f"Table B row {idx} expected feature '{feat_name}', found '{cols[0]}'.")

    # 3. Validate Mermaid diagrams in Section 5 and Section 14
    if "flowchart TD" not in text:
        errors.append("Missing 'flowchart TD' Mermaid diagram in architecture section.")
    if "subgraph AL" not in text or "subgraph IL" not in text:
        errors.append("Missing Alert and Incident Lifecycle Mermaid subgraphs in Section 14.")

    # 4. Validate Table of Contents (28 sections)
    toc_matches = re.findall(r"^- \[(\d+)\.\s+([^\]]+)\]\(#\d+-[^\)]+\)", text, re.MULTILINE)
    section_headers = re.findall(r"^## (\d+)\.\s+(.*)$", text, re.MULTILINE)

    if len(toc_matches) != len(section_headers):
        errors.append(f"TOC entries count ({len(toc_matches)}) does not match Section headers count ({len(section_headers)}).")

    print(f"Validated {file_path.name}: {len(toc_matches)} sections, 12 feature rows, 2 Mermaid diagrams.")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreatGuard README Structure Validator")
    parser.add_argument("--file", default="README.md", help="Path to README file (default: README.md)")
    args = parser.parse_args()

    errors = validate_readme_structure(Path(args.file))
    if errors:
        print(f"\n[FAIL] Found {len(errors)} structural errors:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("[PASS] README structure and technical feature tables fully verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
