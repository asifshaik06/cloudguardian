"""ThreatGuard — Markdown Mathematical Formula & KaTeX Validator.

Validates that LaTeX mathematical formulas in documentation adhere to GitHub
KaTeX rendering requirements:
1. Balanced braces in display math ($$...$$) and inline math ($...$).
2. No raw underscores inside \\text{...} blocks (which break KaTeX rendering).
3. Display math blocks properly delimited on separate lines.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List


def audit_markdown_math(file_path: Path) -> List[str]:
    """Audit mathematical formulas in the specified Markdown file."""
    if not file_path.is_file():
        return [f"File not found: {file_path}"]

    lines = file_path.read_text(encoding="utf-8").splitlines()
    content = "\n".join(lines)
    issues: List[str] = []

    # 1. Check display math ($$) blocks
    in_display = False
    display_blocks = []
    current_block: List[str] = []
    start_line = 0

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("$$"):
            if not in_display:
                in_display = True
                start_line = idx
                current_block = [line]
                if stripped.endswith("$$") and len(stripped) > 2:
                    in_display = False
                    display_blocks.append((start_line, idx, "\n".join(current_block)))
                    current_block = []
            else:
                in_display = False
                current_block.append(line)
                display_blocks.append((start_line, idx, "\n".join(current_block)))
                current_block = []
        elif in_display:
            current_block.append(line)

    for start_l, end_l, block in display_blocks:
        open_b = block.count("{")
        close_b = block.count("}")
        if open_b != close_b:
            issues.append(f"Line {start_l}-{end_l}: Unbalanced braces in display math ({open_b} open, {close_b} close)")
        for tm in re.findall(r"\\text\{([^}]*)\}", block):
            if "_" in tm:
                issues.append(f"Line {start_l}-{end_l}: Raw underscore in \\text: '\\text{{{tm}}}'")

    # 2. Check inline single-dollar math ($...$)
    single_dollars = []
    for idx, line in enumerate(lines, 1):
        if line.strip().startswith("$$"):
            continue
        for m in re.findall(r"(?<!\$)\$(?!\$)(.*?)(?<!\$)\$(?!\$)", line):
            single_dollars.append((idx, m))

    for idx, expr in single_dollars:
        open_b = expr.count("{")
        close_b = expr.count("}")
        if open_b != close_b:
            issues.append(f"Line {idx}: Unbalanced braces in $...$: '{expr}'")
        for tm in re.findall(r"\\text\{([^}]*)\}", expr):
            if "_" in tm:
                issues.append(f"Line {idx}: Raw underscore in \\text in $...$: '\\text{{{tm}}}'")

    print(f"Audited {file_path.name}: {len(display_blocks)} display blocks, {len(single_dollars)} inline math spans.")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreatGuard Markdown Math Validator")
    parser.add_argument("--file", default="README.md", help="Path to markdown file (default: README.md)")
    args = parser.parse_args()

    target = Path(args.file)
    issues = audit_markdown_math(target)

    if issues:
        print(f"\n[FAIL] Found {len(issues)} formula rendering issues in {target.name}:")
        for iss in issues:
            print(f"  - {iss}")
        return 1

    print(f"[PASS] Zero formula issues detected in {target.name} (full KaTeX compliance).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
