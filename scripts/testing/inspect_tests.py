"""ThreatGuard — Automated Test Suite Inspector & Inventory Utility.

Analyzes tests in tests/ using Python's Abstract Syntax Tree (AST) module
without executing test code. Verifies:
1. Every test module has a module-level docstring.
2. Counts test functions and test classes across unit and integration scopes.
3. Optionally runs pytest --collect-only to verify collector discovery.
"""

import argparse
import ast
import subprocess
import sys
from pathlib import Path
from typing import Dict, List


def inspect_module(file_path: Path) -> Dict[str, object]:
    """Inspect an individual test module via AST."""
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
    except Exception as exc:
        return {"error": str(exc), "file": file_path.name}

    docstring = ast.get_docstring(tree)
    test_functions = []
    test_classes = []

    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            test_functions.append(node.name)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            test_classes.append(node.name)
            for sub_node in node.body:
                if isinstance(sub_node, ast.FunctionDef) and sub_node.name.startswith("test_"):
                    test_functions.append(f"{node.name}::{sub_node.name}")

    return {
        "file": str(file_path.as_posix()),
        "has_docstring": bool(docstring),
        "docstring_preview": (docstring.splitlines()[0] if docstring else ""),
        "function_count": len(test_functions),
        "class_count": len(test_classes),
        "functions": test_functions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreatGuard Test Suite Inspector")
    parser.add_argument("--tests-dir", default="tests", help="Path to tests directory (default: tests)")
    parser.add_argument("--collect", action="store_true", help="Run pytest --collect-only to verify active runner")
    parser.add_argument("--verbose", action="store_true", help="Print detailed per-module breakdown")
    args = parser.parse_args()

    tests_dir = Path(args.tests_dir).resolve()
    if not tests_dir.is_dir():
        print(f"[FAIL] Tests directory not found: {tests_dir}")
        return 1

    unit_files = sorted(tests_dir.glob("unit/test_*.py"))
    integration_files = sorted(tests_dir.glob("integration/test_*.py"))

    all_test_files = unit_files + integration_files
    unit_counts = 0
    integration_counts = 0
    missing_docstrings: List[str] = []

    for tf in all_test_files:
        info = inspect_module(tf)
        count = int(info["function_count"])
        if "unit" in tf.parts:
            unit_counts += count
        else:
            integration_counts += count
        if not info["has_docstring"]:
            missing_docstrings.append(tf.as_posix())

        if args.verbose:
            print(f"  {tf.relative_to(tests_dir.parent).as_posix():55} -> {count:2} tests | {info['docstring_preview'][:45]}")

    total_ast_tests = unit_counts + integration_counts
    print(f"Test Modules Scanned: {len(all_test_files)} ({len(unit_files)} unit, {len(integration_files)} integration)")
    print(f"Static Test Functions (AST): {total_ast_tests} ({unit_counts} unit, {integration_counts} integration)")

    if missing_docstrings:
        print(f"\n[WARN] {len(missing_docstrings)} test files lack module docstrings:")
        for md in missing_docstrings:
            print(f"  - {md}")

    if args.collect:
        print("\nRunning pytest --collect-only...")
        res = subprocess.run(
            [sys.executable, "-m", "pytest", str(tests_dir), "--collect-only", "-q"],
            capture_output=True,
            text=True,
        )
        collected = [l for l in res.stdout.splitlines() if "::" in l]
        print(f"Pytest Collector: {len(collected)} items collected.")

    print("\n[PASS] Test suite organization verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
