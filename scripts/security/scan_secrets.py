"""ThreatGuard — Repository-Wide Safe Secret Scanner.

Performs static regex pattern matching across repository files to detect exposed
credentials, API keys, private keys, Telegram tokens, and personal access tokens.
Never prints matched secret strings to console output.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

SECRET_PATTERNS = [
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "AWS Access Key ID"),
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key"),
    (re.compile(r"\b\d{6,10}:[A-Za-z0-9_-]{35,}\b"), "Telegram Bot Token"),
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b"), "GitHub Personal Access Token"),
    (re.compile(r"""(?i)(password|secret|api_key|access_key)\s*[:=]\s*["']([A-Za-z0-9!@#$%^&*()_+=-]{8,})["']"""), "Hardcoded Secret/Password"),
]

SAFE_ALLOWLIST = [
    re.compile(r"AKIA\*{16}"),
    re.compile(r"<telegram-token>"),
    re.compile(r"AKIAIOSFODNN7EXAMPLE"),
    re.compile(r"test-secret-key-123"),
]

BINARY_EXTENSIONS = {
    ".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite-wal", ".sqlite-shm",
    ".joblib", ".pkl", ".pyc", ".png", ".jpg", ".jpeg", ".ico", ".gz", ".tar", ".zip",
}


def get_target_files(target_dir: Path) -> List[Path]:
    """Retrieve list of files to scan, preferring git ls-files if available."""
    try:
        res = subprocess.run(
            ["git", "ls-files"],
            cwd=target_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        tracked = [target_dir / line.strip() for line in res.stdout.splitlines() if line.strip()]
        return [p for p in tracked if p.is_file()]
    except Exception:
        # Fallback to directory walk
        ignored_dirs = {".git", ".venv", ".venv_backup", "__pycache__", ".pytest_cache", "scratch"}
        files = []
        for p in target_dir.rglob("*"):
            if p.is_file() and not any(part in p.parts for part in ignored_dirs):
                files.append(p)
        return files


def scan_file(file_path: Path, root_path: Path) -> List[Dict[str, str]]:
    """Scan a single file for secret patterns without exposing matched secret values."""
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return []

    rel_posix = file_path.relative_to(root_path).as_posix()
    is_exempt = (".env.example" in rel_posix) or ("tests/" in rel_posix)

    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    for line_num, line in enumerate(content.splitlines(), 1):
        for pattern, desc in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                matched = match.group(0)
                if any(al.search(matched) for al in SAFE_ALLOWLIST):
                    continue
                findings.append({
                    "file": rel_posix,
                    "line": str(line_num),
                    "type": desc,
                    "is_exempt": str(is_exempt),
                })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreatGuard Safe Secret Scanner")
    parser.add_argument("--path", default=".", help="Root directory to scan (default: current directory)")
    parser.add_argument("--include-tests", action="store_true", help="Report test fixtures and mock keys")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    target_files = get_target_files(root)

    findings: List[Dict[str, str]] = []
    for fp in target_files:
        findings.extend(scan_file(fp, root))

    production_findings = [f for f in findings if f["is_exempt"] == "False"]
    exempt_findings = [f for f in findings if f["is_exempt"] == "True"]

    print(f"Scanned {len(target_files)} tracked files.")
    print(f"Production findings: {len(production_findings)}")
    if args.include_tests:
        print(f"Test fixture / example mock findings: {len(exempt_findings)}")

    if production_findings:
        print("\n[FAIL] Potential exposed secrets detected in production files:")
        for pf in production_findings:
            print(f"  {pf['file']}:{pf['line']} -> {pf['type']}")
        return 1

    print("[PASS] Zero exposed secrets detected in production repository files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
