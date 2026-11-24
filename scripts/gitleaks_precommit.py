import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

IMAGE = (
    "ghcr.io/gitleaks/gitleaks:v8.30.1"
    "@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb"
)

# High-fidelity regex patterns for sensitive data detection (fallback scanner)
SECRET_PATTERNS = [
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "AWS Access Key ID"),
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key"),
    (re.compile(r"\b\d{6,10}:[A-Za-z0-9_-]{35,}\b"), "Telegram Bot Token"),
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b"), "GitHub Personal Access Token"),
    (re.compile(r"""(?i)(password|secret|api_key|access_key)\s*[:=]\s*["']([A-Za-z0-9!@#$%^&*()_+=-]{8,})["']"""), "Hardcoded Secret/Password"),
]

# Patterns allowed in example or test files
SAFE_ALLOWLIST = [
    re.compile(r"AKIA\*{16}"),  # Masked keys
    re.compile(r"<telegram-token>"),
    re.compile(r"AKIAIOSFODNN7EXAMPLE"),  # AWS documentation example key
    re.compile(r"test-secret-key-123"),  # Test harness mock key
]


def run(args):
    if not shutil.which(args[0]):
        return subprocess.CompletedProcess(args=args, returncode=127, stdout="", stderr=f"{args[0]} not found")
    try:
        return subprocess.run(args, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args=args, returncode=127, stdout="", stderr=f"{args[0]} not found")


def scan_directory_regex(root_path: Path) -> list:
    """Fallback scanner searching staged files for known secret patterns."""
    findings = []
    for file_path in root_path.rglob("*"):
        if not file_path.is_file():
            continue
        # Skip binary files or git metadata
        if file_path.suffix.lower() in {".db", ".db-wal", ".db-shm", ".joblib", ".pkl", ".pyc", ".png", ".jpg", ".gz", ".tar"}:
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, desc in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                matched_str = match.group(0)
                # Check allowlist
                if any(al.search(matched_str) for al in SAFE_ALLOWLIST):
                    continue
                # Skip example files or test fixtures where dummy secrets are explicitly declared
                rel_path = file_path.relative_to(root_path).as_posix()
                if ".env.example" in rel_path or "tests/" in rel_path:
                    continue
                findings.append(f"{rel_path}: Potential {desc} detected (matched pattern length {len(matched_str)})")
    return findings


# Ensure there are staged changes to scan.
check = run(["git", "diff", "--cached", "--quiet"])
if check.returncode == 0:
    print("No staged changes to scan.")
    sys.exit(0)
if check.returncode != 1:
    print("Could not inspect Git index.", file=sys.stderr)
    sys.exit(check.returncode)

snapshot = Path(tempfile.mkdtemp(prefix="threatguard-gitleaks-"))

try:
    prefix = snapshot.as_posix().rstrip("/") + "/"
    result = run(["git", "checkout-index", "--all", "--prefix=" + prefix])
    if result.returncode != 0:
        print("Could not create staged snapshot.", file=sys.stderr)
        sys.exit(result.returncode)

    # 1. First attempt: Official Gitleaks Docker container
    docker_check = run(["docker", "info"])
    if docker_check.returncode == 0:
        mount = "type=bind,source=" + snapshot.as_posix() + ",target=/scan,readonly"
        result = run([
            "docker", "run", "--rm",
            "--mount", mount,
            IMAGE,
            "dir", "--redact", "--verbose", "/scan"
        ])
        if result.returncode != 0:
            print("Gitleaks scan failed. Commit blocked.", file=sys.stderr)
            if result.stdout:
                print(result.stdout)
            sys.exit(result.returncode)
        print("Gitleaks staged snapshot scan passed (Docker).")
        sys.exit(0)

    # 2. Second attempt: Standalone gitleaks CLI
    standalone = run(["gitleaks", "version"])
    if standalone.returncode == 0:
        gl_run = run(["gitleaks", "dir", snapshot.as_posix(), "--redact", "--verbose"])
        if gl_run.returncode != 0:
            print("Gitleaks scan failed. Commit blocked.", file=sys.stderr)
            sys.exit(gl_run.returncode)
        print("Gitleaks staged snapshot scan passed (Standalone).")
        sys.exit(0)

    # 3. Third attempt: Native Python secret scanner fallback
    leaks = scan_directory_regex(snapshot)
    if leaks:
        print("Secret scanner failed! Staged secrets detected:", file=sys.stderr)
        for leak in leaks:
            print(f"  [!] {leak}", file=sys.stderr)
        sys.exit(1)

    print("Secret verification passed (Native Python Fallback Scanner - Docker offline).")

finally:
    shutil.rmtree(snapshot, ignore_errors=True)
