import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

IMAGE = (
    "ghcr.io/gitleaks/gitleaks:v8.30.1"
    "@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb"
)

def run(args):
    return subprocess.run(args, check=False)

# Ensure there are staged changes to scan.
check = run(["git", "diff", "--cached", "--quiet"])
if check.returncode == 0:
    print("No staged changes to scan.")
    sys.exit(0)
if check.returncode != 1:
    print("Could not inspect Git index.", file=sys.stderr)
    sys.exit(check.returncode)

snapshot = Path(tempfile.mkdtemp(prefix="cloudguardian-gitleaks-"))

try:
    prefix = snapshot.as_posix().rstrip("/") + "/"

    result = run(["git", "checkout-index", "--all", "--prefix=" + prefix])
    if result.returncode != 0:
        print("Could not create staged snapshot.", file=sys.stderr)
        sys.exit(result.returncode)

    mount = (
        "type=bind,source=" + snapshot.as_posix()
        + ",target=/scan,readonly"
    )

    result = run([
        "docker", "run", "--rm",
        "--mount", mount,
        IMAGE,
        "dir", "--redact", "--verbose", "/scan"
    ])

    if result.returncode != 0:
        print("Gitleaks scan failed. Commit blocked.", file=sys.stderr)
        sys.exit(result.returncode)

    print("Gitleaks staged snapshot scan passed.")

finally:
    shutil.rmtree(snapshot, ignore_errors=True)
