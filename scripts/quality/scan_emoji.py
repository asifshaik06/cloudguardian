"""ThreatGuard — Unicode Emoji Audit Scanner.

Enforces Rule 1 (Strict Emoji Prohibition Convention):
Never introduce emoji characters anywhere in ThreatGuard source code, frontend,
backend, documentation, tests, assets, configuration, or GitHub-facing files.
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

EMOJI_REGEX = re.compile(
    "["
    "\U0001F600-\U0001F64F"  # emoticons
    "\U0001F300-\U0001F5FF"  # symbols & pictographs
    "\U0001F680-\U0001F6FF"  # transport & map
    "\U0001F1E0-\U0001F1FF"  # flags (iOS)
    "\U00002702-\U000027B0"  # dingbats
    "\U0001F900-\U0001F9FF"  # supplemental symbols
    "\U0001FA00-\U0001FA6F"  # chess symbols
    "\U0001FA70-\U0001FAFF"  # symbols and pictographs extended-a
    "\U00002600-\U000026FF"  # miscellaneous symbols
    "]+", flags=re.UNICODE
)

TEXT_EXTENSIONS = {
    ".py", ".md", ".html", ".js", ".css", ".svg", ".json",
    ".yaml", ".yml", ".txt", ".example", ".sh", ".ps1", ".toml"
}

IGNORED_DIRS = {
    ".git", ".venv", ".venv_backup", "__pycache__",
    ".pytest_cache", "node_modules", "scratch"
}


def scan_file(filepath: Path) -> List[Tuple[int, str, List[str]]]:
    """Scan a single file for Unicode emoji code points."""
    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception:
        return []

    matches = []
    for line_num, line in enumerate(content.splitlines(), 1):
        found = EMOJI_REGEX.findall(line)
        if found:
            matches.append((line_num, line.strip(), found))
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreatGuard Unicode Emoji Scanner")
    parser.add_argument("--path", default=".", help="File or directory path to scan (default: repository root)")
    args = parser.parse_args()

    target = Path(args.path).resolve()
    violations = []
    scanned_count = 0

    if target.is_file():
        scanned_count = 1
        matches = scan_file(target)
        for m in matches:
            violations.append((target.as_posix(), m[0], m[2]))
    else:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for file_name in files:
                p = Path(root) / file_name
                if p.suffix.lower() in TEXT_EXTENSIONS:
                    scanned_count += 1
                    matches = scan_file(p)
                    for m in matches:
                        violations.append((p.relative_to(target).as_posix(), m[0], m[2]))

    print(f"Scanned {scanned_count} files for Unicode emojis.")
    if violations:
        print(f"\n[FAIL] Found {len(violations)} emoji violations:")
        for v in violations:
            print(f"  {v[0]}:{v[1]} -> {v[2]}")
        return 1

    print("[PASS] Zero emoji characters detected across repository files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
