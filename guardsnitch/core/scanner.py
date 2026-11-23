"""Local source scanning for secrets, personal data, and risky code patterns."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Iterable

from guardsnitch.config import appdata_dir
from guardsnitch.core.pii import find_pii
from guardsnitch.core.redact import redact_text
from guardsnitch.core.secrets import find_secrets


MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__"}
RISK_PATTERNS = (
    ("dynamic-eval", re.compile(r"\b(?:eval|exec)\s*\("), "Dynamic code execution"),
    ("shell-true", re.compile(r"\bshell\s*=\s*True\b"), "Shell execution enabled"),
    ("disabled-tls", re.compile(r"\bverify\s*=\s*False\b"), "TLS verification disabled"),
)


def _finding(path: str, line_number: int, category: str, value: str, line: str) -> dict[str, object]:
    fingerprint = hashlib.sha256(
        f"{path}:{line_number}:{category}:{value}".encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    return {
        "id": fingerprint,
        "path": path,
        "line": line_number,
        "category": category,
        "severity": "high" if category in {"private_key", "aws_access_key"} else "medium",
        "message": category.replace("-", " ").replace("_", " ").capitalize(),
        "snippet": redact_text(line.strip())[:240],
    }


def scan_text(text: str, path: str = "<stdin>") -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for category, value in find_secrets(line):
            findings.append(_finding(path, line_number, category, value, line))
        for category, value in find_pii(line):
            findings.append(_finding(path, line_number, category, value, line))
        for category, pattern, message in RISK_PATTERNS:
            for match in pattern.finditer(line):
                findings.append(_finding(path, line_number, category, match.group(0), line))
                findings[-1]["message"] = message
    unique = {str(item["id"]): item for item in findings}
    return list(unique.values())


def scan_paths(paths: Iterable[Path]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for target in paths:
        if target.is_symlink():
            raise ValueError(f"Refusing to scan a symbolic link; scan its target explicitly: {target}")
        if target.is_dir():
            children = (
                item for item in target.rglob("*")
                if item.is_file() and not any(part in SKIP_DIRS for part in item.parts)
            )
        elif target.is_file():
            children = (target,)
        else:
            raise FileNotFoundError(str(target))
        for item in children:
            if item.is_symlink() or item.stat().st_size > MAX_FILE_BYTES:
                continue
            try:
                text = item.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            findings.extend(scan_text(text, str(item)))
    return findings


def staged_files(cwd: Path | None = None) -> list[tuple[str, str]]:
    """Return staged text blobs without reading unstaged working-tree content."""
    root = cwd or Path.cwd()
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(detail or "Could not read staged Git changes.")
    files: list[tuple[str, str]] = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = raw_path.decode(errors="surrogateescape")
        if any(part in SKIP_DIRS for part in Path(relative).parts):
            continue
        blob = subprocess.run(
            ["git", "show", f":{relative}"],
            cwd=root,
            capture_output=True,
            check=False,
        )
        if blob.returncode:
            continue
        if len(blob.stdout) > MAX_FILE_BYTES or b"\0" in blob.stdout:
            continue
        files.append((relative, blob.stdout.decode("utf-8", errors="replace")))
    return files


def scan_staged(cwd: Path | None = None) -> list[dict[str, object]]:
    return [
        finding
        for path, text in staged_files(cwd)
        for finding in scan_text(text, path)
    ]


def save_findings(findings: Iterable[dict[str, object]]) -> Path:
    target = appdata_dir() / "scan-findings.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(list(findings), indent=2), encoding="utf-8")
    return target


def load_findings() -> list[dict[str, object]]:
    target = appdata_dir() / "scan-findings.json"
    if not target.exists():
        return []
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise ValueError(f"Invalid scan findings in {target}")
    return data


def scan_path(path: str) -> list[dict[str, object]]:
    target = Path(path).expanduser()
    if path == "-":
        import sys

        return scan_text(sys.stdin.read())
    return scan_paths([target])
