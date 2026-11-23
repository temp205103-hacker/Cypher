"""Install a pre-commit hook that scans the exact staged Git blobs."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys


def install_pre_commit_hook(cwd: Path | None = None) -> Path:
    root = cwd or Path.cwd()
    try:
        git_dir = subprocess.check_output(
            ["git", "rev-parse", "--git-path", "hooks"],
            cwd=root,
            text=True,
            stderr=subprocess.PIPE,
        ).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Run this command inside a Git repository: {exc}") from exc
    hooks = Path(git_dir)
    if not hooks.is_absolute():
        hooks = (root / hooks).resolve()
    if not hooks.is_dir():
        raise RuntimeError("Cannot locate this repository's Git hooks directory.")

    hook = hooks / "pre-commit"
    backup = hooks / "pre-commit.guardsnitch-backup"
    if hook.exists() and backup.exists():
        raise RuntimeError("A GuardSnitch pre-commit hook is already installed.")
    if hook.exists():
        hook.replace(backup)

    python = shlex.quote(Path(sys.executable).as_posix())
    lines = ["#!/bin/sh", "set -e"]
    if backup.exists():
        lines.extend([f'"{backup.as_posix()}"', ""])
    lines.extend([f"{python} -m guardsnitch.cli scan --staged", ""])
    try:
        hook.write_text("\n".join(lines), encoding="utf-8")
        if os.name != "nt":
            hook.chmod(0o755)
    except OSError:
        if backup.exists() and not hook.exists():
            backup.replace(hook)
        raise
    return hook
