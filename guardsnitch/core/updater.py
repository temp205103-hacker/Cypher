"""Explicit, fast-forward-only updates from the GuardSnitch.ai GitHub repository."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
from threading import Lock
import time
from urllib.parse import urlsplit
from typing import Any


EXPECTED_REPOSITORY = "/temp205103-hacker/guardsnitch.ai"
STATUS_CACHE_SECONDS = 300


class UpdateError(RuntimeError):
    """Expected, user-facing update failure."""


_STATUS_LOCK = Lock()
_STATUS_CACHE: dict[str, Any] | None = None
_STATUS_CACHED_AT = 0.0


def _package_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _git(root: Path, *arguments: str, timeout: int = 20) -> str:
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpdateError(f"Could not start Git: {type(exc).__name__}.") from exc
    if result.returncode:
        raise UpdateError(f"Git {arguments[0]} failed (exit code {result.returncode}).")
    return result.stdout.strip()


def _trusted_origin(origin: str) -> bool:
    origin = origin.strip()
    if origin.startswith("git@github.com:"):
        repository = "/" + origin.partition(":")[2]
    else:
        parsed = urlsplit(origin)
        if parsed.scheme not in {"https", "ssh"} or parsed.hostname != "github.com":
            return False
        if parsed.query or parsed.fragment or parsed.password is not None:
            return False
        if parsed.scheme == "https" and parsed.username is not None:
            return False
        if parsed.scheme == "ssh" and parsed.username not in {None, "git"}:
            return False
        try:
            port = parsed.port
        except ValueError:
            return False
        if port not in {None, 443 if parsed.scheme == "https" else 22}:
            return False
        repository = parsed.path
    repository = repository.rstrip("/")
    if repository.casefold().endswith(".git"):
        repository = repository[:-4]
    return repository.casefold() == EXPECTED_REPOSITORY


def _fetch_status() -> dict[str, Any]:
    root = _package_root()
    try:
        git_root = Path(_git(root, "rev-parse", "--show-toplevel")).resolve()
    except UpdateError as exc:
        raise UpdateError("Updates require GuardSnitch.ai to be installed from a Git clone.") from exc
    if git_root != root.resolve():
        raise UpdateError("The installed GuardSnitch.ai checkout could not be located.")

    branch = _git(root, "branch", "--show-current")
    if branch != "main":
        raise UpdateError("Updates are available only from the main branch.")
    origin = _git(root, "remote", "get-url", "origin")
    if not _trusted_origin(origin):
        raise UpdateError("The origin remote is not the trusted GuardSnitch.ai GitHub repository.")

    _git(root, "fetch", "--quiet", "origin", "main", timeout=15)
    dirty = bool(_git(root, "status", "--porcelain"))
    counts = _git(root, "rev-list", "--left-right", "--count", "HEAD...FETCH_HEAD").split()
    if len(counts) != 2 or not all(item.isdigit() for item in counts):
        raise UpdateError("Git returned an invalid update comparison.")
    ahead, behind = (int(item) for item in counts)
    if ahead and behind:
        raise UpdateError("Local and remote main have diverged; reconcile them manually before updating.")

    return {
        "available": behind > 0,
        "current": _git(root, "rev-parse", "--short", "HEAD"),
        "latest": _git(root, "rev-parse", "--short", "FETCH_HEAD"),
        "target": _git(root, "rev-parse", "FETCH_HEAD"),
        "behind": behind,
        "dirty": dirty,
        "branch": branch,
    }


def check_for_updates(force: bool = False) -> dict[str, Any]:
    global _STATUS_CACHE, _STATUS_CACHED_AT
    with _STATUS_LOCK:
        if (
            not force
            and _STATUS_CACHE is not None
            and time.monotonic() - _STATUS_CACHED_AT < STATUS_CACHE_SECONDS
        ):
            return dict(_STATUS_CACHE)
        try:
            status = _fetch_status()
        except UpdateError as exc:
            status = {"available": False, "error": str(exc)}
        status.pop("target", None)
        _STATUS_CACHE = status
        _STATUS_CACHED_AT = time.monotonic()
        return dict(status)


def update_checkout() -> dict[str, Any]:
    global _STATUS_CACHE, _STATUS_CACHED_AT
    with _STATUS_LOCK:
        status = _fetch_status()
        if status["dirty"]:
            raise UpdateError("Local changes detected. Commit or stash them before updating.")
        if not status["behind"]:
            status.pop("target", None)
            _STATUS_CACHE = status
            _STATUS_CACHED_AT = time.monotonic()
            return {"updated": False, **status}

        root = _package_root()
        if _git(root, "status", "--porcelain"):
            raise UpdateError("Local changes appeared during the update check; no update was applied.")
        _git(root, "merge", "--ff-only", status["target"], timeout=45)
        status = {
            "available": False,
            "current": _git(root, "rev-parse", "--short", "HEAD"),
            "latest": _git(root, "rev-parse", "--short", "HEAD"),
            "behind": 0,
            "dirty": False,
            "branch": "main",
        }
        _STATUS_CACHE = status
        _STATUS_CACHED_AT = time.monotonic()
        return {"updated": True, **status}
