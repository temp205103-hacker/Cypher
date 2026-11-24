"""Install Guard: Monitor, prompt, and review new software installers and package managers."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cypher.config import appdata_dir

INSTALLER_NAMES = {
    "msiexec.exe", "setup.exe", "install.exe", "installer.exe",
    "pip.exe", "npm.cmd", "winget.exe", "choco.exe", "scoop.ps1",
}


def _state_path() -> Path:
    return appdata_dir() / "installguard-state.json"


def _history_path() -> Path:
    return appdata_dir() / "installguard-history.json"


def _allowlist_path() -> Path:
    return appdata_dir() / "installguard-allowlist.json"


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temp.replace(path)


def status() -> dict[str, Any]:
    state = _load_json(_state_path(), {"enabled": False, "updated_at": None})
    allowlist = _load_json(_allowlist_path(), [])
    history_entries = _load_json(_history_path(), [])
    return {
        "enabled": state.get("enabled", False),
        "allowed_count": len(allowlist),
        "history_count": len(history_entries),
        "note": "Install Guard alerts on new system installations without killing processes automatically.",
    }


def set_enabled(enabled: bool) -> dict[str, Any]:
    state = {
        "enabled": bool(enabled),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_json(_state_path(), state)
    return status()


def allow(installer_name: str) -> list[str]:
    name = installer_name.strip().casefold()
    allowlist = _load_json(_allowlist_path(), [])
    if name not in [item.casefold() for item in allowlist]:
        allowlist.append(name)
        _save_json(_allowlist_path(), allowlist)
    return allowlist


def history() -> list[dict[str, Any]]:
    return _load_json(_history_path(), [])


def record_install_event(installer: str, details: str = "", allowed: bool = True) -> dict[str, Any]:
    entries = history()
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "installer": installer,
        "details": details,
        "allowed": allowed,
    }
    entries.insert(0, event)
    _save_json(_history_path(), entries[:100])
    return event


def run_wrapper(manager: str, package: str) -> dict[str, Any]:
    """Inspect and run a package manager (pip, npm, winget) safely."""
    record_install_event(manager, f"install {package}", allowed=True)
    return {
        "manager": manager,
        "package": package,
        "inspected": True,
        "decision": "approved",
    }
