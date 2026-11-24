"""Persist the explicit extension click-check preference."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cypher.config import appdata_dir


def _state_path() -> Path:
    return appdata_dir() / "phish" / "watch.json"


def status() -> dict[str, Any]:
    """Report which watchers are active without implying unavailable coverage."""
    path = _state_path()
    enabled = False
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Could not read phishing watch state: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("enabled"), bool):
            raise RuntimeError("The phishing watch state is invalid.")
        enabled = data["enabled"]
    return {
        "enabled": enabled,
        "extension_click_checks": enabled,
        "clipboard": False,
        "dns_connection": False,
        "note": (
            "The browser extension checks ordinary clicked links when connected. "
            "Clipboard and DNS/connection watchers are not implemented."
        ),
    }


def set_enabled(enabled: bool) -> dict[str, Any]:
    """Enable or disable local extension click checks."""
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    try:
        temporary.write_text(
            json.dumps({"enabled": bool(enabled)}, indent=2),
            encoding="utf-8",
        )
        temporary.replace(path)
    except OSError as exc:
        raise RuntimeError(f"Could not update phishing watch state: {exc}") from exc
    return status()
