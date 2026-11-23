"""Persistent local history for completed public-IP rotation attempts."""

from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timezone
from typing import Any

from guardsnitch.config import appdata_dir


def _history_path():
    return appdata_dir() / "ip-rotation-history.json"


def record_rotation(result: dict[str, Any]) -> None:
    path = _history_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = list(deque(load_history(), maxlen=100))
    entries.insert(0, {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    })
    path.write_text(json.dumps(entries[:100], indent=2), encoding="utf-8")


def load_history() -> list[dict[str, Any]]:
    path = _history_path()
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise ValueError(f"Invalid IP rotation history in {path}")
    return data
