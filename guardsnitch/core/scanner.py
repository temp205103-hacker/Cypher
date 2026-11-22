"""Shared scanner entry point."""

from __future__ import annotations

from pathlib import Path


def scan_path(path: str) -> list[dict[str, object]]:
    target = Path(path)
    if not target.exists() and path != "-":
        raise FileNotFoundError(path)
    return []
