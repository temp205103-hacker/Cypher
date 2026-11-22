"""Local quarantine index."""

from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardsnitch.config import appdata_dir


def _items_path() -> Path:
    return appdata_dir() / "malware-items.json"


def _load_items() -> list[dict[str, Any]]:
    index = _items_path()
    if not index.exists():
        return []
    try:
        data = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read malware item index {index}: {exc}") from exc
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise RuntimeError(f"Malware item index {index} has an invalid format.")
    return data


def _save_items(items: list[dict[str, Any]]) -> None:
    index = _items_path()
    index.parent.mkdir(parents=True, exist_ok=True)
    temporary = index.with_suffix(".tmp")
    try:
        temporary.write_text(json.dumps(items, indent=2), encoding="utf-8")
        temporary.replace(index)
    except OSError as exc:
        raise RuntimeError(f"Could not save malware item index {index}: {exc}") from exc


def queue_findings(scan_result: dict[str, object]) -> list[dict[str, Any]]:
    findings = scan_result.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Scan result does not contain a findings list.")
    if not findings:
        return []

    items = _load_items()
    queued: list[dict[str, Any]] = []
    timestamp = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        if not isinstance(finding, dict) or not finding.get("path"):
            raise ValueError("Scan result contains an invalid finding.")
        detected_path = Path(str(finding["path"]))
        try:
            file_stat = detected_path.stat()
        except OSError as exc:
            raise RuntimeError(f"Detected file is no longer available: {detected_path}") from exc
        item = {
            "id": uuid.uuid4().hex[:12],
            "status": "pending",
            "detected_at": timestamp,
            "path": str(detected_path),
            "file_size": file_stat.st_size,
            "file_mtime_ns": file_stat.st_mtime_ns,
            "engine": str(finding.get("engine", "unknown")),
            "classification": str(finding.get("classification", "suspicious")),
            "signature": str(finding.get("signature", "unknown")),
            "quarantine_path": None,
        }
        items.append(item)
        queued.append(item)
    _save_items(items)
    return queued


def list_findings() -> list[dict[str, Any]]:
    return [item for item in _load_items() if item.get("status") == "pending"]


def quarantine_dir() -> Path:
    target = appdata_dir() / "quarantine"
    target.mkdir(parents=True, exist_ok=True)
    return target


def list_quarantine() -> list[dict[str, object]]:
    return [
        item
        for item in _load_items()
        if item.get("status") in {"quarantining", "quarantined", "restoring", "deleting"}
    ]


def quarantine_finding(item_id: str) -> dict[str, Any]:
    items = _load_items()
    item = next((entry for entry in items if entry.get("id") == item_id), None)
    if item is None or item.get("status") != "pending":
        raise ValueError(f"No pending finding exists with ID {item_id}.")

    source = Path(str(item["path"]))
    if source.is_symlink() or not source.is_file():
        raise FileNotFoundError(f"Detected file no longer exists: {source}")
    try:
        current_stat = source.stat()
    except OSError as exc:
        raise RuntimeError(f"Could not validate detected file {source}: {exc}") from exc
    if (
        current_stat.st_size != item.get("file_size")
        or current_stat.st_mtime_ns != item.get("file_mtime_ns")
    ):
        raise RuntimeError(f"File changed after scanning; scan it again before quarantine: {source}")
    destination = quarantine_dir() / f"{item_id}.blocked"
    if destination.exists():
        raise FileExistsError(f"Quarantine destination already exists: {destination}")

    item["quarantine_path"] = str(destination)
    item["status"] = "quarantining"
    _save_items(items)
    try:
        shutil.move(str(source), str(destination))
    except OSError:
        item["status"] = "pending"
        item["quarantine_path"] = None
        _save_items(items)
        raise

    item["status"] = "quarantined"
    _save_items(items)
    return item


def restore_quarantined(item_id: str) -> dict[str, Any]:
    items = _load_items()
    item = next((entry for entry in items if entry.get("id") == item_id), None)
    if item is None or item.get("status") != "quarantined":
        raise ValueError(f"No quarantined item exists with ID {item_id}.")

    source = Path(str(item["quarantine_path"]))
    destination = Path(str(item["path"]))
    if not source.is_file():
        raise FileNotFoundError(f"Quarantined file is missing: {source}")
    if destination.exists():
        raise FileExistsError(f"Cannot restore; the original path already exists: {destination}")

    item["status"] = "restoring"
    _save_items(items)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
    except OSError:
        item["status"] = "quarantined"
        _save_items(items)
        raise
    item["status"] = "restored"
    item["quarantine_path"] = None
    _save_items(items)
    return item


def delete_quarantined(item_id: str) -> dict[str, Any]:
    items = _load_items()
    item = next((entry for entry in items if entry.get("id") == item_id), None)
    if item is None or item.get("status") != "quarantined":
        raise ValueError(f"No quarantined item exists with ID {item_id}.")

    target = Path(str(item["quarantine_path"]))
    if not target.is_file():
        raise FileNotFoundError(f"Quarantined file is missing: {target}")
    item["status"] = "deleting"
    _save_items(items)
    try:
        target.unlink()
    except OSError:
        item["status"] = "quarantined"
        _save_items(items)
        raise
    item["status"] = "deleted"
    item["quarantine_path"] = None
    _save_items(items)
    return item
