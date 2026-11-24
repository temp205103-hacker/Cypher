"""Local quarantine index."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from cypher.config import appdata_dir


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

    from cypher.fscan.trust import is_excluded_path
    if is_excluded_path(source):
        raise ValueError(f"Protected system or project path cannot be quarantined: {source}")
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
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass
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


def stop_detected_process(item_id: str) -> dict[str, Any]:
    items = _load_items()
    item = next((entry for entry in items if entry.get("id") == item_id), None)
    if item is None or item.get("status") not in {"pending", "quarantined"}:
        raise ValueError(f"No active finding exists with ID {item_id}.")

    stored_path = item.get("quarantine_path") if item.get("status") == "quarantined" else item["path"]
    if stored_path:
        artifact = Path(str(stored_path))
        if artifact.is_symlink():
            raise RuntimeError(f"Refusing to trust a symbolic link for this finding: {artifact}")
        if artifact.exists():
            try:
                current_stat = artifact.stat()
            except OSError as exc:
                raise RuntimeError(f"Could not validate detected file {artifact}: {exc}") from exc
            if (
                current_stat.st_size != item.get("file_size")
                or current_stat.st_mtime_ns != item.get("file_mtime_ns")
            ):
                raise RuntimeError(f"File changed after scanning; rescan it before stopping its process: {artifact}")

    expected_path = os.path.normcase(str(Path(str(item["path"])).resolve()))
    matches: list[psutil.Process] = []
    inaccessible: list[int] = []
    try:
        processes = psutil.process_iter(["pid", "exe"])
        for process in processes:
            try:
                executable = process.info.get("exe") or process.exe()
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                inaccessible.append(process.pid)
                continue
            if executable and os.path.normcase(str(Path(executable).resolve())) == expected_path:
                matches.append(process)
    except psutil.Error as exc:
        raise RuntimeError(f"Could not inspect running processes: {exc}") from exc

    if not matches:
        if inaccessible:
            raise RuntimeError(
                "No accessible process matched this finding. Run elevated if the process "
                "belongs to another user or service."
            )
        raise ValueError("No running process matches this detected file.")

    stopped: list[int] = []
    for process in matches:
        try:
            executable = process.exe()
            if os.path.normcase(str(Path(executable).resolve())) != expected_path:
                continue
            process.terminate()
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stopped.append(process.pid)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as exc:
            message = f"Could not stop process {process.pid}; administrator rights may be required."
            if stopped:
                message = f"Stopped PID(s) {', '.join(map(str, stopped))}; {message}"
            raise RuntimeError(message) from exc
        except psutil.TimeoutExpired as exc:
            message = f"Process {process.pid} did not stop in time."
            if stopped:
                message = f"Stopped PID(s) {', '.join(map(str, stopped))}; {message}"
            raise RuntimeError(message) from exc
        except psutil.Error as exc:
            message = f"Could not stop process {process.pid}: {exc}"
            if stopped:
                message = f"Stopped PID(s) {', '.join(map(str, stopped))}; {message}"
            raise RuntimeError(message) from exc

    if not stopped:
        raise ValueError("No running process still matched this detected file.")
    return {"stopped": stopped, "path": str(item["path"])}
