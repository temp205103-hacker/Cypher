"""Windows Task Scheduler integration for recurring local scans and IP rotation."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


TASKS = {
    "malware": "CypherMalwareScan",
    "ip": "CypherIpRotation",
}
LEGACY_TASKS = {
    "malware": "GuardSnitchMalwareScan",
    "ip": "GuardSnitchIpRotation",
}


def _run(arguments: list[str]) -> str:
    if os.name != "nt":
        raise RuntimeError("Recurring schedules are supported only on Windows.")
    try:
        result = subprocess.run(
            ["schtasks", *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Windows Task Scheduler request failed: {exc}") from exc
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(detail or "Windows Task Scheduler rejected the request.")
    return result.stdout.strip()


def migrate_legacy_schedules() -> None:
    """Recreate existing scheduled jobs with Cypher names and module paths."""
    for kind, legacy_name in LEGACY_TASKS.items():
        try:
            xml = _run(["/Query", "/TN", legacy_name, "/XML"])
        except RuntimeError as exc:
            message = str(exc).casefold()
            if "cannot find" in message or "does not exist" in message:
                continue
            raise

        root = ET.fromstring(xml)
        exec_nodes = [
            node for node in root.iter()
            if node.tag.rsplit("}", 1)[-1] == "Exec"
        ]
        if not exec_nodes:
            raise RuntimeError(f"Could not migrate scheduled task {legacy_name}: no executable action.")
        command = subprocess.list2cmdline([
            "-m", "cypher.cli",
            *(["malware", "scan"] if kind == "malware" else ["ip", "rotate"]),
        ])
        for node in exec_nodes:
            children = {child.tag.rsplit("}", 1)[-1]: child for child in node}
            command_node = children.get("Command")
            if command_node is None:
                raise RuntimeError(
                    f"Could not migrate scheduled task {legacy_name}: command is missing."
                )
            command_node.text = sys.executable
            if "Arguments" in children:
                children["Arguments"].text = command
            else:
                namespace = node.tag.rpartition("}")[0]
                argument_tag = namespace + "}Arguments" if namespace else "Arguments"
                ET.SubElement(node, argument_tag).text = command
        for node in root.iter():
            if node.tag.rsplit("}", 1)[-1] == "URI" and node.text:
                node.text = node.text.replace(legacy_name, TASKS[kind])

        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as handle:
                temp_path = Path(handle.name)
                handle.write(ET.tostring(root, encoding="utf-8", xml_declaration=True))
            _run(["/Create", "/TN", TASKS[kind], "/XML", str(temp_path), "/F"])
            _run(["/Delete", "/TN", legacy_name, "/F"])
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)


def set_schedule(kind: str, interval: str, at: str = "03:00") -> str:
    if kind not in TASKS:
        raise ValueError(f"Unsupported schedule: {kind}")
    interval = interval.casefold()
    if kind == "malware" and interval not in {"hourly", "daily"}:
        raise ValueError("Malware scan interval must be hourly or daily.")
    if kind == "ip" and interval != "daily":
        raise ValueError("IP rotation interval must be daily.")
    if interval == "daily" and (
        len(at) != 5 or at[2] != ":" or not at[:2].isdigit() or not at[3:].isdigit()
        or int(at[:2]) > 23 or int(at[3:]) > 59
    ):
        raise ValueError("Schedule time must use 24-hour HH:MM format.")

    migrate_legacy_schedules()
    subcommand = ["malware", "scan"] if kind == "malware" else ["ip", "rotate"]
    command = subprocess.list2cmdline([sys.executable, "-m", "cypher.cli", *subcommand])
    frequency = "HOURLY" if interval == "hourly" else "DAILY"
    args = ["/Create", "/TN", TASKS[kind], "/SC", frequency, "/TR", command, "/F"]
    if frequency == "DAILY":
        args.extend(["/ST", at])
    return _run(args)


def remove_schedule(kind: str) -> str:
    if kind not in TASKS:
        raise ValueError(f"Unsupported schedule: {kind}")
    migrate_legacy_schedules()
    return _run(["/Delete", "/TN", TASKS[kind], "/F"])


def schedule_status(kind: str) -> dict[str, object]:
    if kind not in TASKS:
        raise ValueError(f"Unsupported schedule: {kind}")
    migrate_legacy_schedules()
    try:
        output = _run(["/Query", "/TN", TASKS[kind], "/FO", "LIST"])
    except RuntimeError as exc:
        if "cannot find" in str(exc).casefold() or "does not exist" in str(exc).casefold():
            return {"enabled": False, "task": TASKS[kind]}
        raise
    return {"enabled": True, "task": TASKS[kind], "details": output}
