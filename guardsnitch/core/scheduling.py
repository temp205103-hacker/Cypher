"""Windows Task Scheduler integration for recurring local scans and IP rotation."""

from __future__ import annotations

import os
import subprocess
import sys


TASKS = {
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

    subcommand = ["malware", "scan"] if kind == "malware" else ["ip", "rotate"]
    command = subprocess.list2cmdline([sys.executable, "-m", "guardsnitch.cli", *subcommand])
    frequency = "HOURLY" if interval == "hourly" else "DAILY"
    args = ["/Create", "/TN", TASKS[kind], "/SC", frequency, "/TR", command, "/F"]
    if frequency == "DAILY":
        args.extend(["/ST", at])
    return _run(args)


def remove_schedule(kind: str) -> str:
    if kind not in TASKS:
        raise ValueError(f"Unsupported schedule: {kind}")
    return _run(["/Delete", "/TN", TASKS[kind], "/F"])


def schedule_status(kind: str) -> dict[str, object]:
    if kind not in TASKS:
        raise ValueError(f"Unsupported schedule: {kind}")
    try:
        output = _run(["/Query", "/TN", TASKS[kind], "/FO", "LIST"])
    except RuntimeError as exc:
        if "cannot find" in str(exc).casefold() or "does not exist" in str(exc).casefold():
            return {"enabled": False, "task": TASKS[kind]}
        raise
    return {"enabled": True, "task": TASKS[kind], "details": output}
