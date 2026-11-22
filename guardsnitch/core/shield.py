"""Reverse-shell shield orchestration."""

from __future__ import annotations

import json
import os
import psutil
import subprocess
from pathlib import Path

from guardsnitch.config import appdata_dir


SUSPICIOUS_PORTS = {4444, 1337, 9001, 31337}

ALLOWED_PROCESSES_PATH = appdata_dir() / "shield_allowlist.json"


def shield_state_path() -> Path:
    return appdata_dir() / "reverse-shell-shield.json"


def shield_pid_path() -> Path:
    return appdata_dir() / "reverse-shell-shield.pid"


def install_startup() -> str:
    if os.name != "nt":
        raise OSError("Automatic startup registration is supported only on Windows.")
    import sys
    import winreg

    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.is_file():
        raise OSError(f"pythonw.exe was not found next to {sys.executable}.")
    command = subprocess.list2cmdline(
        [str(pythonw), "-m", "guardsnitch.core.shield_service"]
    )
    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, run_key) as key:
        winreg.SetValueEx(key, "GuardSnitchReverseShellShield", 0, winreg.REG_SZ, command)
    return command


def remove_startup() -> bool:
    if os.name != "nt":
        raise OSError("Automatic startup registration is supported only on Windows.")
    import winreg

    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, "GuardSnitchReverseShellShield")
    except FileNotFoundError:
        return False
    return True


def startup_status() -> str | None:
    if os.name != "nt":
        raise OSError("Automatic startup registration is supported only on Windows.")
    import winreg

    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key) as key:
            value, _ = winreg.QueryValueEx(key, "GuardSnitchReverseShellShield")
    except FileNotFoundError:
        return None
    return str(value)


def read_shield_status() -> dict[str, object]:
    state_path = shield_state_path()
    pid_path = shield_pid_path()
    pid = None
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Could not read the shield process ID: {exc}") from exc
    running = pid is not None
    if running:
        try:
            process = psutil.Process(pid)
            running = "guardsnitch.core.shield_service" in " ".join(process.cmdline())
        except psutil.NoSuchProcess:
            running = False
        except psutil.AccessDenied as exc:
            raise RuntimeError(f"Could not inspect shield process {pid}: {exc}") from exc

    state: dict[str, object] = {
        "running": running,
        "pid": pid if running else None,
    }
    if state_path.exists():
        try:
            saved_state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Could not read shield state: {exc}") from exc
        if not isinstance(saved_state, dict):
            raise RuntimeError("Shield state has an invalid format.")
        state.update(saved_state)
    state["running"] = running
    return state


def start_shield() -> dict[str, object]:
    status = read_shield_status()
    if status["running"]:
        return status

    import sys

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if hasattr(subprocess, "DETACHED_PROCESS"):
        creationflags |= subprocess.DETACHED_PROCESS
    process = subprocess.Popen(
        [sys.executable, "-m", "guardsnitch.core.shield_service"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
        close_fds=True,
    )
    pid_path = shield_pid_path()
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(process.pid), encoding="utf-8")
    return read_shield_status()


def stop_shield() -> dict[str, object]:
    pid_path = shield_pid_path()
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Could not read the shield process ID: {exc}") from exc
        try:
            process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            process = None
        except psutil.AccessDenied as exc:
            raise RuntimeError(f"Could not inspect shield process {pid}: {exc}") from exc
        if process is not None:
            try:
                command_line = " ".join(process.cmdline())
            except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                raise RuntimeError(f"Could not verify shield process {pid}: {exc}") from exc
            if "guardsnitch.core.shield_service" not in command_line:
                raise RuntimeError(
                    f"PID {pid} is not the GuardSnitch shield; refusing to stop it."
                )
            try:
                process.terminate()
                process.wait(timeout=10)
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied as exc:
                raise RuntimeError(f"Could not stop the shield: {exc}") from exc
            except psutil.TimeoutExpired as exc:
                raise RuntimeError("The shield did not stop in time.") from exc
        try:
            pid_path.unlink()
        except OSError as exc:
            raise RuntimeError(f"Could not remove the shield process ID: {exc}") from exc
    return read_shield_status()


def set_process_allowed(process_name: str, allowed: bool = True) -> dict[str, object]:
    names: set[str] = set()
    if ALLOWED_PROCESSES_PATH.exists():
        try:
            names = set(json.loads(ALLOWED_PROCESSES_PATH.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            names = set()
    normalized = process_name.strip().casefold()
    if allowed:
        names.add(normalized)
    else:
        names.discard(normalized)
    ALLOWED_PROCESSES_PATH.parent.mkdir(parents=True, exist_ok=True)
    ALLOWED_PROCESSES_PATH.write_text(json.dumps(sorted(names), indent=2), encoding="utf-8")
    return {"allowed_processes": sorted(names)}


def find_suspicious_connections() -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            connections = process.net_connections(kind="inet")
            if not connections:
                continue
            for connection in connections:
                if connection.status != psutil.CONN_ESTABLISHED:
                    continue
                remote_port = getattr(connection.raddr, "port", None)
                remote_ip = getattr(connection.raddr, "ip", None)
                if remote_port in SUSPICIOUS_PORTS:
                    findings.append({
                        "pid": process.pid,
                        "name": process.info.get("name"),
                        "exe": process.info.get("exe"),
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings
