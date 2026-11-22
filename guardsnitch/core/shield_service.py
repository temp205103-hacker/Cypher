"""Background detection and user-mediated blocking for suspicious connections."""

from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import psutil

from guardsnitch.config import appdata_dir
from guardsnitch.core.shield import (
    ALLOWED_PROCESSES_PATH,
    SUSPICIOUS_PORTS,
    shield_pid_path,
    shield_state_path,
)
from guardsnitch.ip.rotate import IpRotationError, rotate as rotate_public_ip
from guardsnitch.vpn.manager import VpnError


POLL_SECONDS = 3
PROMPT_TIMEOUT_MS = 30_000
SHELL_PROCESSES = {
    "bash",
    "bash.exe",
    "cmd.exe",
    "cscript.exe",
    "nc",
    "nc.exe",
    "ncat.exe",
    "node.exe",
    "powershell.exe",
    "pwsh.exe",
    "python.exe",
    "pythonw.exe",
    "socat.exe",
    "sh",
    "sh.exe",
    "wscript.exe",
}
SUSPICIOUS_COMMAND_TOKENS = (
    "-encodedcommand",
    "downloadstring",
    "frombase64string",
    "invoke-expression",
    "new-object net.sockets.tcpclient",
    "/dev/tcp/",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_allowlist() -> set[str]:
    if not ALLOWED_PROCESSES_PATH.exists():
        return set()
    try:
        data = json.loads(ALLOWED_PROCESSES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read the shield allowlist: {exc}") from exc
    if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
        raise RuntimeError("The shield allowlist has an invalid format.")
    return {item.strip().casefold() for item in data}


def write_state(state: dict[str, object]) -> None:
    path = shield_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temporary.replace(path)


def append_event(event: dict[str, object]) -> None:
    path = appdata_dir() / "shield-events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")


def connection_key(executable: str, remote_ip: str, remote_port: int) -> str:
    return f"{executable.casefold()}|{remote_ip}|{remote_port}"


def detection_reasons(
    name: str,
    command_line: list[str] | None,
    remote_port: int,
) -> list[str]:
    reasons: list[str] = []
    if remote_port in SUSPICIOUS_PORTS:
        reasons.append(f"known suspicious remote port {remote_port}")
    normalized_name = Path(name).name.casefold()
    normalized_command = " ".join(command_line or ()).casefold()
    has_suspicious_command = any(
        token in normalized_command for token in SUSPICIOUS_COMMAND_TOKENS
    )
    if normalized_name in SHELL_PROCESSES and (
        remote_port in SUSPICIOUS_PORTS or has_suspicious_command
    ):
        reasons.append(f"shell-capable process {normalized_name} has an established connection")
    reasons.extend(
        f"suspicious command-line indicator {token}"
        for token in SUSPICIOUS_COMMAND_TOKENS
        if token in normalized_command
    )
    return reasons


def _message_box_timeout(message: str, title: str, flags: int, timeout: int) -> int:
    prompt = ctypes.windll.user32.MessageBoxTimeoutW
    prompt.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint,
        ctypes.c_ushort,
        ctypes.c_uint,
    ]
    prompt.restype = ctypes.c_int
    return prompt(None, message, title, flags, 0, timeout)


def ask_user(finding: dict[str, object]) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "prompt-unavailable"
    message = (
        "GuardSnitch detected a suspicious established connection.\n\n"
        f"Application: {finding.get('name') or 'unknown'}\n"
        f"Remote endpoint: {finding['remote_ip']}:{finding['remote_port']}\n"
        f"Reason: {', '.join(finding['reasons'])}\n\n"
        "Allow this connection? GuardSnitch attempts a temporary outbound firewall rule for "
        "this endpoint while the prompt is open. Choose No or wait 30 seconds to keep it blocked, terminate "
        "the application, and attempt real OpenVPN rotation if available.\n"
        "The connection is already established; some data may have passed before detection."
    )
    try:
        answer = _message_box_timeout(
            message,
            "GuardSnitch.ai connection alert",
            0x00000004 | 0x00000030 | 0x00040000,
            PROMPT_TIMEOUT_MS,
        )
    except (AttributeError, OSError):
        return False, "prompt-unavailable"
    if answer == 6:
        return True, "allowed"
    if answer == 32000:
        return False, "timed-out"
    return False, "denied"


def remove_firewall_rule(rule_name: str) -> dict[str, object]:
    try:
        result = subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={rule_name}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"removed": False, "error": str(exc)}
    if result.returncode == 0:
        return {"removed": True}
    return {
        "removed": False,
        "error": result.stderr.strip() or result.stdout.strip() or f"netsh returned {result.returncode}",
    }


def block_remote_connection(
    remote_ip: str,
    remote_port: int,
    executable: str | None,
) -> dict[str, object]:
    try:
        address = str(ipaddress.ip_address(remote_ip))
    except ValueError as exc:
        return {"blocked": False, "error": f"Invalid remote IP address: {exc}"}
    if address in {"127.0.0.1", "::1"}:
        return {"blocked": False, "error": "Refusing to block a loopback address."}
    if not 1 <= remote_port <= 65535:
        return {"blocked": False, "error": "Invalid remote port."}
    if not executable:
        return {"blocked": False, "error": "Process executable path is unavailable."}

    identity = f"{str(Path(executable)).casefold()}|{address}|{remote_port}"
    suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    rule_name = f"GuardSnitch denied connection {suffix}"
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        "protocol=TCP",
        f"remoteip={address}",
        f"remoteport={remote_port}",
        f'program="{executable}"',
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"blocked": False, "error": str(exc), "rule": rule_name}
    if result.returncode == 0:
        return {"blocked": True, "rule": rule_name}

    detail = result.stderr.strip() or result.stdout.strip()
    try:
        existing = subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "show",
                "rule",
                f"name={rule_name}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "blocked": False,
            "error": f"{detail or result.returncode}; checking an existing rule failed: {exc}",
            "rule": rule_name,
        }
    if existing.returncode == 0 and rule_name.casefold() in existing.stdout.casefold():
        return {"blocked": True, "rule": rule_name}
    return {
        "blocked": False,
        "error": detail or f"netsh returned {result.returncode}",
        "rule": rule_name,
    }


def _terminate_process(process: psutil.Process) -> dict[str, object]:
    try:
        process.terminate()
        process.wait(timeout=5)
        return {"terminated": True, "error": None}
    except psutil.NoSuchProcess:
        return {"terminated": True, "error": None}
    except psutil.AccessDenied as exc:
        return {"terminated": False, "error": str(exc)}
    except psutil.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=5)
            return {"terminated": True, "error": None}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as exc:
            return {"terminated": False, "error": str(exc)}


def _rotate_ip() -> dict[str, object]:
    try:
        result = rotate_public_ip()
    except (IpRotationError, VpnError, OSError) as exc:
        return {"rotated": False, "error": str(exc)}
    return {
        "rotated": bool(result["changed"]),
        "profile": Path(str(result["to_profile"])).name,
    }


def scan_once(
    last_actions: dict[str, float],
    allowlist: set[str],
    approved: set[str],
    prompt: Callable[[dict[str, object]], tuple[bool, str]] = ask_user,
    block: Callable[[str, int, str | None], dict[str, object]] = block_remote_connection,
    unblock: Callable[[str], dict[str, object]] = remove_firewall_rule,
    rotate_ip: Callable[[], dict[str, object]] = _rotate_ip,
) -> dict[str, object]:
    denied = 0
    findings: list[dict[str, object]] = []
    now = time.monotonic()

    for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            name = str(process.info.get("name") or "").strip()
            if name.casefold() in allowlist:
                continue
            executable = process.info.get("exe")
            for connection in process.net_connections(kind="inet"):
                if connection.status != psutil.CONN_ESTABLISHED:
                    continue
                remote_ip = getattr(connection.raddr, "ip", None)
                remote_port = getattr(connection.raddr, "port", None)
                if not remote_ip or not remote_port:
                    continue
                reasons = detection_reasons(
                    name,
                    process.info.get("cmdline"),
                    remote_port,
                )
                if not reasons:
                    continue

                exe_label = str(executable or name or process.pid)
                key = connection_key(exe_label, remote_ip, remote_port)
                if key in approved or now - last_actions.get(key, -300) < 300:
                    continue

                finding: dict[str, object] = {
                    "timestamp": utc_now(),
                    "pid": process.pid,
                    "name": name or "unknown",
                    "executable": executable,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "reasons": reasons,
                }
                block_result = block(remote_ip, remote_port, executable)
                finding["temporary_firewall"] = block_result
                allowed, decision = prompt(finding)
                finding["decision"] = decision

                if allowed:
                    if block_result.get("blocked") and block_result.get("rule"):
                        removal = unblock(str(block_result["rule"]))
                        finding["firewall_removal"] = removal
                        if not removal.get("removed"):
                            finding["action"] = "allow-requested-but-firewall-rule-remains"
                            last_actions[key] = now
                            append_event(finding)
                            findings.append(finding)
                            show_result(finding)
                            continue
                    last_actions[key] = now
                    approved.add(key)
                    finding["action"] = "allowed for this endpoint during this session"
                    append_event(finding)
                    findings.append(finding)
                    continue

                terminate_result = _terminate_process(process)
                rotation_result = rotate_ip()
                last_actions[key] = now if (
                    block_result.get("blocked") or terminate_result.get("terminated")
                ) else now - 285
                finding["action"] = "denied"
                finding["firewall"] = block_result
                finding["process"] = terminate_result
                finding["ip_rotation"] = rotation_result
                denied += 1
                append_event(finding)
                findings.append(finding)
                show_result(finding)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {"denied": denied, "findings": findings}


def show_result(finding: dict[str, object]) -> None:
    firewall = finding.get("firewall", finding.get("temporary_firewall", {}))
    firewall_removal = finding.get("firewall_removal", {})
    process = finding.get("process", {})
    rotation = finding.get("ip_rotation", {})
    lines = [
        str(finding.get("action", "GuardSnitch processed a suspicious connection.")),
        f"Firewall rule: {'created' if firewall.get('blocked') else firewall.get('error', 'not created')}",
        f"Firewall removal: {'removed' if firewall_removal.get('removed') else firewall_removal.get('error', 'not requested')}",
        f"Process stopped: {'yes' if process.get('terminated') else process.get('error', 'no')}",
        f"Public IP rotation: {'changed' if rotation.get('rotated') else rotation.get('error', 'unchanged')}",
    ]
    try:
        _message_box_timeout(
            "\n".join(lines),
            "GuardSnitch.ai protection result",
            0x00000040 | 0x00040000,
            15_000,
        )
    except (AttributeError, OSError):
        pass


def main() -> None:
    if os.name != "nt":
        raise OSError("The live reverse-shell shield is supported only on Windows.")
    state: dict[str, object] = {
        "running": True,
        "started_at": utc_now(),
        "blocked_count": 0,
        "last_scan": None,
        "last_error": None,
    }
    write_state(state)
    pid_path = shield_pid_path()
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(os.getpid()), encoding="utf-8")
    last_actions: dict[str, float] = {}
    approved: set[str] = set()

    while True:
        try:
            allowlist = load_allowlist()
            result = scan_once(last_actions, allowlist, approved)
            state["blocked_count"] = int(state["blocked_count"]) + int(result["denied"])
            state["last_error"] = None
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            state["last_error"] = str(exc)
        state["last_scan"] = utc_now()
        write_state(state)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
