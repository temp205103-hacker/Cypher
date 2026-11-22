import json
from types import SimpleNamespace

import pytest

from guardsnitch.core import shield
from guardsnitch.core import shield_service


def test_shield_allowlist_is_persisted(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    allowlist_path = tmp_path / "GuardSnitch" / "shield_allowlist.json"
    monkeypatch.setattr(shield, "ALLOWED_PROCESSES_PATH", allowlist_path)

    result = shield.set_process_allowed("PowerShell.EXE")

    assert result["allowed_processes"] == ["powershell.exe"]
    assert json.loads(allowlist_path.read_text(encoding="utf-8")) == ["powershell.exe"]


def test_shield_status_ignores_reused_pid(monkeypatch, tmp_path) -> None:
    pid_path = tmp_path / "reverse-shell-shield.pid"
    pid_path.write_text("123", encoding="utf-8")
    monkeypatch.setattr(shield, "shield_pid_path", lambda: pid_path)
    monkeypatch.setattr(shield, "shield_state_path", lambda: tmp_path / "state.json")
    monkeypatch.setattr(
        shield.psutil,
        "Process",
        lambda _pid: SimpleNamespace(cmdline=lambda: ["python.exe", "unrelated.py"]),
    )

    assert shield.read_shield_status()["running"] is False


def test_stop_shield_refuses_to_terminate_reused_pid(monkeypatch, tmp_path) -> None:
    pid_path = tmp_path / "reverse-shell-shield.pid"
    pid_path.write_text("123", encoding="utf-8")
    process = SimpleNamespace(
        cmdline=lambda: ["python.exe", "unrelated.py"],
        terminate=lambda: pytest.fail("unrelated process must not be terminated"),
    )
    monkeypatch.setattr(shield, "shield_pid_path", lambda: pid_path)
    monkeypatch.setattr(shield, "shield_state_path", lambda: tmp_path / "state.json")
    monkeypatch.setattr(shield.psutil, "Process", lambda _pid: process)

    with pytest.raises(RuntimeError, match="refusing to stop"):
        shield.stop_shield()

    assert pid_path.exists()


def test_shell_process_connection_is_flagged() -> None:
    reasons = shield_service.detection_reasons(
        "powershell.exe",
        ["powershell.exe", "-EncodedCommand", "example"],
        443,
    )

    assert any("shell-capable process" in reason for reason in reasons)
    assert any("-encodedcommand" in reason for reason in reasons)


def test_ordinary_shell_https_connection_is_not_flagged() -> None:
    assert shield_service.detection_reasons(
        "python.exe",
        ["python.exe", "download_report.py"],
        443,
    ) == []


def test_denied_connection_is_blocked_terminated_and_rotated(monkeypatch) -> None:
    connection = SimpleNamespace(
        status=shield_service.psutil.CONN_ESTABLISHED,
        raddr=SimpleNamespace(ip="203.0.113.8", port=443),
    )

    class Process:
        pid = 123
        info = {
            "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": ["powershell.exe", "-EncodedCommand", "test"],
        }

        def net_connections(self, kind):
            return [connection]

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            return 0

        def kill(self):
            self.terminated = True

    process = Process()
    monkeypatch.setattr(shield_service.psutil, "process_iter", lambda _attrs: [process])
    monkeypatch.setattr(shield_service, "append_event", lambda _event: None)
    monkeypatch.setattr(shield_service, "show_result", lambda _finding: None)
    blocked = []
    rotated = []

    def deny_after_timeout(_finding):
        assert blocked == [("203.0.113.8", 443)]
        return False, "timed-out"

    result = shield_service.scan_once(
        {},
        set(),
        set(),
        prompt=deny_after_timeout,
        block=lambda ip, port, _exe: blocked.append((ip, port)) or {"blocked": True},
        rotate_ip=lambda: rotated.append(True) or {"rotated": True},
    )

    assert result["denied"] == 1
    assert blocked == [("203.0.113.8", 443)]
    assert rotated == [True]
    assert process.terminated is True
    assert result["findings"][0]["decision"] == "timed-out"


def test_allowed_connection_is_not_reprompted(monkeypatch) -> None:
    connection = SimpleNamespace(
        status=shield_service.psutil.CONN_ESTABLISHED,
        raddr=SimpleNamespace(ip="203.0.113.8", port=443),
    )

    class Process:
        pid = 123
        info = {
            "name": "pwsh.exe",
            "exe": r"C:\pwsh.exe",
            "cmdline": ["pwsh.exe", "-EncodedCommand", "test"],
        }

        def net_connections(self, kind):
            return [connection]

    monkeypatch.setattr(shield_service.psutil, "process_iter", lambda _attrs: [Process()])
    monkeypatch.setattr(shield_service, "append_event", lambda _event: None)
    monkeypatch.setattr(shield_service, "show_result", lambda _finding: None)
    prompts = []
    approved = set()
    removed = []

    def prompt(_finding):
        prompts.append(True)
        return True, "allowed"

    shield_service.scan_once(
        {}, set(), approved, prompt=prompt,
        block=lambda _ip, _port, _exe: {"blocked": True, "rule": "test-rule"},
        unblock=lambda rule: removed.append(rule) or {"removed": True},
    )
    shield_service.scan_once(
        {}, set(), approved, prompt=prompt,
        block=lambda _ip, _port, _exe: {"blocked": False},
    )

    assert len(prompts) == 1
    assert removed == ["test-rule"]
