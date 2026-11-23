import base64
import hashlib
from io import StringIO

from fastapi import HTTPException
from rich.console import Console
from typer.testing import CliRunner

from guardsnitch import cli
from guardsnitch.config import GuardConfig
from guardsnitch.core import theft
from guardsnitch.core import shield_service
from guardsnitch.web import app as dashboard


def test_online_flag_launches_dashboard_without_interactive_setup(monkeypatch) -> None:
    launches = []
    monkeypatch.setattr(cli, "_launch_dashboard", lambda port, no_browser: launches.append((port, no_browser)))
    monkeypatch.setattr(cli, "_ensure_initial_setup", lambda: False)

    result = CliRunner().invoke(cli.app, ["--online", "--no-browser"])

    assert result.exit_code == 0
    assert launches == [(8787, True)]


def test_health_endpoint_exposes_dashboard_api_version() -> None:
    assert dashboard.health()["api_version"] >= 2


def test_cli_detects_outdated_dashboard_process(monkeypatch) -> None:
    from io import BytesIO

    import guardsnitch.cli as cli

    monkeypatch.setattr(
        cli,
        "urlopen",
        lambda *_args, **_kwargs: BytesIO(
            b'{"name":"GuardSnitch.ai","scope":"localhost"}'
        ),
    )

    assert cli._dashboard_status("http://127.0.0.1:8787") == "outdated"


def test_dashboard_action_returns_and_stores_completed_report(monkeypatch) -> None:
    dashboard._REPORTS.clear()
    monkeypatch.setattr(
        dashboard.malware_core,
        "scan_file",
        lambda path: {"path": path, "status": "clean", "engines": ["YARA"], "findings": [], "warnings": []},
    )
    monkeypatch.setattr(dashboard.quarantine_core, "queue_findings", lambda result: [])

    report = dashboard.run_action(
        dashboard.ActionRequest(action="malware.scan", path="sample.txt")
    )

    assert report["status"] == "completed"
    assert report["result"]["scan"]["status"] == "clean"
    assert dashboard.reports()[0]["id"] == report["id"]


def test_dashboard_destructive_action_requires_confirmation(monkeypatch) -> None:
    dashboard._REPORTS.clear()
    monkeypatch.setattr(
        dashboard.quarantine_core,
        "quarantine_finding",
        lambda _item_id: (_ for _ in ()).throw(AssertionError("must not move file")),
    )

    try:
        dashboard.run_action(
            dashboard.ActionRequest(action="quarantine.isolate", item_id="finding-1")
        )
    except HTTPException as error:
        assert error.status_code == 400
        assert error.detail["report"]["status"] == "failed"
        assert "Confirm" in error.detail["message"]
    else:
        raise AssertionError("an unconfirmed destructive action should fail")


def test_disarm_accepts_a_pin_and_refuses_an_incorrect_pin(monkeypatch, tmp_path) -> None:
    salt = b"s" * 16
    expected = hashlib.pbkdf2_hmac("sha256", b"correct-pin", salt, 200_000)
    stored = base64.urlsafe_b64encode(salt + expected).decode("ascii")
    monkeypatch.setattr(theft.keyring, "get_password", lambda *_args: stored)

    service = theft.TheftProtection(console=Console(file=StringIO()))
    service.state_path = tmp_path / "theft-state.json"
    service._write_state(True)

    assert service.disarm("wrong-pin") is False
    assert service.is_armed()
    assert service.disarm("correct-pin") is True
    assert not service.is_armed()


def test_dashboard_profile_save_stores_hashed_pin(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    stored = {}
    monkeypatch.setattr(dashboard.keyring, "get_password", lambda _service, key: stored.get(key))
    monkeypatch.setattr(dashboard.keyring, "set_password", lambda _service, key, value: stored.__setitem__(key, value))

    result = dashboard._perform_action(
        dashboard.ActionRequest(
            action="profile.save",
            name="Test User",
            alert_email="test@example.com",
            ai_mode="offline",
            pin="test-pin",
        )
    )

    assert result["configured"] is True
    assert result["email_delivery"] is False
    assert stored["disarm-pin"] != "test-pin"
    assert GuardConfig.load().name == "Test User"


def test_firewall_ip_block_normalizes_address_and_creates_scoped_rule(monkeypatch) -> None:
    commands = []
    monkeypatch.setattr(shield_service.os, "name", "nt")
    monkeypatch.setattr(
        shield_service.subprocess,
        "run",
        lambda command, **_kwargs: commands.append(command)
        or shield_service.subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )

    result = shield_service.block_remote_ip("203.0.113.8")

    assert result["blocked"] is True
    assert "remoteip=203.0.113.8" in commands[0]
    assert "action=block" in commands[0]


def test_firewall_ip_block_refuses_loopback(monkeypatch) -> None:
    monkeypatch.setattr(
        shield_service.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not change firewall")),
    )

    result = shield_service.block_remote_ip("127.0.0.1")

    assert result["blocked"] is False
    assert "loopback" in result["error"]
