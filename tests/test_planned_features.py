import json
from pathlib import Path
import subprocess

import pytest
from fastapi import HTTPException
from typer.testing import CliRunner

from guardsnitch.cli import app
from guardsnitch.config import GuardConfig
from guardsnitch.core import safe_run, safe_zones, scanner, scheduling
from guardsnitch.web import app as dashboard


def test_source_scanner_finds_secrets_pii_and_risky_code(tmp_path: Path) -> None:
    source = tmp_path / "sample.py"
    source.write_text(
        'email = "person@example.com"\n'
        'token = "AKIA1234567890ABCDEF"\n'
        "result = eval(user_input)\n",
        encoding="utf-8",
    )

    findings = scanner.scan_path(str(source))

    assert {item["category"] for item in findings} == {
        "email", "aws_access_key", "dynamic-eval",
    }
    assert all(item["id"] for item in findings)
    assert "person@example.com" not in findings[0]["snippet"]


def test_redaction_writes_a_separate_dashboard_output(tmp_path: Path) -> None:
    source = tmp_path / "note.txt"
    source.write_text("contact person@example.com", encoding="utf-8")
    dashboard._REPORTS.clear()

    report = dashboard.run_action(
        dashboard.ActionRequest(action="redact", path=str(source))
    )

    assert report["status"] == "completed"
    assert source.read_text(encoding="utf-8") == "contact person@example.com"
    assert Path(report["result"]["output"]).read_text(encoding="utf-8") == "contact [REDACTED_EMAIL]"


def test_safe_run_rejects_loopback_without_fetching(monkeypatch) -> None:
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: pytest.fail("must not resolve"))

    with pytest.raises(safe_run.SafeRunError, match="public"):
        safe_run.inspect_url("http://127.0.0.1/script.py")


def test_safe_run_scores_public_url_without_network_activity(monkeypatch) -> None:
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: pytest.fail("must not resolve"))
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: pytest.fail("must not connect"))

    result = safe_run.inspect_url("https://user:secret@bit.ly/login?token=private")

    assert result["status"] == "suspicious"
    assert result["network_contacted"] is False
    assert result["opened"] is False
    assert result["url"] == "https://bit.ly/"
    assert "secret" not in str(result)
    assert "private" not in str(result)


def test_safe_run_normalizes_unicode_host_for_punycode_detection() -> None:
    result = safe_run.inspect_url("https://раураl.example/")

    assert result["status"] == "unverified"
    assert any(item["id"] == "punycode-host" for item in result["findings"])


def test_schedule_validates_intervals_and_creates_expected_task(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(scheduling.os, "name", "nt")
    monkeypatch.setattr(scheduling.subprocess, "run", lambda args, **kwargs: (
        calls.append((args, kwargs))
        or scheduling.subprocess.CompletedProcess(args, 0, stdout="created", stderr="")
    ))

    assert scheduling.set_schedule("malware", "hourly") == "created"
    assert "HOURLY" in calls[0][0]
    with pytest.raises(ValueError, match="HH:MM"):
        scheduling.set_schedule("ip", "daily", "25:00")


def test_safe_zone_add_remove_and_dashboard_list(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))

    assert safe_zones.add_safe_zone("Home Wi-Fi") == ["Home Wi-Fi"]
    assert safe_zones.add_safe_zone("home wi-fi") == ["Home Wi-Fi"]
    report = dashboard.run_action(dashboard.ActionRequest(action="theft.safe-zones"))
    assert report["status"] == "completed"
    assert report["result"] == ["Home Wi-Fi"]
    assert safe_zones.remove_safe_zone("HOME WI-FI") == []


def test_dashboard_records_source_findings_and_enables_explanation(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    source = tmp_path / "sample.py"
    source.write_text('secret = "person@example.com"\n', encoding="utf-8")

    report = dashboard.run_action(
        dashboard.ActionRequest(action="scan", path=str(source))
    )
    finding_id = report["result"]["findings"][0]["id"]
    explanation = dashboard.run_action(
        dashboard.ActionRequest(action="explain", item_id=finding_id)
    )

    assert explanation["result"]["explanation"]
    assert json.loads((tmp_path / "GuardSnitch" / "scan-findings.json").read_text(encoding="utf-8"))


def test_dashboard_does_not_report_invalid_schedule_as_complete(monkeypatch) -> None:
    dashboard._REPORTS.clear()
    monkeypatch.setattr(
        scheduling, "set_schedule",
        lambda *_args: (_ for _ in ()).throw(ValueError("invalid interval")),
    )

    with pytest.raises(HTTPException) as error:
        dashboard.run_action(
            dashboard.ActionRequest(action="malware.schedule", interval="weekly")
        )
    assert error.value.detail["report"]["status"] == "failed"


def test_cli_source_scan_and_offline_question_work(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    GuardConfig(name="Test", alert_email="test@example.com").save()
    source = tmp_path / "source.py"
    source.write_text('email = "person@example.com"\n', encoding="utf-8")
    runner = CliRunner()

    scan_result = runner.invoke(app, ["scan", str(source), "--format", "json"])
    ask_result = runner.invoke(app, ["ask", "How do I protect a secret token?"])

    assert scan_result.exit_code == 0
    assert "email" in scan_result.stdout
    assert ask_result.exit_code == 0
    assert "rotate any exposed value" in ask_result.stdout


def test_staged_cli_scan_blocks_findings_in_pre_commit_hook(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    GuardConfig(name="Test", alert_email="test@example.com").save()
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    source = repo / "source.py"
    source.write_text('email = "person@example.com"\n', encoding="utf-8")
    subprocess.run(["git", "add", "source.py"], cwd=repo, check=True)
    monkeypatch.chdir(repo)

    result = CliRunner().invoke(app, ["scan", "--staged"])

    assert result.exit_code == 1
    assert "email" in result.stdout
