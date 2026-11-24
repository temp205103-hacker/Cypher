import json
import re

import pytest
from typer.testing import CliRunner

from cypher.cli import app
from cypher.phish import incident


def test_incident_is_local_bounded_to_domain_and_retrievable(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(incident, "appdata_dir", lambda: tmp_path)
    with pytest.raises(ValueError, match="domain only"):
        incident.create_incident(
            domain="https://paypa1-login.invalid/account?token=private",
            verdict="Suspicious",
            risk_score=56,
        )

    report = incident.create_incident(
        domain="paypa1-login.invalid",
        verdict="Suspicious",
        risk_score=56,
        evidence=["Brand lookalike"],
        trigger="extension-click",
    )

    stored = (tmp_path / "phish" / "incidents.json").read_text(encoding="utf-8")
    assert report["domain"] == "paypa1-login.invalid"
    assert report["id"] == incident.get_incident(report["id"])["id"]
    assert report in incident.list_incidents()
    assert "private" not in stored
    assert json.loads(stored)[0]["network_changed"] is False


def test_manual_response_records_checklist_without_network_action(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(incident, "appdata_dir", lambda: tmp_path)
    report = incident.create_incident("example.invalid", "Phishing", 80)

    updated = incident.run_manual_response(report["id"])

    assert updated["response_started"] is True
    assert updated["network_changed"] is False
    assert updated["actions_pending"]
    assert updated["timeline"][-1]["event"] == "User opened the manual response checklist."


def test_simulation_incident_cannot_run_response(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(incident, "appdata_dir", lambda: tmp_path)
    report = incident.create_incident(
        "example.invalid", "Phishing", 100, simulation=True
    )

    with pytest.raises(ValueError, match="simulation"):
        incident.run_manual_response(report["id"])


def test_incident_can_record_an_ip_host(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(incident, "appdata_dir", lambda: tmp_path)

    report = incident.create_incident(
        "192.0.2.10", "Suspicious", 55, trigger="extension-click"
    )

    assert report["domain"] == "192.0.2.10"


def test_cli_safe_phish_test_creates_a_viewable_simulation(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))

    simulation = CliRunner().invoke(app, ["phish", "test"])

    assert simulation.exit_code == 0
    output = " ".join(simulation.output.split())
    assert "incident " in output
    assert "VPN change" in output
    incident_id = re.search(r"incident ([0-9a-f]{12})", simulation.output).group(1)
    report = CliRunner().invoke(
        app, ["phish", "incident", incident_id, "--format", "json"]
    )

    assert report.exit_code == 0
    assert json.loads(report.output)["simulation"] is True
