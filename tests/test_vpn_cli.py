from typer.testing import CliRunner

from cypher.cli import app
from cypher.config import CypherConfig


def test_top_level_vpn_flags_connect_mock(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("CYPHER_VPN_PROVIDER", "mock")

    result = CliRunner().invoke(app, ["-v", "-c", "Germany"])

    assert result.exit_code == 0
    assert "VPN SIMULATED (no network changes)" in result.stdout
    assert "Germany (DE)" in result.stdout


def test_vpn_option_off_disconnects_mock(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("CYPHER_VPN_PROVIDER", "mock")
    runner = CliRunner()

    connect_result = runner.invoke(app, ["-v", "-c", "Germany"])
    disconnect_result = runner.invoke(app, ["--vpn", "off"])

    assert connect_result.exit_code == 0
    assert disconnect_result.exit_code == 0
    assert "VPN disconnected" in disconnect_result.stdout


def test_verbose_is_long_only_for_scan(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    CypherConfig(name="Test User", alert_email="test@example.com").save()

    help_result = CliRunner().invoke(app, ["scan", "--help"])
    assert help_result.exit_code == 0
    assert "--verbose" in help_result.stdout
    assert " -v " not in help_result.stdout
