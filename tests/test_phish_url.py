import json

from typer.testing import CliRunner

from cypher import cli
from cypher.phish.analyzer import analyze_url


def test_trusted_domains_are_not_flagged() -> None:
    for url in (
        "https://example.com/",
        "https://mail.google.com/",
        "https://paypal.com/login",
    ):
        result = analyze_url(url)
        assert result["verdict"] == "Safe"
        assert result["risk_score"] == 0


def test_local_demo_blocklist_has_phishing_verdict_without_network() -> None:
    result = analyze_url("https://phishing-demo.invalid/login")

    assert result["verdict"] == "Phishing"
    assert result["risk_score"] == 100
    assert result["network_contacted"] is False
    assert result["source"] == "local-blocklist"


def test_check_command_has_json_help_and_local_only_output(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    runner = CliRunner()
    help_result = runner.invoke(cli.app, ["phish", "check", "--help"])
    assert help_result.exit_code == 0
    assert "--format" in help_result.stdout
    assert "--verbose" in help_result.stdout
    assert "--offline" in help_result.stdout

    result = runner.invoke(
        cli.app,
        ["phish", "check", "https://example.com", "--format", "json", "--offline"],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["verdict"] == "Safe"
    assert data["network_contacted"] is False
    assert data["mode"] == "offline"
