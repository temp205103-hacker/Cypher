import base64
import hashlib
import asyncio
from io import StringIO

from fastapi import HTTPException
import pytest
from starlette.requests import Request
from starlette.responses import Response
from rich.console import Console
from typer.testing import CliRunner

from cypher import cli
from cypher.config import CypherConfig
from cypher.core import theft
from cypher.core import shield_service
from cypher.web import app as dashboard


def test_online_flag_launches_dashboard_without_interactive_setup(monkeypatch) -> None:
    launches = []
    monkeypatch.setattr(cli, "_launch_dashboard", lambda port, no_browser: launches.append((port, no_browser)))
    monkeypatch.setattr(cli, "_ensure_initial_setup", lambda: False)

    result = CliRunner().invoke(cli.app, ["--online", "--no-browser"])

    assert result.exit_code == 0
    assert launches == [(8787, True)]


def test_health_endpoint_exposes_dashboard_api_version() -> None:
    assert dashboard.health()["name"] == "Cypher"
    assert dashboard.health()["api_version"] >= 3


def test_phish_dashboard_api_checks_and_saves_local_feedback(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))

    result = dashboard.phish_check(
        dashboard.PhishCheckRequest(url="https://paypa1-login.invalid/verify")
    )
    assert result["verdict"] == "Suspicious"
    assert result["network_contacted"] is False

    saved = dashboard.phish_feedback(
        dashboard.PhishFeedbackRequest(
            domain="paypa1-login.invalid",
            outcome="false-positive",
        )
    )
    assert saved["outcome"] == "false-positive"
    assert dashboard.phish_history()[-1]["domain"] == "paypa1-login.invalid"


def test_extension_bridge_requires_the_local_token(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    token = dashboard.phish_extension_token()["token"]

    def request_with_token(supplied_token: str) -> Request:
        headers = [
            (b"host", b"127.0.0.1:8787"),
            (b"origin", b"chrome-extension://test-extension"),
            (b"x-cypher-token", supplied_token.encode("utf-8")),
        ]
        return Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/api/phish/blocked-domains",
                "headers": headers,
                "query_string": b"",
                "scheme": "http",
                "server": ("127.0.0.1", 8787),
                "client": ("127.0.0.1", 12345),
                "http_version": "1.1",
            }
        )

    async def call_next(_request: Request) -> Response:
        return Response("ok")

    denied = asyncio.run(
        dashboard.restrict_to_local_browser(request_with_token("incorrect-token"), call_next)
    )
    allowed = asyncio.run(
        dashboard.restrict_to_local_browser(request_with_token(token), call_next)
    )

    assert denied.status_code == 403
    assert allowed.status_code == 200


def test_extension_incident_submission_requires_token(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    token = dashboard.phish_extension_token()["token"]

    def request_with_token(supplied_token: str) -> Request:
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/phish/incident",
                "headers": [
                    (b"host", b"127.0.0.1:8787"),
                    (b"origin", b"chrome-extension://test-extension"),
                    (b"x-cypher-token", supplied_token.encode("utf-8")),
                ],
                "query_string": b"",
                "scheme": "http",
                "server": ("127.0.0.1", 8787),
                "client": ("127.0.0.1", 12345),
                "http_version": "1.1",
            }
        )

    async def call_next(_request: Request) -> Response:
        return Response("ok")

    denied = asyncio.run(
        dashboard.restrict_to_local_browser(
            request_with_token("incorrect-token"), call_next
        )
    )
    allowed = asyncio.run(
        dashboard.restrict_to_local_browser(request_with_token(token), call_next)
    )

    assert denied.status_code == 403
    assert allowed.status_code == 200


def test_dashboard_can_record_and_open_manual_incident_response(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))

    report = dashboard.phish_create_incident(
        dashboard.PhishIncidentRequest(
            domain="example.invalid",
            verdict="Suspicious",
            risk_score=45,
            evidence=[{"evidence": "User reported a click."}],
            trigger="user-panic-button",
        )
    )
    response = dashboard.phish_run_manual_response(report["id"])

    assert response["response_started"] is True
    assert response["network_changed"] is False
    assert dashboard.phish_incidents()[0]["id"] == report["id"]


def test_cli_detects_outdated_dashboard_process(monkeypatch) -> None:
    from io import BytesIO

    import cypher.cli as cli

    monkeypatch.setattr(
        cli,
        "urlopen",
        lambda *_args, **_kwargs: BytesIO(
            b'{"name":"Cypher","scope":"localhost"}'
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
    monkeypatch.setattr(theft, "get_secret", lambda _name: stored)

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
    assert CypherConfig.load().name == "Test User"


def test_dashboard_imports_cloudconnexa_profile(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.delenv("CYPHER_VPN_PROVIDER", raising=False)
    content = "client\nremote vpn.example.com 1194\n"

    result = dashboard._perform_action(
        dashboard.ActionRequest(
            action="vpn.import-profile",
            vpn_profile_name="cloudconnexa.ovpn",
            vpn_profile_content=content,
        )
    )

    profile_path = tmp_path / "Cypher" / "openvpn_profiles" / "cloudconnexa.ovpn"
    assert result["profile"] == "cloudconnexa.ovpn"
    assert profile_path.read_text(encoding="utf-8") == content
    assert {"name": "cloudconnexa", "code": "cloudconnexa"} in dashboard._vpn_dashboard_state()["available"]


def test_dashboard_rejects_invalid_or_duplicate_vpn_profiles(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.delenv("CYPHER_VPN_PROVIDER", raising=False)

    with pytest.raises(ValueError, match="valid .ovpn"):
        dashboard._perform_action(
            dashboard.ActionRequest(
                action="vpn.import-profile",
                vpn_profile_name="../escape.ovpn",
                vpn_profile_content="client\nremote vpn.example.com\n",
            )
        )
    with pytest.raises(ValueError, match="client and remote"):
        dashboard._perform_action(
            dashboard.ActionRequest(
                action="vpn.import-profile",
                vpn_profile_name="invalid.ovpn",
                vpn_profile_content="client\n",
            )
        )

    profile = dashboard.ActionRequest(
        action="vpn.import-profile",
        vpn_profile_name="duplicate.ovpn",
        vpn_profile_content="client\nremote vpn.example.com\n",
    )
    dashboard._perform_action(profile)
    with pytest.raises(ValueError, match="already exists"):
        dashboard._perform_action(profile)


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
