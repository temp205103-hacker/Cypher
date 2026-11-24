import json
from pathlib import Path
from typer.testing import CliRunner

from cypher.cli import app
from cypher.config import CypherConfig
from cypher.core import installguard, pii, quarantine, redact, scanner, secrets
from cypher.ip import history as ip_history_store
from cypher.ip.rotate import rotate


def test_installguard_lifecycle(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    CypherConfig(name="Test", alert_email="test@example.com").save()
    runner = CliRunner()

    res_on = runner.invoke(app, ["installguard", "on"])
    assert res_on.exit_code == 0
    assert "enabled" in res_on.stdout.lower()

    res_status = runner.invoke(app, ["installguard", "status"])
    assert res_status.exit_code == 0
    assert "ENABLED" in res_status.stdout

    res_allow = runner.invoke(app, ["installguard", "allow", "setup.exe"])
    assert res_allow.exit_code == 0
    assert "setup.exe" in res_allow.stdout

    res_wrap = runner.invoke(app, ["installguard", "safe-run", "pip", "requests"])
    assert res_wrap.exit_code == 0
    assert "verified" in res_wrap.stdout.lower()

    res_hist = runner.invoke(app, ["installguard", "history"])
    assert res_hist.exit_code == 0
    assert "pip" in res_hist.stdout

    res_off = runner.invoke(app, ["installguard", "off"])
    assert res_off.exit_code == 0
    assert "disabled" in res_off.stdout.lower()


def test_vpn_subcommands_lifecycle(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("CYPHER_VPN_PROVIDER", "mock")
    runner = CliRunner()

    # Create dummy ovpn file
    dummy_ovpn = tmp_path / "server1.ovpn"
    dummy_ovpn.write_text("client\ndev tun\n", encoding="utf-8")

    res_add = runner.invoke(app, ["vpn", "add-config", str(dummy_ovpn)])
    assert res_add.exit_code == 0
    assert "server1" in res_add.stdout

    res_kill = runner.invoke(app, ["vpn", "kill-switch", "on"])
    assert res_kill.exit_code == 0
    assert "kill-switch enabled" in res_kill.stdout.lower()

    res_kill_off = runner.invoke(app, ["vpn", "kill-switch", "off"])
    assert res_kill_off.exit_code == 0
    assert "kill-switch disabled" in res_kill_off.stdout.lower()

    res_auto = runner.invoke(app, ["vpn", "auto-start", "status"])
    assert res_auto.exit_code == 0

    res_panic = runner.invoke(app, ["vpn", "panic-reset"])
    assert res_panic.exit_code == 0
    assert "panic-reset completed" in res_panic.stdout.lower()


def test_daily_rotation_never_reuses_recent_server(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    profile_dir = tmp_path / "openvpn_profiles"
    profile_dir.mkdir(parents=True)
    p1 = profile_dir / "alpha.ovpn"
    p2 = profile_dir / "beta.ovpn"
    p3 = profile_dir / "gamma.ovpn"
    p1.write_text("client", encoding="utf-8")
    p2.write_text("client", encoding="utf-8")
    p3.write_text("client", encoding="utf-8")

    class DummyManager:
        def status(self):
            return {"provider": "openvpn", "connected": True, "profile": str(p1)}
        def connect(self, profile):
            return {"connected": True, "profile": profile}

    # Record beta as used yesterday
    ip_history_store.record_rotation({"to_profile": str(p2)})

    # Rotation should pick gamma (neither current alpha nor recent beta)
    result = rotate(
        dry_run=True,
        manager=DummyManager(),
        profile_dir=profile_dir,
    )
    assert Path(str(result["to_profile"])).name == "gamma.ovpn"


def test_extended_secrets_and_pii_scanner() -> None:
    content = (
        'token = "ghp_123456789012345678901234567890123456"\n'
        'db = "postgresql://user:secret123@db.example.com/mydb"\n'
        'password = "supersecretpassword"\n'
        'card = "4111111111111111"\n'
        'ssn = "123-45-6789"\n'
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        'bad_hash = hashlib.md5(data)\n'
    )
    findings = scanner.scan_text(content, "test.py")
    categories = {f["category"] for f in findings}
    assert "generic_token" in categories
    assert "database_url" in categories
    assert "password_assignment" in categories
    assert "credit_card" in categories
    assert "ssn" in categories
    assert "sql-injection" in categories
    assert "weak-crypto" in categories


def test_extended_redaction() -> None:
    raw = (
        'ghp_123456789012345678901234567890123456 '
        'password="supersecretpassword" '
        '4111111111111111 '
        '123-45-6789'
    )
    redacted = redact.redact_text(raw)
    assert "ghp_" not in redacted
    assert "supersecretpassword" not in redacted
    assert "4111111111111111" not in redacted
    assert "123-45-6789" not in redacted
    assert "[REDACTED_TOKEN]" in redacted
    assert "[REDACTED_CARD]" in redacted
    assert "[REDACTED_SSN]" in redacted


def test_quarantine_rejects_protected_path(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    import cypher.fscan.trust as trust_module
    monkeypatch.setattr(trust_module, "is_excluded_path", lambda p: True)

    dummy = tmp_path / "system32.dll"
    dummy.write_text("data", encoding="utf-8")
    queued = quarantine.queue_findings({
        "findings": [{"path": str(dummy), "signature": "TestSig", "engine": "test"}]
    })

    import pytest
    with pytest.raises(ValueError, match="Protected system or project path"):
        quarantine.quarantine_finding(queued[0]["id"])
