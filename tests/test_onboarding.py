from typer.testing import CliRunner

from cypher import cli
from cypher import config as config_module
from cypher.config import CypherConfig


def _save_profile(_console) -> CypherConfig:
    config = CypherConfig(name="Ada", alert_email="ada@example.com")
    config.save()
    return config


def test_first_launch_runs_setup_when_alert_email_is_missing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    CypherConfig(name="Ada").save()
    setup_calls = []

    def run_setup(console):
        setup_calls.append(True)
        return _save_profile(console)

    monkeypatch.setattr(cli, "run_wizard", run_setup)

    result = CliRunner().invoke(cli.app, [])

    assert result.exit_code == 0
    assert setup_calls == [True]


def test_installing_shield_startup_runs_setup_when_profile_is_missing(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    setup_calls = []
    monkeypatch.setattr(
        cli,
        "run_wizard",
        lambda console: setup_calls.append(True) or _save_profile(console),
    )
    monkeypatch.setattr(cli.shield, "install_startup", lambda: "pythonw.exe -m shield")

    result = CliRunner().invoke(cli.app, ["shield", "startup", "install"])

    assert result.exit_code == 0
    assert setup_calls == [True]
    assert "automatically" in result.stdout


def test_first_launch_skips_setup_for_complete_profile(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    CypherConfig(name="Ada", alert_email="ada@example.com").save()
    monkeypatch.setattr(
        cli,
        "run_wizard",
        lambda _console: (_ for _ in ()).throw(AssertionError("setup should not run")),
    )

    result = CliRunner().invoke(cli.app, [])

    assert result.exit_code == 0


def test_appdata_directory_migrates_existing_user_files(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    legacy = tmp_path / "GuardSnitch"
    legacy.mkdir()
    (legacy / "profile.yaml").write_text("name: Ada\n", encoding="utf-8")

    assert config_module.appdata_dir() == tmp_path / "Cypher"
    assert (tmp_path / "Cypher" / "profile.yaml").read_text(encoding="utf-8") == "name: Ada\n"
    assert not legacy.exists()


def test_appdata_migration_merges_without_overwriting_existing_cypher_files(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    legacy = tmp_path / "GuardSnitch"
    target = tmp_path / "Cypher"
    legacy.mkdir()
    target.mkdir()
    (legacy / "profile.yaml").write_text("name: Old\n", encoding="utf-8")
    (legacy / "settings.yaml").write_text("theme: old\n", encoding="utf-8")
    (target / "profile.yaml").write_text("name: New\n", encoding="utf-8")

    assert config_module.appdata_dir() == target
    assert (target / "profile.yaml").read_text(encoding="utf-8") == "name: New\n"
    assert (target / "settings.yaml").read_text(encoding="utf-8") == "theme: old\n"
    assert (legacy / "profile.yaml").read_text(encoding="utf-8") == "name: Old\n"


def test_legacy_keyring_secret_is_copied_to_cypher(monkeypatch) -> None:
    saved = []

    def get_password(service: str, key: str) -> str | None:
        return "existing-secret" if service == "GuardSnitch.ai" else None

    monkeypatch.setattr(config_module.keyring, "get_password", get_password)
    monkeypatch.setattr(
        config_module.keyring,
        "set_password",
        lambda service, key, value: saved.append((service, key, value)),
    )

    assert config_module.get_secret("smtp-password") == "existing-secret"
    assert saved == [("Cypher", "smtp-password", "existing-secret")]
