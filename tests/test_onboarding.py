from typer.testing import CliRunner

from guardsnitch import cli
from guardsnitch.config import GuardConfig


def _save_profile(_console) -> GuardConfig:
    config = GuardConfig(name="Ada", alert_email="ada@example.com")
    config.save()
    return config


def test_first_launch_runs_setup_when_alert_email_is_missing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    GuardConfig(name="Ada").save()
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
    GuardConfig(name="Ada", alert_email="ada@example.com").save()
    monkeypatch.setattr(
        cli,
        "run_wizard",
        lambda _console: (_ for _ in ()).throw(AssertionError("setup should not run")),
    )

    result = CliRunner().invoke(cli.app, [])

    assert result.exit_code == 0
