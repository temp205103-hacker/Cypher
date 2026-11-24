from pathlib import Path
import subprocess

import pytest

from cypher import cli
from cypher.core import updater
from cypher.web import app as dashboard
from typer.testing import CliRunner


def _git(path: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)


@pytest.mark.parametrize(
    "remote",
    [
        "https://github.com/temp205103-hacker/Cypher.git",
        "git@github.com:temp205103-hacker/Cypher.git",
        "ssh://git@github.com/temp205103-hacker/Cypher",
    ],
)
def test_updater_accepts_only_expected_origin_forms(remote) -> None:
    assert updater._trusted_origin(remote)


@pytest.mark.parametrize(
    "remote",
    [
        "https://github.com/someone-else/Cypher.git",
        "https://user:token@github.com/temp205103-hacker/Cypher.git",
        "https://example.com/temp205103-hacker/Cypher.git",
        "https://github.com:8443/temp205103-hacker/Cypher.git",
        "https://github.com:bad-port/temp205103-hacker/Cypher.git",
    ],
)
def test_updater_rejects_untrusted_origins(remote) -> None:
    assert not updater._trusted_origin(remote)


def test_updater_refuses_dirty_checkouts(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        updater, "_fetch_status",
        lambda: {
            "available": True, "current": "old", "latest": "new", "behind": 1,
            "dirty": True, "branch": "main",
        },
    )
    monkeypatch.setattr(updater, "_package_root", lambda: tmp_path)
    monkeypatch.setattr(updater, "_git", lambda *_args, **_kwargs: pytest.fail("must not merge"))

    with pytest.raises(updater.UpdateError, match="Commit or stash"):
        updater.update_checkout()


def test_updater_fast_forwards_a_clean_checkout(monkeypatch, tmp_path) -> None:
    remote = tmp_path / "origin.git"
    checkout = tmp_path / "checkout"
    writer = tmp_path / "writer"
    remote.mkdir()
    checkout.mkdir()
    subprocess.run(["git", "init", "--bare", "-b", "main"], cwd=remote, check=True, capture_output=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=checkout, check=True, capture_output=True)
    _git(checkout, "config", "user.email", "test@example.com")
    _git(checkout, "config", "user.name", "Test")
    (checkout / "feature.txt").write_text("before\n", encoding="utf-8")
    _git(checkout, "add", "feature.txt")
    _git(checkout, "commit", "-m", "initial")
    _git(checkout, "remote", "add", "origin", str(remote))
    _git(checkout, "push", "-u", "origin", "main")
    subprocess.run(["git", "clone", str(remote), str(writer)], check=True, capture_output=True)
    _git(writer, "config", "user.email", "test@example.com")
    _git(writer, "config", "user.name", "Test")
    (writer / "feature.txt").write_text("after\n", encoding="utf-8")
    _git(writer, "commit", "-am", "change")
    _git(writer, "push", "origin", "main")
    monkeypatch.setattr(updater, "_package_root", lambda: checkout)
    monkeypatch.setattr(updater, "_trusted_origin", lambda _origin: True)

    result = updater.update_checkout()

    assert result["updated"] is True
    assert (checkout / "feature.txt").read_text(encoding="utf-8") == "after\n"


def test_cli_update_flag_calls_checkout_updater(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(
        updater,
        "update_checkout",
        lambda: calls.append(True) or {
            "updated": True, "current": "abc123",
        },
    )

    result = CliRunner().invoke(cli.app, ["--update"])

    assert result.exit_code == 0
    assert calls == [True]
    assert "Restart the CLI or dashboard" in result.stdout


def test_dashboard_update_routes_call_the_updater(monkeypatch) -> None:
    status = {"available": True, "behind": 2, "dirty": False}
    applied = {"updated": True, "current": "new"}
    monkeypatch.setattr(updater, "check_for_updates", lambda: status)
    monkeypatch.setattr(updater, "update_checkout", lambda: applied)

    assert dashboard.update_status() == status
    assert dashboard.apply_update() == applied
