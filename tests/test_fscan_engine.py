import json
from pathlib import Path

from typer.testing import CliRunner

from guardsnitch.cli import app
from guardsnitch.fscan import engine
from guardsnitch.fscan.engine import ScanOptions, analyze_file, scan_paths
from guardsnitch.fscan.hashing import cached_sha256
from guardsnitch.fscan.trust import EICAR_TEST_SHA256, allow_hash, hash_reputation, is_excluded_path


SAFE_EICAR_FIXTURE = b"Harmless placeholder; scanner test supplies the published EICAR test hash."


def test_scan_detects_safe_samples_and_reports_precision_recall(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    eicar = downloads / "eicar.txt"
    eicar.write_bytes(SAFE_EICAR_FIXTURE)
    original_hash = engine.cached_sha256

    def test_hash(path, **kwargs):
        if path.name == "eicar.txt":
            return EICAR_TEST_SHA256
        return original_hash(path, **kwargs)

    monkeypatch.setattr(engine, "cached_sha256", test_hash)
    disguised = downloads / "invoice.pdf.exe"
    disguised.write_text("Harmless placeholder sample.", encoding="utf-8")
    normal = downloads / "notes.txt"
    normal.write_text("Meeting notes and a grocery list.", encoding="utf-8")

    report = scan_paths([downloads], options=ScanOptions())

    actual_positive = {str(eicar), str(disguised)}
    predicted_positive = {item["path"] for item in report["findings"]}
    true_positive = len(actual_positive & predicted_positive)
    precision = true_positive / len(predicted_positive)
    recall = true_positive / len(actual_positive)
    print(f"Safe-sample precision={precision:.2f}, recall={recall:.2f} (TP={true_positive}, FP=0, FN=0)")

    assert precision == 1.0
    assert recall == 1.0
    assert report["files_scanned"] == 3
    assert report["counts"]["Clean"] == 1
    assert report["counts"]["Suspicious"] == 1
    assert report["counts"]["Low"] == 1
    assert all(item["evidence"] for item in report["findings"])


def test_explicit_scan_path_reports_repeatable_scores(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    target = tmp_path / "invoice.pdf.exe"
    target.write_bytes(b"safe fake installer")

    first = analyze_file(target)
    second = analyze_file(target)

    assert first["sha256"] == second["sha256"]
    assert first["score"] == second["score"]
    assert first["verdict"] == "Low"


def test_guardignore_skips_matching_files(tmp_path) -> None:
    root = tmp_path / "sample"
    root.mkdir()
    (root / "skip.exe").write_bytes(b"fake")
    (root / "keep.txt").write_text("ordinary text", encoding="utf-8")
    ignore = tmp_path / ".guardignore"
    ignore.write_text("skip.exe\n", encoding="utf-8")

    report = scan_paths([root], options=ScanOptions(ignore_file=ignore))

    assert report["files_scanned"] == 1
    assert not report["findings"]


def test_default_protection_excludes_project_but_explicit_scan_can_include(tmp_path) -> None:
    repository = Path(__file__).resolve().parents[1]

    assert is_excluded_path(repository / "guardsnitch" / "cli.py")
    assert is_excluded_path(repository / "demo")
    assert not is_excluded_path(tmp_path / "download.exe")


def test_local_hash_allowlist_is_user_scoped_and_overrides_fixture_blocklist(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))

    assert hash_reputation(EICAR_TEST_SHA256) == "blocked"
    allow_hash(EICAR_TEST_SHA256)
    assert hash_reputation(EICAR_TEST_SHA256) == "user-allowlisted"


def test_fscan_cli_works_without_profile_setup_and_emits_json(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    target = tmp_path / "EICAR.txt"
    target.write_bytes(SAFE_EICAR_FIXTURE)
    monkeypatch.setattr(engine, "cached_sha256", lambda *_args, **_kwargs: EICAR_TEST_SHA256)

    result = CliRunner().invoke(app, ["fscan", "--path", str(target), "--format", "json"])

    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["files_scanned"] == 1
    assert report["findings"][0]["verdict"] == "Suspicious"


def test_fscan_help_includes_modes_and_examples(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))

    result = CliRunner().invoke(app, ["fscan", "--help"])

    assert result.exit_code == 0
    for option in ("--quick", "--full", "--path", "--usb", "--format", "--quiet", "--verbose"):
        assert option in result.stdout
    assert "GuardSnitch.ai fscan --usb" in result.stdout
