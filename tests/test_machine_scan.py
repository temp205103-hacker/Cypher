import pytest
from fastapi import HTTPException
from typer.testing import CliRunner

from guardsnitch.cli import app
from guardsnitch.config import GuardConfig
from guardsnitch.core import machine_scan, malware, quarantine
from guardsnitch.web import app as dashboard


def test_machine_scan_summarizes_volumes_and_quarantines_clamav_matches(monkeypatch) -> None:
    monkeypatch.setattr(malware, "scanner_status", lambda: {"available": True})
    monkeypatch.setattr(machine_scan, "machine_roots", lambda: ["C:\\", "D:\\"])
    monkeypatch.setattr(
        malware,
        "scan_file",
        lambda root: {
            "path": root,
            "status": "suspicious" if root == "C:\\" else "clean",
            "engines": ["ClamAV"],
            "warnings": [],
            "findings": [{"path": "C:\\bad.exe", "classification": "malware-detected"}]
            if root == "C:\\"
            else [],
        },
    )
    monkeypatch.setattr(
        quarantine,
        "queue_findings",
        lambda result: [{"id": "finding-1", "path": "C:\\bad.exe", **item}
                        for item in result["findings"]],
    )
    quarantined = []
    monkeypatch.setattr(
        quarantine,
        "quarantine_finding",
        lambda finding_id: quarantined.append(finding_id),
    )

    result = machine_scan.scan_machine()

    assert result["status"] == "complete"
    assert result["volumes_scanned"] == 2
    assert result["total_findings"] == 1
    assert result["total_quarantined"] == 1
    assert quarantined == ["finding-1"]


def test_machine_scan_reports_partial_volume_errors(monkeypatch) -> None:
    monkeypatch.setattr(malware, "scanner_status", lambda: {"available": True})
    monkeypatch.setattr(machine_scan, "machine_roots", lambda: ["C:\\", "D:\\"])

    def scan(root):
        if root == "D:\\":
            raise PermissionError("access denied")
        return {"path": root, "findings": [], "engines": ["YARA"], "warnings": []}

    monkeypatch.setattr(malware, "scan_file", scan)
    monkeypatch.setattr(quarantine, "queue_findings", lambda _result: [])

    result = machine_scan.scan_machine()

    assert result["status"] == "partial"
    assert result["volumes_scanned"] == 1
    assert result["volumes_failed"] == 1
    assert result["errors"][0]["volume"] == "D:\\"


def test_machine_scan_requires_a_local_scanner(monkeypatch) -> None:
    monkeypatch.setattr(malware, "scanner_status", lambda: {"available": False})

    with pytest.raises(malware.ScannerUnavailableError, match="No local scanner"):
        machine_scan.scan_machine()


def test_machine_scan_deduplicates_multiple_signatures_for_a_file(tmp_path) -> None:
    target = str(tmp_path / "same.exe")
    result = machine_scan._unique_file_findings({
        "findings": [
            {"path": target, "classification": "malware-detected", "signature": "Win.A"},
            {"path": target, "classification": "malware-detected", "signature": "Win.B"},
            {"path": target, "classification": "suspicious-pattern", "signature": "Yara.C"},
        ]
    })

    assert len(result["findings"]) == 1
    assert result["findings"][0]["signature"] == "Win.A, Win.B"


def test_machine_scan_keeps_yara_suspicion_for_review(monkeypatch) -> None:
    monkeypatch.setattr(malware, "scanner_status", lambda: {"available": True})
    monkeypatch.setattr(machine_scan, "machine_roots", lambda: ["C:\\"])
    monkeypatch.setattr(
        malware,
        "scan_file",
        lambda _root: {
            "path": "C:\\",
            "findings": [{
                "path": "C:\\script.ps1",
                "classification": "suspicious-pattern",
                "signature": "SuspiciousRule",
            }],
            "engines": ["YARA"],
            "warnings": [],
        },
    )
    monkeypatch.setattr(
        quarantine,
        "queue_findings",
        lambda _result: [{"id": "review-1", "path": "C:\\script.ps1",
                          "classification": "suspicious-pattern"}],
    )
    monkeypatch.setattr(
        quarantine,
        "quarantine_finding",
        lambda *_args: pytest.fail("YARA suspicion must remain for user review"),
    )

    result = machine_scan.scan_machine()

    assert result["total_findings"] == 1
    assert result["total_quarantined"] == 0
    assert result["volumes"][0]["finding_ids"] == ["review-1"]


def test_stop_process_only_terminates_matching_finding(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    target = tmp_path / "detected.exe"
    target.write_bytes(b"sample")
    item = quarantine.queue_findings({
        "findings": [{
            "path": str(target),
            "engine": "ClamAV",
            "classification": "malware-detected",
            "signature": "Win.Test.Signature",
        }]
    })[0]

    class Process:
        pid = 123
        info = {"exe": str(target)}
        terminated = False

        def exe(self):
            return str(target)

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            return 0

    process = Process()
    monkeypatch.setattr(quarantine.psutil, "process_iter", lambda _attrs: [process])

    result = quarantine.stop_detected_process(item["id"])

    assert result["stopped"] == [123]
    assert process.terminated


def test_dashboard_machine_scan_requires_confirmation(monkeypatch) -> None:
    monkeypatch.setattr(machine_scan, "scan_machine", lambda: {"status": "complete"})
    dashboard._REPORTS.clear()

    with pytest.raises(HTTPException) as error:
        dashboard.run_action(dashboard.ActionRequest(action="malware.scan-machine"))
    assert "Confirm" in error.value.detail["message"]


def test_dashboard_machine_scan_returns_summary(monkeypatch) -> None:
    summary = {"status": "complete", "total_findings": 2, "total_quarantined": 1}
    monkeypatch.setattr(machine_scan, "scan_machine", lambda: summary)

    report = dashboard.run_action(
        dashboard.ActionRequest(action="malware.scan-machine", confirmed=True)
    )

    assert report["status"] == "completed"
    assert report["result"] == summary


def test_cli_machine_scan_shows_summary(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    GuardConfig(name="Test", alert_email="test@example.com").save()
    summary = {
        "status": "complete", "volumes_scanned": 1, "volumes_failed": 0,
        "total_findings": 1, "total_quarantined": 1,
        "volumes": [{
            "volume": "C:\\", "status": "detections", "findings": 1,
            "finding_ids": [], "quarantined_ids": ["item-1"], "warnings": [],
        }],
        "errors": [], "note": "Confirmed ClamAV detections were moved to quarantine.",
    }
    monkeypatch.setattr(machine_scan, "scan_machine", lambda **_kwargs: summary)

    result = CliRunner().invoke(app, ["malware", "scan-machine", "--yes"])

    assert result.exit_code == 0
    assert "quarantined" in result.stdout
    assert "item-1" in result.stdout


def test_stop_process_requires_exact_executable_match(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    target = tmp_path / "detected.exe"
    other = tmp_path / "other.exe"
    target.write_bytes(b"sample")
    other.write_bytes(b"other")
    finding = quarantine.queue_findings({
        "findings": [{
            "path": str(target),
            "engine": "ClamAV",
            "classification": "malware-detected",
            "signature": "Win.Test.Signature",
        }]
    })[0]

    class OtherProcess:
        pid = 321
        info = {"exe": str(other)}

        def exe(self):
            return str(other)

    monkeypatch.setattr(quarantine.psutil, "process_iter", lambda _attrs: [OtherProcess()])

    with pytest.raises(ValueError, match="No running process"):
        quarantine.stop_detected_process(finding["id"])
