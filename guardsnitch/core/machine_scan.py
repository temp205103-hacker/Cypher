"""Full scan of mounted local volumes with explicit partial-scan reporting."""

from __future__ import annotations

import os
from typing import Any, Callable

import psutil

from guardsnitch.core import malware, quarantine


class MachineScanError(RuntimeError):
    """Expected, user-facing whole-machine scan failure."""


_REMOTE_FILESYSTEMS = {
    "cifs", "devfs", "devtmpfs", "fuse.sshfs", "nfs", "proc", "smbfs",
    "sysfs", "tmpfs",
}


def machine_roots() -> list[str]:
    roots: set[str] = set()
    try:
        partitions = psutil.disk_partitions(all=False)
    except psutil.Error as exc:
        raise MachineScanError(f"Could not list mounted drives: {exc}") from exc
    for partition in partitions:
        mountpoint = partition.mountpoint
        if not mountpoint:
            continue
        if psutil.WINDOWS:
            if "fixed" not in partition.opts.casefold() and "removable" not in partition.opts.casefold():
                continue
        elif partition.fstype.casefold() in _REMOTE_FILESYSTEMS:
            continue
        roots.add(mountpoint)
    if not roots:
        raise MachineScanError("No mounted local drives were found to scan.")
    return sorted(roots, key=str.casefold)


def _unique_file_findings(result: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in result.get("findings", []):
        path = str(finding.get("path", ""))
        key = os.path.normcase(os.path.abspath(path)) if path else repr(finding)
        grouped.setdefault(key, []).append(finding)

    findings: list[dict[str, Any]] = []
    for matches in grouped.values():
        malware_matches = [
            item for item in matches
            if item.get("classification") == "malware-detected"
        ]
        selected = malware_matches or matches
        finding = dict(selected[0])
        finding["signature"] = ", ".join(
            dict.fromkeys(str(item.get("signature", "unknown")) for item in selected)
        )
        findings.append(finding)
    return {**result, "findings": findings}


def scan_machine(
    on_volume: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    scanners = malware.scanner_status()
    if not scanners["available"]:
        raise malware.ScannerUnavailableError(
            "No local scanner is installed. Install ClamAV (clamscan) or YARA, then retry."
        )

    roots = machine_roots()
    volumes: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    total_findings = 0
    total_quarantined = 0

    for root in roots:
        if on_volume:
            on_volume(root)
        error_count_before = len(errors)
        try:
            result = _unique_file_findings(malware.scan_file(root))
            queued = quarantine.queue_findings(result)
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append({"volume": root, "error": str(exc)})
            volumes.append({"volume": root, "status": "failed", "findings": 0, "warnings": []})
            continue

        count = len(queued)
        total_findings += count
        quarantined: list[str] = []
        pending: list[str] = []
        for item in queued:
            if item.get("classification") != "malware-detected":
                pending.append(str(item["id"]))
                continue
            try:
                quarantine.quarantine_finding(str(item["id"]))
            except (OSError, RuntimeError, ValueError) as exc:
                errors.append({"volume": root, "error": f"{item['path']}: {exc}"})
                pending.append(str(item["id"]))
            else:
                quarantined.append(str(item["id"]))
        total_quarantined += len(quarantined)
        warnings = [str(warning) for warning in result.get("warnings", [])]
        volumes.append({
            "volume": root,
            "status": "partial" if warnings or len(errors) > error_count_before else ("detections" if count else "clean"),
            "findings": count,
            "quarantined": len(quarantined),
            "quarantined_ids": quarantined,
            "finding_ids": pending,
            "engines": result.get("engines", []),
            "warnings": warnings,
        })

    if not any(volume["status"] != "failed" for volume in volumes):
        message = "; ".join(f"{item['volume']}: {item['error']}" for item in errors)
        raise MachineScanError(f"No volumes could be scanned. {message}")

    return {
        "status": "partial" if errors or any(item["status"] == "partial" for item in volumes) else "complete",
        "volumes_scanned": sum(item["status"] != "failed" for item in volumes),
        "volumes_failed": sum(item["status"] == "failed" for item in volumes),
        "total_findings": total_findings,
        "total_quarantined": total_quarantined,
        "volumes": volumes,
        "errors": errors,
        "note": "ClamAV malware detections were moved to quarantine. YARA suspicious-pattern findings remain queued for review.",
    }
