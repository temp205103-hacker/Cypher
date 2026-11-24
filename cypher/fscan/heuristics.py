"""Conservative, explainable file-context signals."""

from __future__ import annotations

from pathlib import Path
from typing import Any


EXECUTABLE_SUFFIXES = {
    ".appx", ".bat", ".cmd", ".com", ".dll", ".exe", ".hta", ".jar",
    ".js", ".jse", ".lnk", ".msi", ".msix", ".ps1", ".scr", ".vbe",
    ".vbs", ".wsf",
}
RISKY_SUFFIXES = EXECUTABLE_SUFFIXES | {".iso", ".zip"}


def inspect_path(path: Path) -> list[dict[str, Any]]:
    suffixes = [suffix.casefold() for suffix in path.suffixes]
    signals: list[dict[str, Any]] = []
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_SUFFIXES and suffixes[-2] not in EXECUTABLE_SUFFIXES:
        signals.append({
            "id": "double-extension",
            "group": "filename",
            "weight": 25,
            "evidence": f"Executable has a misleading double extension: {path.name}",
        })

    lower_parts = {part.casefold() for part in path.parts}
    suffix = path.suffix.casefold()
    if suffix in RISKY_SUFFIXES and lower_parts.intersection(
        {"appdata", "roaming", "startup", "downloads", "desktop", "temp", "tmp"}
    ):
        is_persistence_area = bool(lower_parts.intersection({"appdata", "roaming", "startup"}))
        signals.append({
            "id": "executable-in-persistence-area" if is_persistence_area else "executable-in-user-risk-area",
            "group": "location",
            "weight": 18 if is_persistence_area else 14,
            "evidence": (
                f"Executable or installer is in an application-data/startup area: {path.parent}"
                if is_persistence_area
                else f"Executable or installer is in a user-writable risk area: {path.parent}"
            ),
        })

    if suffix in EXECUTABLE_SUFFIXES:
        try:
            mark = Path(str(path) + ":Zone.Identifier")
            if mark.is_file():
                signals.append({
                    "id": "mark-of-the-web",
                    "group": "origin",
                    "weight": 8,
                    "evidence": "Windows Mark-of-the-Web indicates this file came from the internet.",
                })
        except OSError:
            pass

    if len(suffixes) > 2 and suffix in EXECUTABLE_SUFFIXES and not (
        len(suffixes) >= 2 and suffixes[-2] not in EXECUTABLE_SUFFIXES
    ):
        signals.append({
            "id": "multiple-suffixes",
            "group": "filename",
            "weight": 8,
            "evidence": "File has multiple suffixes, which can disguise its real type.",
        })
    return signals
