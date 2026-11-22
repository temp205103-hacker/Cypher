"""Configuration stored in the user's GuardSnitch data directory."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict

import yaml


def appdata_dir() -> Path:
    if os.name == "nt":
        base = os.getenv("APPDATA")
        if base:
            return Path(base) / "GuardSnitch"
    return Path.home() / ".guardsnitch"


def config_path() -> Path:
    return appdata_dir() / "config.yaml"


@dataclass
class GuardConfig:
    name: str = ""
    alert_email: str = ""
    ai_mode: str = "offline"
    theft_protection: bool = False
    reverse_shell_shield: bool = True
    malware_scans: bool = True
    ip_rotation: bool = False
    ip_rotation_time: str = "03:00"
    consent_webcam: bool = False
    consent_location: bool = False
    dashboard_token: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> "GuardConfig":
        target = path or config_path()
        if not target.exists():
            return cls()
        with target.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Invalid configuration in {target}")
        known = cls.__dataclass_fields__
        return cls(**{key: value for key, value in data.items() if key in known})

    def exists(self, path: Path | None = None) -> bool:
        return (path or config_path()).is_file()

    def save(self, path: Path | None = None) -> Path:
        target = path or config_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(asdict(self), handle, sort_keys=False)
        return target

    def reset(self, path: Path | None = None) -> None:
        target = path or config_path()
        if target.exists():
            target.unlink()
