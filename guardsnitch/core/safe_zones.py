"""Manage user-approved Wi-Fi SSIDs for theft-signal evaluation."""

from __future__ import annotations

from guardsnitch.config import GuardConfig


SSID_MAX_LENGTH = 32


def list_safe_zones() -> list[str]:
    value = GuardConfig.load().extra.get("safe_zone_ssids", [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("Configured safe-zone list is invalid.")
    return sorted(set(value), key=str.casefold)


def _save(zones: list[str]) -> list[str]:
    config = GuardConfig.load()
    config.extra["safe_zone_ssids"] = sorted(set(zones), key=str.casefold)
    config.save()
    return config.extra["safe_zone_ssids"]


def add_safe_zone(ssid: str) -> list[str]:
    name = ssid.strip()
    if not name or len(name) > SSID_MAX_LENGTH or any(ord(char) < 32 for char in name):
        raise ValueError("Enter a Wi-Fi network name between 1 and 32 printable characters.")
    zones = list_safe_zones()
    if not any(item.casefold() == name.casefold() for item in zones):
        zones.append(name)
    return _save(zones)


def remove_safe_zone(ssid: str) -> list[str]:
    name = ssid.strip()
    zones = list_safe_zones()
    updated = [item for item in zones if item.casefold() != name.casefold()]
    if len(updated) == len(zones):
        raise ValueError(f"No safe zone named {name!r} exists.")
    return _save(updated)
