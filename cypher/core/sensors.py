"""Portable laptop sensor snapshots."""

from __future__ import annotations

import os
import subprocess
from typing import Any, Dict

import psutil


def sensor_snapshot() -> Dict[str, Any]:
    battery = psutil.sensors_battery()
    snapshot: Dict[str, Any] = {
        "battery_percent": getattr(battery, "percent", None),
        "battery_plugged": getattr(battery, "power_plugged", None),
        "connected": psutil.net_if_addrs() is not None,
        "wifi_names": [],
    }
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "SSID" in line and "BSSID" not in line:
                        snapshot["wifi_names"].append(line.split(":", 1)[-1].strip())
        except (OSError, subprocess.SubprocessError):
            pass
    return snapshot
