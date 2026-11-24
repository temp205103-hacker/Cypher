"""Best-effort location resolution without a stalkerware-style permanent tracker."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from urllib.request import urlopen


@dataclass
class Location:
    description: str
    latitude: float | None = None
    longitude: float | None = None
    source: str = "none"

    def maps_url(self) -> str:
        if self.latitude is not None and self.longitude is not None:
            return f"https://www.google.com/maps?q={self.latitude},{self.longitude}"
        return "https://www.google.com/maps"


class LocationResolver:
    def resolve(self) -> Location:
        from cypher.config import CypherConfig

        if not CypherConfig.load().consent_location:
            return Location(description="Location sharing disabled", source="none")
        windows_location = self._windows_location()
        if windows_location:
            return windows_location

        wifi_location = self._wifi_location()
        if wifi_location:
            return wifi_location

        return self._ip_location()

    def _windows_location(self) -> Location | None:
        if os.name != "nt":
            return None
        try:
            import winsdk.windows.devices.geolocation as geolocation

            # winsdk is optional and can require a live async UI context.
            if geolocation.Geolocator().location is not None:
                position = geolocation.Geolocator().location
                coordinate = position.coordinate
                return Location(
                    description="Windows Location reported a coordinate",
                    latitude=coordinate.latitude,
                    longitude=coordinate.longitude,
                    source="windows",
                )
        except (ImportError, AttributeError, OSError):
            pass
        return None

    def _wifi_location(self) -> Location | None:
        if os.name != "nt":
            return None
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0 and "SSID" in result.stdout:
                ssids = [
                    line.split(":", 1)[-1].strip()
                    for line in result.stdout.splitlines()
                    if "SSID" in line and "BSSID" not in line
                ]
                if ssids:
                    return Location(
                        description=f"Approximate location unavailable; Wi-Fi SSID: {ssids[0]}",
                        source="wifi",
                    )
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def _ip_location(self) -> Location:
        try:
            with urlopen("https://ipapi.co/json/", timeout=4) as response:
                data = json.loads(response.read().decode("utf-8"))
            latitude = data.get("latitude")
            longitude = data.get("longitude")
            if latitude is not None and longitude is not None:
                return Location(
                    description=f"IP-based estimate near {data.get('city', 'unknown')}",
                    latitude=float(latitude),
                    longitude=float(longitude),
                    source="ip",
                )
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        return Location(description="Location unavailable", source="none")
