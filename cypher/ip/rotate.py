"""Rotate an active OpenVPN connection between installed profiles."""

from __future__ import annotations

import ipaddress
import json
import random
from pathlib import Path
from typing import Callable
from urllib.request import urlopen

from cypher.vpn.manager import VpnManager
from cypher.vpn.providers.openvpn import OpenVpnProvider


class IpRotationError(RuntimeError):
    """Expected, user-facing IP rotation failure."""


def public_ip(version: int = 4) -> str:
    if version == 4:
        url = "https://api.ipify.org?format=json"
    elif version == 6:
        url = "https://api6.ipify.org?format=json"
    else:
        raise ValueError("IP version must be 4 or 6.")

    try:
        with urlopen(url, timeout=8) as response:
            data = json.loads(response.read().decode("utf-8"))
        address = ipaddress.ip_address(data["ip"])
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise IpRotationError(f"Could not determine the public IPv{version} address: {exc}") from exc
    if address.version != version:
        raise IpRotationError(f"The IP-check service returned a non-IPv{version} address.")
    return str(address)


def rotate(
    dry_run: bool = False,
    *,
    manager: VpnManager | None = None,
    profile_dir: Path | None = None,
    ip_lookup: Callable[[int], str] = public_ip,
) -> dict[str, object]:
    vpn = manager or VpnManager(provider=OpenVpnProvider())
    state = vpn.status()
    if state.get("provider") != "openvpn" or not state.get("connected"):
        raise IpRotationError("Connect a real OpenVPN profile before rotating the public IP.")

    folder = profile_dir or OpenVpnProvider().profile_dir
    profiles = sorted(folder.glob("*.ovpn"), key=lambda path: path.name.casefold())
    if not profiles:
        raise IpRotationError(f"No .ovpn profiles found in {folder}.")

    current_value = state.get("profile")
    current = Path(str(current_value)).resolve() if current_value else None
    choices = [profile.resolve() for profile in profiles if profile.resolve() != current]
    if not choices:
        raise IpRotationError("Add at least one other .ovpn profile to rotate to.")

    recent_profiles = set()
    try:
        from cypher.ip import history as ip_history_store
        for entry in ip_history_store.load_history()[:10]:
            to_p = entry.get("to_profile")
            if to_p:
                recent_profiles.add(Path(str(to_p)).resolve())
    except Exception:
        pass

    eligible = [p for p in choices if p not in recent_profiles]
    target = random.choice(eligible) if eligible else random.choice(choices)
    if dry_run:
        return {
            "method": "openvpn",
            "changed": False,
            "dry_run": True,
            "from_profile": str(current) if current else None,
            "to_profile": str(target),
        }

    before = ip_lookup(4)
    new_state = vpn.connect(str(target))
    after = ip_lookup(4)
    return {
        "method": "openvpn",
        "changed": before != after,
        "dry_run": False,
        "from_profile": str(current) if current else None,
        "to_profile": str(target),
        "previous_ip": before,
        "current_ip": after,
        "connected": bool(new_state.get("connected")),
    }
