"""Public IP and local DNS configuration diagnostics."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from guardsnitch.ip.rotate import IpRotationError, public_ip
from guardsnitch.vpn.manager import VpnManager
from guardsnitch.vpn.providers.openvpn import OpenVpnProvider


class LeakTestError(RuntimeError):
    """Expected, user-facing leak-test failure."""


def system_dns_servers() -> list[str]:
    if os.name == "nt":
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if not powershell:
            raise LeakTestError("PowerShell is required to inspect Windows DNS settings.")
        command = (
            "Get-DnsClientServerAddress | ForEach-Object {$_.ServerAddresses} "
            "| ConvertTo-Json -Compress"
        )
        try:
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LeakTestError(f"Could not inspect Windows DNS settings: {exc}") from exc
        if result.returncode:
            raise LeakTestError(
                f"Could not inspect Windows DNS settings: {result.stderr.strip()}"
            )
        try:
            raw_servers = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise LeakTestError("Windows returned invalid DNS settings.") from exc
        if raw_servers is None:
            raw_servers = []
        if isinstance(raw_servers, str):
            raw_servers = [raw_servers]
        return _valid_ips(raw_servers)

    resolv_conf = Path("/etc/resolv.conf")
    try:
        lines = resolv_conf.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LeakTestError(f"Could not read {resolv_conf}: {exc}") from exc
    servers = [
        match.group(1)
        for line in lines
        if (match := re.match(r"\s*nameserver\s+(\S+)", line))
    ]
    return _valid_ips(servers)


def _valid_ips(values: object) -> list[str]:
    if not isinstance(values, list):
        raise LeakTestError("DNS server information has an unexpected format.")
    valid: list[str] = []
    for value in values:
        try:
            address = str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            continue
        if address not in valid:
            valid.append(address)
    return valid


def _profile_dns(profile: object) -> list[str]:
    if not profile:
        raise LeakTestError("The active VPN state does not identify its OpenVPN profile.")
    try:
        lines = Path(str(profile)).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise LeakTestError(f"Could not read the active OpenVPN profile: {exc}") from exc
    servers: list[str] = []
    for line in lines:
        match = re.match(r"\s*dhcp-option\s+DNS\s+(\S+)", line, re.IGNORECASE)
        if match:
            try:
                address = str(ipaddress.ip_address(match.group(1)))
            except ValueError:
                continue
            if address not in servers:
                servers.append(address)
    return servers


def run_leak_test(
    *,
    manager: VpnManager | None = None,
    ip_lookup: Callable[[int], str] = public_ip,
    dns_lookup: Callable[[], list[str]] = system_dns_servers,
) -> dict[str, object]:
    vpn = manager or VpnManager(provider=OpenVpnProvider())
    state = vpn.status()
    vpn_connected = (
        state.get("provider") == "openvpn"
        and bool(state.get("connected"))
        and not bool(state.get("simulated"))
    )

    public_ipv4 = ip_lookup(4)
    try:
        public_ipv6 = ip_lookup(6)
        ipv6_error = None
    except IpRotationError as exc:
        public_ipv6 = None
        ipv6_error = str(exc)

    dns_servers = dns_lookup()
    vpn_dns_servers = _profile_dns(state.get("profile")) if vpn_connected else []
    if not vpn_connected:
        dns_status = "vpn-disconnected"
    elif not vpn_dns_servers:
        dns_status = "not-verifiable-from-profile"
    elif set(dns_servers).intersection(vpn_dns_servers):
        dns_status = "matches-profile"
    else:
        dns_status = "potential-mismatch"

    return {
        "vpn_connected": vpn_connected,
        "public_ipv4": public_ipv4,
        "public_ipv6": public_ipv6,
        "ipv6_error": ipv6_error,
        "dns_servers": dns_servers,
        "profile_dns_servers": vpn_dns_servers,
        "dns_status": dns_status,
    }
