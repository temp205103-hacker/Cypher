from pathlib import Path

import pytest

from cypher.ip.leaktest import run_leak_test
from cypher.ip.rotate import IpRotationError, rotate


class FakeVpnManager:
    def __init__(self, state):
        self.state = state
        self.connected_profile = None

    def status(self):
        return self.state

    def connect(self, profile):
        self.connected_profile = profile
        self.state = {**self.state, "profile": profile, "connected": True}
        return self.state


def test_rotate_switches_profile_and_reports_ip_change(tmp_path: Path) -> None:
    current = tmp_path / "current.ovpn"
    target = tmp_path / "next.ovpn"
    current.write_text("client\n", encoding="utf-8")
    target.write_text("client\n", encoding="utf-8")
    manager = FakeVpnManager({
        "provider": "openvpn",
        "connected": True,
        "profile": str(current),
    })
    addresses = iter(["192.0.2.1", "198.51.100.2"])

    result = rotate(
        manager=manager,
        profile_dir=tmp_path,
        ip_lookup=lambda _version: next(addresses),
    )

    assert result["changed"] is True
    assert result["previous_ip"] == "192.0.2.1"
    assert result["current_ip"] == "198.51.100.2"
    assert manager.connected_profile == str(target.resolve())


def test_rotate_dry_run_does_not_connect_or_query_ip(tmp_path: Path) -> None:
    current = tmp_path / "current.ovpn"
    target = tmp_path / "next.ovpn"
    current.touch()
    target.touch()
    manager = FakeVpnManager({
        "provider": "openvpn",
        "connected": True,
        "profile": str(current),
    })

    result = rotate(
        dry_run=True,
        manager=manager,
        profile_dir=tmp_path,
        ip_lookup=lambda _version: pytest.fail("dry-run must not query public IP"),
    )

    assert result["dry_run"] is True
    assert manager.connected_profile is None


def test_rotate_rejects_mock_vpn(tmp_path: Path) -> None:
    manager = FakeVpnManager({
        "provider": "mock",
        "connected": True,
        "profile": None,
    })
    with pytest.raises(IpRotationError, match="real OpenVPN"):
        rotate(manager=manager, profile_dir=tmp_path)


def test_leak_test_compares_dns_to_active_profile(tmp_path: Path) -> None:
    profile = tmp_path / "active.ovpn"
    profile.write_text("dhcp-option DNS 10.8.0.1\n", encoding="utf-8")
    manager = FakeVpnManager({
        "provider": "openvpn",
        "connected": True,
        "simulated": False,
        "profile": str(profile),
    })

    result = run_leak_test(
        manager=manager,
        ip_lookup=lambda version: (
            "203.0.113.8" if version == 4 else "2001:db8::8"
        ),
        dns_lookup=lambda: ["10.8.0.1"],
    )

    assert result["vpn_connected"] is True
    assert result["public_ipv4"] == "203.0.113.8"
    assert result["dns_status"] == "matches-profile"


def test_leak_test_reports_dns_mismatch_and_unavailable_ipv6(tmp_path: Path) -> None:
    profile = tmp_path / "active.ovpn"
    profile.write_text("dhcp-option DNS 10.8.0.1\n", encoding="utf-8")
    manager = FakeVpnManager({
        "provider": "openvpn",
        "connected": True,
        "simulated": False,
        "profile": str(profile),
    })

    def lookup(version):
        if version == 6:
            raise IpRotationError("IPv6 unavailable")
        return "203.0.113.8"

    result = run_leak_test(
        manager=manager,
        ip_lookup=lookup,
        dns_lookup=lambda: ["192.168.1.1"],
    )

    assert result["dns_status"] == "potential-mismatch"
    assert result["public_ipv6"] is None
    assert result["ipv6_error"] == "IPv6 unavailable"
