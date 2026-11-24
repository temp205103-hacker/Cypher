"""No-network VPN provider for demos and tests."""

from __future__ import annotations

from cypher.vpn.countries import resolve_country


class MockProvider:
    """Simulate a connection without changing the machine's network."""

    name = "mock"

    def connect(self, country_code: str) -> dict[str, object]:
        country = resolve_country(country_code)
        suffix = int(country.code, 36) % 200 + 1
        return {
            "country_code": country.code,
            "country_name": country.name,
            "server": f"mock-{country.code.lower()}-{suffix:03d}",
            "ipv4": f"198.51.100.{suffix}",
            "ipv6": f"2001:db8::{suffix:x}",
            "simulated": True,
        }

    def disconnect(self) -> None:
        """There is no real tunnel to stop in mock mode."""
