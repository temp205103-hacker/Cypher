"""Provider protocol shared by VPN backends."""

from __future__ import annotations

from typing import Protocol


class VpnProvider(Protocol):
    name: str

    def connect(self, country_code: str) -> dict[str, object]:
        """Connect to a server and return non-secret connection details."""
        ...

    def disconnect(self) -> None:
        """Stop the provider's active connection."""
        ...
