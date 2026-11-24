"""Shared VPN state and connection orchestration."""

from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cypher.config import appdata_dir
from cypher.vpn.countries import Country, available_countries, resolve_country
from cypher.vpn.providers.base import VpnProvider
from cypher.vpn.providers.mock import MockProvider
from cypher.vpn.providers.openvpn import OpenVpnProvider


class VpnError(RuntimeError):
    """Expected, user-facing VPN operation failure."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class VpnManager:
    """Manage a provider and persist its current connection state."""

    def __init__(
        self,
        provider: VpnProvider | None = None,
        state_path: Path | None = None,
    ) -> None:
        self.provider = provider or MockProvider()
        self.state_path = state_path or appdata_dir() / "vpn_state.json"

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {
                "connected": False,
                "provider": self.provider.name,
                "country_code": None,
                "country_name": None,
                "server": None,
                "started_at": None,
                "kill_switch": False,
            }
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VpnError(f"Could not read VPN state at {self.state_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise VpnError(f"VPN state at {self.state_path} is not a JSON object.")
        return data

    def _save_state(self, state: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".tmp")
        try:
            temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
            temporary.replace(self.state_path)
        except OSError as exc:
            raise VpnError(f"Could not save VPN state at {self.state_path}: {exc}") from exc

    def countries(self) -> list[Country]:
        """List mock countries available in this implementation stage."""
        return available_countries()

    def status(self) -> dict[str, Any]:
        """Return persisted connection details."""
        return self._load_state()

    def connect(self, country: str | None = None) -> dict[str, Any]:
        current = self._load_state()
        previous_code = current.get("country_code")
        if self.provider.name == "openvpn":
            profile = country or str(previous_code or "")
            if not profile:
                raise VpnError(
                    "No OpenVPN profile is selected. Pass a profile name or .ovpn path."
                )
            if current.get("connected"):
                try:
                    self.provider.disconnect()
                except Exception as exc:
                    raise VpnError(f"Could not stop the current VPN connection: {exc}") from exc
                current["connected"] = False
                current["started_at"] = None
                current["disconnected_at"] = _utc_now()
                self._save_state(current)
            try:
                details = self.provider.connect(profile)
            except Exception as exc:
                raise VpnError(str(exc)) from exc
            state = {
                **current,
                **details,
                "connected": True,
                "provider": self.provider.name,
                "started_at": _utc_now(),
                "disconnected_at": None,
                "kill_switch": bool(current.get("kill_switch", False)),
            }
            self._save_state(state)
            return state

        if country is None:
            target = resolve_country(str(previous_code or "US"))
        elif country.strip().casefold() == "random":
            choices = [
                candidate
                for candidate in self.countries()
                if candidate.code != previous_code
            ]
            if not choices:
                raise VpnError("No alternate countries are available.")
            target = random.choice(choices)
        else:
            try:
                target = resolve_country(country)
            except ValueError as exc:
                raise VpnError(str(exc)) from exc

        if current.get("connected"):
            try:
                self.provider.disconnect()
            except Exception as exc:
                raise VpnError(f"Could not stop the current VPN connection: {exc}") from exc
            current["connected"] = False
            current["started_at"] = None
            current["disconnected_at"] = _utc_now()
            self._save_state(current)

        try:
            details = self.provider.connect(target.code)
        except Exception as exc:
            raise VpnError(f"Could not connect to {target.name}: {exc}") from exc

        state = {
            **current,
            **details,
            "connected": True,
            "provider": self.provider.name,
            "started_at": _utc_now(),
            "disconnected_at": None,
            "kill_switch": bool(current.get("kill_switch", False)),
        }
        self._save_state(state)
        return state

    def disconnect(self) -> dict[str, Any]:
        state = self._load_state()
        if state.get("connected"):
            try:
                self.provider.disconnect()
            except Exception as exc:
                raise VpnError(f"Could not disconnect VPN: {exc}") from exc
        state["connected"] = False
        state["started_at"] = None
        state["disconnected_at"] = _utc_now()
        self._save_state(state)
        return state

    def reconnect(self) -> dict[str, Any]:
        state = self._load_state()
        country_code = state.get("country_code")
        if not country_code:
            raise VpnError("No previous VPN country is saved. Connect to a country first.")
        return self.connect(str(country_code))
