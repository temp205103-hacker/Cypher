import json

from cypher.vpn.manager import VpnManager
from cypher.vpn.providers.mock import MockProvider


def test_mock_connect_persists_state(tmp_path) -> None:
    state_path = tmp_path / "vpn_state.json"
    manager = VpnManager(provider=MockProvider(), state_path=state_path)

    state = manager.connect("Germany")

    assert state["connected"] is True
    assert state["country_code"] == "DE"
    assert state["provider"] == "mock"
    assert state["simulated"] is True
    assert manager.status() == json.loads(state_path.read_text(encoding="utf-8"))


def test_disconnect_keeps_last_country_for_reconnect(tmp_path) -> None:
    manager = VpnManager(
        provider=MockProvider(),
        state_path=tmp_path / "vpn_state.json",
    )
    manager.connect("JP")

    state = manager.disconnect()

    assert state["connected"] is False
    assert state["country_code"] == "JP"
    assert manager.reconnect()["country_code"] == "JP"


def test_random_uses_different_country(tmp_path) -> None:
    manager = VpnManager(
        provider=MockProvider(),
        state_path=tmp_path / "vpn_state.json",
    )
    first = manager.connect("Germany")

    second = manager.connect("random")

    assert second["connected"] is True
    assert second["country_code"] != first["country_code"]


def test_connect_without_country_uses_us_by_default(tmp_path) -> None:
    manager = VpnManager(
        provider=MockProvider(),
        state_path=tmp_path / "vpn_state.json",
    )

    assert manager.connect()["country_code"] == "US"
