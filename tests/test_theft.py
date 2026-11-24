import pytest

from cypher.core import theft
from cypher.core.theft import score_theft_signals, should_trigger


def test_one_theft_signal_does_not_trigger() -> None:
    assert not should_trigger({"charger_unplugged": True})


def test_combined_signals_trigger() -> None:
    signals = {
        "charger_unplugged": True,
        "outside_safe_zone": True,
        "new_usb": True,
    }
    assert score_theft_signals(signals) == 6
    assert should_trigger(signals)


@pytest.mark.parametrize(
    "signals, expected",
    [
        ({"lid_or_sleep": True}, False),
        ({"lid_or_sleep": True, "charger_unplugged": True}, True),
    ],
)
def test_score_threshold(signals, expected) -> None:
    assert should_trigger(signals) is expected


def test_live_signals_lock_only_when_armed_and_triggered(monkeypatch, tmp_path) -> None:
    protection = theft.TheftProtection()
    protection.state_path = tmp_path / "theft-state.json"
    locked = []

    class Notifier:
        def queue_alert(self, snapshot, location):
            return tmp_path / "alert.json"

        def send_alert(self, snapshot, location):
            return "sent"

    class Resolver:
        def resolve(self):
            return object()

    monkeypatch.setattr(theft, "EmailNotifier", Notifier)
    monkeypatch.setattr(theft, "LocationResolver", Resolver)
    monkeypatch.setattr(theft, "lock_workstation", lambda: locked.append(True))

    assert not protection.process_live_signals(
        ["charger_unplugged", "outside_safe_zone", "new_usb"]
    )
    protection._write_state(True)
    assert not protection.process_live_signals(["charger_unplugged"])
    assert locked == []
    assert protection.process_live_signals(
        ["charger_unplugged", "outside_safe_zone", "new_usb"]
    )
    assert locked == [True]
