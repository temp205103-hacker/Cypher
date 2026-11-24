"""Laptop theft signal scoring and alert orchestration."""

from __future__ import annotations

import ctypes
import json
import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Optional
from base64 import urlsafe_b64decode
from getpass import getpass
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cypher.config import CypherConfig, appdata_dir, get_secret
from cypher.core.location import LocationResolver
from cypher.core.notify import EmailNotifier
from cypher.core.sensors import sensor_snapshot


SIGNAL_WEIGHTS = {
    "motion_spike": 2,
    "charger_unplugged": 2,
    "lid_or_sleep": 3,
    "outside_safe_zone": 2,
    "new_usb": 2,
    "failed_logins": 2,
    "shutdown_attempt": 3,
}


@dataclass
class TheftSignalSnapshot:
    timestamp: str
    score: int
    triggered: bool
    signals: dict[str, bool]
    sensor: dict[str, object]


def score_theft_signals(signals: dict[str, bool]) -> int:
    return sum(SIGNAL_WEIGHTS[name] for name, active in signals.items() if active)


def should_trigger(signals: dict[str, bool], threshold: int = 5) -> bool:
    return score_theft_signals(signals) >= threshold


def lock_workstation() -> None:
    """Lock the current Windows session, leaving normal sign-in available."""
    if os.name != "nt":
        raise OSError("Automatic workstation locking is supported only on Windows.")
    if not ctypes.windll.user32.LockWorkStation():
        raise OSError("Windows could not lock the workstation.")


class TheftProtection:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.state_path = appdata_dir() / "theft-state.json"

    def _write_state(self, armed: bool) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "armed": armed,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self.state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def is_armed(self) -> bool:
        if not self.state_path.exists():
            return False
        try:
            return bool(json.loads(self.state_path.read_text(encoding="utf-8")).get("armed"))
        except (json.JSONDecodeError, OSError):
            return False

    def arm(self) -> None:
        config = CypherConfig.load()
        if not config.consent_location:
            self.console.print(
                "[yellow]Location sharing is disabled in setup. "
                "Run Cypher setup to enable it.[/] "
            )
        self._write_state(True)
        self.console.print("[green]Theft protection armed[/].")
        self.console.print("A simulated alert can be tested with [bold]Cypher theft test[/].")

    def disarm(self, pin: Optional[str] = None) -> bool:
        if pin is None:
            pin = getpass("Enter the disarm PIN: ")
        stored = get_secret("disarm-pin")
        if not stored:
            self.console.print("[red]No disarm PIN is configured. Run Cypher setup.[/] ")
            return False
        raw = urlsafe_b64decode(stored)
        salt, stored_hash = raw[:16], raw[16:]
        entered_hash = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, 200_000)
        if not hmac.compare_digest(entered_hash, stored_hash):
            self.console.print("[red]Incorrect PIN; theft protection remains armed.[/] ")
            return False
        self._write_state(False)
        self.console.print("[green]Theft protection disarmed[/].")
        return True

    def status(self) -> None:
        state = "ARMED" if self.is_armed() else "DISARMED"
        style = "green" if self.is_armed() else "yellow"
        self.console.print(Panel(f"Theft protection is [bold {style}]{state}[/].", title="Theft"))

    def collect_snapshot(self, signals: Iterable[str] = ()) -> TheftSignalSnapshot:
        active = set(signals)
        signal_flags = {name: name in active for name in SIGNAL_WEIGHTS}
        score = score_theft_signals(signal_flags)
        return TheftSignalSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            score=score,
            triggered=should_trigger(signal_flags),
            signals=signal_flags,
            sensor=sensor_snapshot(),
        )

    def process_live_signals(self, signals: Iterable[str]) -> bool:
        """Alert and lock only for an armed, confirmed theft event."""
        if not self.is_armed():
            return False
        snapshot = self.collect_snapshot(signals)
        if not snapshot.triggered:
            return False

        try:
            config = CypherConfig.load()
            if config.consent_webcam:
                try:
                    from cypher.core.evidence import capture_screenshot, capture_webcam
                    capture_webcam()
                    capture_screenshot()
                except Exception:
                    pass
            location = LocationResolver().resolve()
            notifier = EmailNotifier()
            notifier.queue_alert(snapshot, location)
            notifier.send_alert(snapshot, location)
        finally:
            lock_workstation()
        return True

    def test_alert(self) -> None:
        snapshot = self.collect_snapshot(
            ["charger_unplugged", "outside_safe_zone", "new_usb"]
        )
        location = LocationResolver().resolve()
        notifier = EmailNotifier()
        result = notifier.send_test_alert(snapshot, location)

        table = Table(title="Safe theft alert simulation")
        table.add_column("Check")
        table.add_column("Result")
        table.add_row("Combined signal score", str(snapshot.score))
        table.add_row("Would trigger", "Yes" if snapshot.triggered else "No")
        table.add_row("Grace period", "20-30 seconds")
        table.add_row("Location", location.description)
        table.add_row("Email", result)
        table.add_row("Loud alarm / lock / webcam", "NOT executed (simulation)")
        self.console.print(table)
        self.console.print(
            "[dim]This demo does not capture a camera image or send a real alert unless delivery is configured and explicitly requested.[/] "
        )
