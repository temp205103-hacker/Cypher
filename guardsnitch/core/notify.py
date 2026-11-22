"""Email notifications for theft alerts."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
import json
from pathlib import Path

import keyring

from guardsnitch.config import GuardConfig
from guardsnitch.config import appdata_dir
from guardsnitch.core.location import Location
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardsnitch.core.theft import TheftSignalSnapshot


class EmailNotifier:
    def queue_alert(self, snapshot: "TheftSignalSnapshot", location: Location) -> Path:
        folder = appdata_dir() / "theft-alerts"
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"{snapshot.timestamp.replace(':', '-')}.json"
        target.write_text(
            json.dumps(
                {
                    "timestamp": snapshot.timestamp,
                    "score": snapshot.score,
                    "signals": snapshot.signals,
                    "location": location.description,
                    "maps_url": location.maps_url(),
                    "source": location.source,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return target

    def send_test_alert(
        self,
        snapshot: "TheftSignalSnapshot",
        location: Location,
    ) -> str:
        return self._send_alert(snapshot, location, test=True)

    def send_alert(
        self,
        snapshot: "TheftSignalSnapshot",
        location: Location,
    ) -> str:
        return self._send_alert(snapshot, location, test=False)

    def _send_alert(
        self,
        snapshot: "TheftSignalSnapshot",
        location: Location,
        *,
        test: bool,
    ) -> str:
        config = GuardConfig.load()
        if not config.alert_email:
            return "not configured (setup first)"
        if not config.consent_location:
            return "location sharing is disabled"
        password = keyring.get_password("GuardSnitch.ai", "smtp-password")
        if not password:
            return f"simulated only; owner: {config.alert_email}"

        sender = keyring.get_password("GuardSnitch.ai", "smtp-user")
        host = keyring.get_password("GuardSnitch.ai", "smtp-host") or "smtp.gmail.com"
        port_text = keyring.get_password("GuardSnitch.ai", "smtp-port") or "587"
        if not sender:
            return "SMTP sender not configured"

        message = EmailMessage()
        message["From"] = sender
        message["To"] = config.alert_email
        message["Subject"] = (
            "GuardSnitch.ai theft alert test"
            if test
            else "GuardSnitch.ai theft alert"
        )
        introduction = (
            "This is a simulated GuardSnitch.ai theft alert.\n"
            if test
            else "GuardSnitch.ai detected a possible laptop theft.\n"
        )
        message.set_content(
            f"{introduction}"
            f"Signal score: {snapshot.score}\n"
            f"Location: {location.description}\n"
            f"Map: {location.maps_url()}\n"
            f"Timestamp: {snapshot.timestamp}\n"
        )
        try:
            with smtplib.SMTP(host, int(port_text), timeout=10) as server:
                server.starttls()
                server.login(sender, password)
                server.send_message(message)
            return f"sent to {config.alert_email}"
        except (smtplib.SMTPException, OSError, ValueError):
            return "delivery failed; alert queued locally"
