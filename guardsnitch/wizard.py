"""First-run setup wizard."""

from __future__ import annotations

from getpass import getpass
import hashlib
import secrets
from base64 import urlsafe_b64encode
import smtplib
from email.message import EmailMessage

import keyring

from rich.console import Console
from rich.prompt import Confirm, Prompt

from guardsnitch.config import GuardConfig, config_path


def run_wizard(console: Console) -> GuardConfig:
    console.rule("[bold cyan]GuardSnitch.ai setup[/]")
    console.print("Press Ctrl+C at any time to cancel safely.\n")

    name = Prompt.ask("1/6  Your name", default="User")
    alert_email = Prompt.ask("2/6  Email address to receive theft alerts")
    while "@" not in alert_email or "." not in alert_email:
        alert_email = Prompt.ask("Enter a valid alert email")

    console.print(
        "[dim]This address is the recipient for theft-location emails. "
        "A configured sender account is required for delivery.[/] "
    )
    email_method = Prompt.ask(
        "   Email sending method",
        choices=["SMTP", "Gmail app password"],
        default="SMTP",
    )
    smtp_user = Prompt.ask("   Sender email", default=alert_email)
    if email_method == "Gmail app password":
        console.print(
            "[dim]Enable 2-Step Verification, then create an App Password in "
            "Google Account > Security > App passwords.[/] "
        )
    smtp_password = getpass("   Email or app password (input hidden): ")
    if smtp_password:
        keyring.set_password("GuardSnitch.ai", "smtp-password", smtp_password)
        keyring.set_password("GuardSnitch.ai", "smtp-user", smtp_user)
        keyring.set_password("GuardSnitch.ai", "smtp-host", "smtp.gmail.com")
        keyring.set_password("GuardSnitch.ai", "smtp-port", "587")
        code = f"{secrets.randbelow(1_000_000):06d}"
        try:
            message = EmailMessage()
            message["From"] = smtp_user
            message["To"] = alert_email
            message["Subject"] = "GuardSnitch.ai setup verification"
            message.set_content(f"Your GuardSnitch.ai verification code is {code}")
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(message)
            entered = Prompt.ask("6-digit verification code")
            if entered != code:
                console.print("[yellow]Email verification failed; setup cancelled.[/] ")
                raise KeyboardInterrupt
        except (smtplib.SMTPException, OSError, ValueError):
            console.print(
                "[yellow]Could not send a verification code. "
                "Setup will continue, but theft email alerts remain unverified.[/] "
            )

    ai_mode = Prompt.ask(
        "3/6  AI mode",
        choices=["cloud", "offline"],
        default="offline",
    )
    theft = Confirm.ask("4/6  Enable theft protection?", default=False)
    malware = Confirm.ask("   Enable periodic malware scans?", default=True)
    shield = Confirm.ask("   Enable reverse-shell shield?", default=True)
    ip_rotation = Confirm.ask("   Enable scheduled IP shield?", default=False)
    ip_time = "03:00"
    if ip_rotation:
        ip_time = Prompt.ask("   Daily IP rotation time (HH:MM)", default="03:00")

    consent_webcam = False
    consent_location = False
    if theft:
        console.print("5/6  Theft evidence consent")
        consent_webcam = Confirm.ask("Allow webcam capture if theft is strongly detected?", default=False)
        consent_location = Confirm.ask("Allow location capture and email alerts?", default=False)

    pin = getpass("6/6  Create a disarm PIN (input hidden): ")
    if len(pin) < 6:
        console.print("[yellow]PIN must be at least 6 characters; setup cancelled.[/]")
        raise KeyboardInterrupt
    pin_salt = secrets.token_bytes(16)
    pin_hash = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), pin_salt, 200_000)
    keyring.set_password(
        "GuardSnitch.ai",
        "disarm-pin",
        urlsafe_b64encode(pin_salt + pin_hash).decode("ascii"),
    )

    config = GuardConfig(
        name=name,
        alert_email=alert_email,
        ai_mode=ai_mode,
        theft_protection=theft,
        reverse_shell_shield=shield,
        malware_scans=malware,
        ip_rotation=ip_rotation,
        ip_rotation_time=ip_time,
        consent_webcam=consent_webcam,
        consent_location=consent_location,
    )
    config.save()
    console.print(f"[green]Saved[/] {config_path()}")
    console.print("[yellow]Sensitive credentials will be stored in Windows Credential Manager in later setup steps.[/]")
    return config
