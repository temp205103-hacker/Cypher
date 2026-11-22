"""Loopback-only web dashboard for GuardSnitch.ai."""

from __future__ import annotations

import base64
from collections import deque
from datetime import datetime, timezone
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import secrets
from threading import RLock
from typing import Any, Callable, Optional
from urllib.parse import urlsplit
import uuid

import keyring
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from rich.console import Console

from guardsnitch.config import GuardConfig
from guardsnitch.core import malware as malware_core
from guardsnitch.core import quarantine as quarantine_core
from guardsnitch.core import shield
from guardsnitch.core.theft import TheftProtection
from guardsnitch.ip.leaktest import run_leak_test
from guardsnitch.ip.rotate import rotate as rotate_public_ip
from guardsnitch.vpn.manager import VpnError, VpnManager
from guardsnitch.vpn.providers.mock import MockProvider
from guardsnitch.vpn.providers.openvpn import OpenVpnProvider


_WEB_DIR = Path(__file__).parent
_REPORTS: deque[dict[str, Any]] = deque(maxlen=50)
_REPORTS_LOCK = RLock()
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}

app = FastAPI(title="GuardSnitch.ai", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(_WEB_DIR / "static")), name="static")


class ActionRequest(BaseModel):
    action: str
    path: Optional[str] = None
    country: Optional[str] = None
    item_id: Optional[str] = None
    process_name: Optional[str] = None
    ip: Optional[str] = None
    pin: Optional[str] = None
    dry_run: bool = False
    confirmed: bool = False
    name: Optional[str] = None
    alert_email: Optional[str] = None
    ai_mode: Optional[str] = None
    theft_protection: bool = False
    reverse_shell_shield: bool = True
    malware_scans: bool = True
    ip_rotation: bool = False
    ip_rotation_time: str = "03:00"
    consent_webcam: bool = False
    consent_location: bool = False


@app.middleware("http")
async def restrict_to_local_browser(request: Request, call_next: Callable[..., Any]) -> Any:
    host = request.headers.get("host", "")
    hostname = urlsplit("//" + host).hostname
    if hostname not in _LOOPBACK_HOSTS:
        return JSONResponse({"detail": "Dashboard is available only on this computer."}, status_code=403)

    origin = request.headers.get("origin")
    if request.method not in {"GET", "HEAD", "OPTIONS"} and origin:
        parsed_origin = urlsplit(origin)
        if parsed_origin.scheme != "http" or parsed_origin.hostname not in _LOOPBACK_HOSTS:
            return JSONResponse({"detail": "Cross-origin actions are not allowed."}, status_code=403)

    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_WEB_DIR / "templates" / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"name": "GuardSnitch.ai", "scope": "localhost"}


def _status_section(operation: Callable[[], Any]) -> Any:
    try:
        return operation()
    except (OSError, RuntimeError, ValueError) as exc:
        return {"error": str(exc)}


def _new_vpn_manager() -> VpnManager:
    if os.getenv("GUARDSNITCH_VPN_PROVIDER", "").casefold() == "mock":
        return VpnManager(provider=MockProvider())
    return VpnManager(provider=OpenVpnProvider())


def _vpn_dashboard_state() -> dict[str, Any]:
    manager = _new_vpn_manager()
    if manager.provider.name == "openvpn":
        profiles = sorted(
            profile.stem
            for profile in OpenVpnProvider().profile_dir.glob("*.ovpn")
        )
        available = [{"name": profile, "code": profile} for profile in profiles]
    else:
        available = [
            {"name": country.name, "code": country.code}
            for country in manager.countries()
        ]
    return {"state": manager.status(), "available": available}


@app.get("/api/dashboard")
def dashboard() -> dict[str, Any]:
    config = _status_section(GuardConfig.load)
    if isinstance(config, GuardConfig):
        profile = {
            "configured": bool(config.name.strip() and config.alert_email.strip()),
            "name": config.name,
            "alert_email": config.alert_email,
            "ai_mode": config.ai_mode,
            "theft_protection": config.theft_protection,
            "reverse_shell_shield": config.reverse_shell_shield,
            "malware_scans": config.malware_scans,
            "ip_rotation": config.ip_rotation,
            "ip_rotation_time": config.ip_rotation_time,
            "consent_webcam": config.consent_webcam,
            "consent_location": config.consent_location,
        }
    else:
        profile = config

    return {
        "profile": profile,
        "shield": _status_section(shield.read_shield_status),
        "startup": _status_section(shield.startup_status),
        "malware": {
            "scanners": malware_core.scanner_status(),
            "monitor": _status_section(malware_core.monitor_status),
        },
        "findings": _status_section(quarantine_core.list_findings),
        "quarantine": _status_section(quarantine_core.list_quarantine),
        "vpn": _status_section(_vpn_dashboard_state),
        "theft": {
            "armed": _status_section(lambda: TheftProtection().is_armed()),
        },
    }


@app.get("/api/reports")
def reports() -> list[dict[str, Any]]:
    with _REPORTS_LOCK:
        return list(_REPORTS)


def _require_confirmation(payload: ActionRequest, message: str) -> None:
    if not payload.confirmed:
        raise ValueError(message)


def _required(value: Optional[str], label: str) -> str:
    if value is None or not value.strip():
        raise ValueError(f"{label} is required.")
    return value.strip()


def _save_profile(payload: ActionRequest) -> dict[str, Any]:
    name = _required(payload.name, "Name")
    email = _required(payload.alert_email, "Alert email")
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        raise ValueError("Enter a valid alert email.")
    if payload.ai_mode not in {"offline", "cloud"}:
        raise ValueError("Choose offline or cloud AI mode.")
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", payload.ip_rotation_time):
        raise ValueError("IP rotation time must use 24-hour HH:MM format.")

    pin = payload.pin or ""
    existing_pin = keyring.get_password("GuardSnitch.ai", "disarm-pin")
    if pin and len(pin) < 6:
        raise ValueError("The disarm PIN must be at least 6 characters.")
    if not existing_pin and not pin:
        raise ValueError("Create a disarm PIN with at least 6 characters.")
    if pin:
        salt = secrets.token_bytes(16)
        pin_hash = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, 200_000)
        encoded = base64.urlsafe_b64encode(salt + pin_hash).decode("ascii")
        keyring.set_password("GuardSnitch.ai", "disarm-pin", encoded)

    previous = GuardConfig.load()
    config = GuardConfig(
        name=name,
        alert_email=email,
        ai_mode=payload.ai_mode,
        theft_protection=payload.theft_protection,
        reverse_shell_shield=payload.reverse_shell_shield,
        malware_scans=payload.malware_scans,
        ip_rotation=payload.ip_rotation,
        ip_rotation_time=payload.ip_rotation_time,
        consent_webcam=payload.consent_webcam,
        consent_location=payload.consent_location,
        dashboard_token=previous.dashboard_token,
        extra=previous.extra,
    )
    config.save()
    return {
        "configured": True,
        "name": name,
        "email_delivery": bool(keyring.get_password("GuardSnitch.ai", "smtp-password")),
    }


def _capture_theft_action(method: str, pin: Optional[str] = None) -> dict[str, Any]:
    from io import StringIO

    output = StringIO()
    service = TheftProtection(console=Console(file=output, force_terminal=False))
    if method == "arm":
        service.arm()
        result: Any = {"armed": service.is_armed()}
    elif method == "disarm":
        result = {"disarmed": service.disarm(pin)}
        if not result["disarmed"]:
            raise ValueError("The PIN was not accepted; theft protection remains armed.")
    else:
        service.test_alert()
        result = {"simulation": True}
    result["output"] = output.getvalue()
    return result


def _perform_action(payload: ActionRequest) -> Any:
    action = payload.action
    if action == "profile.save":
        return _save_profile(payload)
    if action == "shield.status":
        return shield.read_shield_status()
    if action == "shield.startup.status":
        return {"command": shield.startup_status()}
    if action == "malware.status":
        return {
            "scanners": malware_core.scanner_status(),
            "monitor": malware_core.monitor_status(),
        }
    if action == "malware.findings":
        return quarantine_core.list_findings()
    if action == "quarantine.list":
        return quarantine_core.list_quarantine()
    if action == "vpn.status":
        return _new_vpn_manager().status()
    if action == "vpn.countries":
        return _vpn_dashboard_state()["available"]
    if action == "ip.status":
        state = _new_vpn_manager().status()
        return {
            "real_openvpn_connected": (
                state.get("provider") == "openvpn"
                and bool(state.get("connected"))
                and not bool(state.get("simulated"))
            ),
            "provider": state.get("provider"),
            "profile": state.get("profile"),
        }
    if action == "theft.status":
        return {"armed": TheftProtection().is_armed()}

    if action == "malware.scan":
        target = payload.path or str(malware_core.default_downloads_dir())
        scan_result = malware_core.scan_file(target)
        queued = quarantine_core.queue_findings(scan_result)
        return {"scan": scan_result, "queued": queued}
    if action == "malware.monitor.start":
        status = malware_core.start_monitor()
        if not status.get("running"):
            raise RuntimeError("The Downloads monitor did not start.")
        return status
    if action == "malware.monitor.stop":
        return malware_core.stop_monitor()
    if action == "quarantine.isolate":
        _require_confirmation(payload, "Confirm moving this finding into quarantine.")
        return quarantine_core.quarantine_finding(_required(payload.item_id, "Finding ID"))
    if action == "quarantine.restore":
        _require_confirmation(payload, "Confirm restoring this file; it may still be unsafe.")
        return quarantine_core.restore_quarantined(_required(payload.item_id, "Quarantine ID"))
    if action == "quarantine.delete":
        _require_confirmation(payload, "Confirm permanently deleting this quarantined file.")
        return quarantine_core.delete_quarantined(_required(payload.item_id, "Quarantine ID"))

    if action == "vpn.connect":
        return _new_vpn_manager().connect(payload.country or None)
    if action == "vpn.disconnect":
        _require_confirmation(payload, "Confirm disconnecting the VPN.")
        return _new_vpn_manager().disconnect()
    if action == "vpn.reconnect":
        _require_confirmation(payload, "Confirm reconnecting the VPN.")
        return _new_vpn_manager().reconnect()
    if action == "ip.rotate":
        if not payload.dry_run:
            _require_confirmation(payload, "Confirm switching OpenVPN profiles and checking your public IP.")
        return rotate_public_ip(dry_run=payload.dry_run)
    if action == "ip.leak-test":
        return run_leak_test()

    if action == "shield.start":
        status = shield.start_shield()
        if not status.get("running"):
            raise RuntimeError("The reverse-shell shield did not start.")
        return status
    if action == "shield.stop":
        _require_confirmation(payload, "Confirm stopping the reverse-shell shield.")
        return shield.stop_shield()
    if action == "shield.startup.install":
        _require_confirmation(payload, "Confirm starting the shield automatically at Windows sign-in.")
        return {"command": shield.install_startup()}
    if action == "shield.startup.uninstall":
        _require_confirmation(payload, "Confirm removing automatic shield startup.")
        return {"removed": shield.remove_startup()}
    if action == "shield.allow":
        process_name = _required(payload.process_name, "Process name")
        if any(character in process_name for character in ("\0", "\r", "\n")):
            raise ValueError("Process name contains an invalid character.")
        return shield.set_process_allowed(process_name, True)
    if action == "shield.block-ip":
        address = str(ipaddress.ip_address(_required(payload.ip, "IP address")))
        _require_confirmation(payload, f"Confirm blocking outbound traffic to {address}.")
        from guardsnitch.core.shield_service import block_remote_ip

        result = block_remote_ip(address, 0)
        if not result.get("blocked"):
            raise RuntimeError(str(result.get("error", "Could not create the Windows Firewall rule.")))
        return result

    if action == "theft.arm":
        _require_confirmation(payload, "Confirm arming theft protection.")
        return _capture_theft_action("arm")
    if action == "theft.disarm":
        _require_confirmation(payload, "Confirm disarming theft protection.")
        return _capture_theft_action("disarm", _required(payload.pin, "Disarm PIN"))
    if action == "theft.test":
        _require_confirmation(payload, "This safe simulation may send a configured test email. Continue?")
        return _capture_theft_action("test")

    if action in {
        "scan",
        "redact",
        "install-hook",
        "explain",
        "ask",
        "safe-run",
        "malware.schedule",
        "ip.schedule",
        "ip.history",
        "ip.stop",
        "theft.safe-zones",
    }:
        raise ValueError(f"{action} is a planned command and is not implemented yet.")
    raise ValueError(f"Unknown dashboard action: {action}")


def _record_report(action: str, started_at: str, result: Any = None, error: Optional[str] = None) -> dict[str, Any]:
    report = {
        "id": uuid.uuid4().hex,
        "action": action,
        "status": "failed" if error else "completed",
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "result": result,
        "error": error,
    }
    with _REPORTS_LOCK:
        _REPORTS.appendleft(report)
    return report


@app.post("/api/actions")
def run_action(payload: ActionRequest) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = _perform_action(payload)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        report = _record_report(payload.action, started_at, error=str(exc))
        raise HTTPException(
            status_code=400,
            detail={"message": str(exc), "report": report},
        ) from exc
    report = _record_report(payload.action, started_at, result=result)
    return report
