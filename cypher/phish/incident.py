"""Local incident records and a consent-oriented response checklist."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
from threading import RLock
import uuid
from typing import Any

from cypher.config import appdata_dir
from cypher.phish.reputation import normalize_domain


MAX_INCIDENTS = 500
RESPONSE_CHECKLIST = [
    "If you entered a password, change it from a trusted device and update reused passwords.",
    "Sign out of active sessions, revoke unfamiliar app access, and enable 2FA or passkeys.",
    "If you entered card or payment details, contact the provider and review recent activity.",
    "Run a local file scan and review recently downloaded files.",
    "Clear cookies/site data for the domain in your browser if desired.",
]
_INCIDENT_LOCK = RLock()


def _incidents_path() -> Path:
    return appdata_dir() / "phish" / "incidents.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_host(value: str) -> str:
    candidate = value.strip().strip("[]")
    try:
        return ipaddress.ip_address(candidate).compressed.casefold()
    except ValueError:
        return normalize_domain(value)


def _load() -> list[dict[str, Any]]:
    path = _incidents_path()
    if not path.exists():
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read local phishing incidents: {exc}") from exc
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RuntimeError("The local phishing incident index is invalid.")
    return value[-MAX_INCIDENTS:]


def _save(incidents: list[dict[str, Any]]) -> None:
    path = _incidents_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    try:
        temporary.write_text(
            json.dumps(incidents[-MAX_INCIDENTS:], indent=2),
            encoding="utf-8",
        )
        temporary.replace(path)
    except OSError as exc:
        raise RuntimeError(f"Could not save local phishing incident: {exc}") from exc


def create_incident(
    domain: str,
    verdict: str,
    risk_score: int,
    evidence: list[str] | None = None,
    trigger: str = "local-check",
    simulation: bool = False,
) -> dict[str, Any]:
    """Create a local report without retaining the full URL or performing actions."""
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("A domain or IP address is required.")
    host = _normalize_host(domain)
    if type(risk_score) is not int or not 0 <= risk_score <= 100:
        raise ValueError("Incident risk score must be between 0 and 100.")
    allowed_verdicts = {"Safe", "Caution", "Suspicious", "Phishing"}
    if verdict not in allowed_verdicts:
        raise ValueError("Incident verdict is invalid.")
    safe_evidence = [
        str(item)[:500] for item in (evidence or [])[:20] if isinstance(item, str)
    ]
    timestamp = _now()
    incident = {
        "id": uuid.uuid4().hex[:12],
        "created_at": timestamp,
        "domain": host,
        "verdict": verdict,
        "risk_score": risk_score,
        "trigger": str(trigger)[:80],
        "simulation": bool(simulation),
        "evidence": safe_evidence,
        "timeline": [{"at": timestamp, "event": str(trigger)[:120]}],
        "response_started": False,
        "actions_taken": [],
        "actions_pending": list(RESPONSE_CHECKLIST),
        "network_changed": False,
        "credentials_entered": None,
        "email_sent": False,
    }
    with _INCIDENT_LOCK:
        incidents = _load()
        incidents.append(incident)
        _save(incidents)
    return incident


def list_incidents() -> list[dict[str, Any]]:
    """Return local incidents, newest first."""
    with _INCIDENT_LOCK:
        return list(reversed(_load()))


def get_incident(incident_id: str) -> dict[str, Any]:
    if not incident_id or len(incident_id) > 40:
        raise ValueError("Enter a valid incident ID.")
    with _INCIDENT_LOCK:
        for incident in _load():
            if incident.get("id") == incident_id:
                return incident
    raise ValueError(f"Phishing incident '{incident_id}' was not found.")


def run_manual_response(incident_id: str) -> dict[str, Any]:
    """Record a user-requested checklist; no network or destructive action is run."""
    with _INCIDENT_LOCK:
        incident = get_incident(incident_id)
        if incident.get("simulation"):
            raise ValueError("A simulation incident cannot run a real response.")
        timestamp = _now()
        incident["response_started"] = True
        incident["timeline"].append(
            {"at": timestamp, "event": "User opened the manual response checklist."}
        )
        incidents = _load()
        for index, item in enumerate(incidents):
            if item.get("id") == incident_id:
                incidents[index] = incident
                break
        _save(incidents)
        return incident
