"""Local, user-editable phishing lists and privacy-limited check history."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from threading import RLock
from typing import Any
from urllib.parse import urlsplit

from cypher.config import appdata_dir


_STORE_LOCK = RLock()
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_MAX_HISTORY = 500


def _store_dir() -> Path:
    return appdata_dir() / "phish"


def normalize_domain(value: str) -> str:
    """Validate a domain or URL input and return an ASCII lowercase hostname."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A domain is required.")
    candidate = value.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The domain contains an invalid port.") from exc
    if (
        parsed.username
        or parsed.password
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Enter a domain only, without credentials, path, query, or fragment.")
    host = (parsed.hostname or "").rstrip(".")
    if not host:
        raise ValueError("Enter a valid domain.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name, not an IP address.")
    try:
        normalized = host.encode("idna").decode("ascii").casefold()
    except UnicodeError as exc:
        raise ValueError("The domain contains invalid internationalized characters.") from exc
    if not _DOMAIN_RE.fullmatch(normalized):
        raise ValueError("Enter a fully qualified domain name.")
    return normalized


def _read_list(filename: str) -> frozenset[str]:
    path = _store_dir() / filename
    if not path.exists():
        return frozenset()
    try:
        return frozenset(
            normalize_domain(line.strip())
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Could not read local phishing list {path}: {exc}") from exc


def _write_list(filename: str, domains: set[str]) -> None:
    directory = _store_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    content = "# Cypher local phishing list; edited by the user.\n"
    content += "".join(f"{domain}\n" for domain in sorted(domains))
    temporary = path.with_suffix(".tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    except OSError as exc:
        raise RuntimeError(f"Could not update local phishing list {path}: {exc}") from exc


def user_allowed_domains() -> frozenset[str]:
    return _read_list("allowlist.txt")


def user_blocked_domains() -> frozenset[str]:
    return _read_list("blocklist.txt")


def set_domain_decision(value: str, decision: str) -> str:
    """Add a domain to one local list and remove it from the opposite list."""
    domain = normalize_domain(value)
    if decision not in {"allow", "block"}:
        raise ValueError("Decision must be 'allow' or 'block'.")
    with _STORE_LOCK:
        allowlist = set(user_allowed_domains())
        blocklist = set(user_blocked_domains())
        if decision == "allow":
            allowlist.add(domain)
            blocklist.discard(domain)
        else:
            blocklist.add(domain)
            allowlist.discard(domain)
        _write_list("allowlist.txt", allowlist)
        _write_list("blocklist.txt", blocklist)
    return domain


def record_check(result: dict[str, Any]) -> None:
    """Store a bounded, local summary without query strings or full URL paths."""
    domain = str(result.get("host", ""))[:253]
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "verdict": str(result.get("verdict", "Unknown")),
        "risk_score": int(result.get("risk_score", 0)),
        "url_hash": hashlib.sha256(
            str(result.get("url", "")).encode("utf-8", errors="replace")
        ).hexdigest(),
    }
    directory = _store_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "history.json"
    with _STORE_LOCK:
        entries = history()
        entries.append(entry)
        entries = entries[-_MAX_HISTORY:]
        temporary = path.with_suffix(".tmp")
        try:
            temporary.write_text(json.dumps(entries, indent=2), encoding="utf-8")
            temporary.replace(path)
        except OSError as exc:
            raise RuntimeError(f"Could not save local phishing history: {exc}") from exc


def history() -> list[dict[str, Any]]:
    """Return local check summaries, newest last."""
    path = _store_dir() / "history.json"
    if not path.exists():
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read local phishing history: {exc}") from exc
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RuntimeError("The local phishing history is invalid.")
    return value[-_MAX_HISTORY:]


def clear_history() -> None:
    """Delete local phishing check history."""
    path = _store_dir() / "history.json"
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Could not clear local phishing history: {exc}") from exc
