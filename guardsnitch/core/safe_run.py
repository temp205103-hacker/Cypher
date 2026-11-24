"""Check URLs locally without contacting or opening the destination."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


class SafeRunError(ValueError):
    """Expected, user-facing URL inspection failure."""


SHORTENERS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tinyurl.com",
}
SUSPICIOUS_TERMS = re.compile(
    r"(?:account|billing|confirm|login|password|recover|secure|signin|verify|wallet)",
    re.IGNORECASE,
)
LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid")


def _parsed_public_url(url: str):
    if not isinstance(url, str) or not url or len(url) > 4096:
        return None
    try:
        parsed = urlsplit(url.strip())
        host = (parsed.hostname or "").rstrip(".").casefold()
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.casefold() not in {"http", "https"} or not host:
        return None
    if any(character.isspace() or ord(character) < 32 for character in host):
        return None
    if host == "localhost" or host.endswith(LOCAL_SUFFIXES):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        labels = ascii_host.split(".")
        if len(labels) < 2 or any(
            not label or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            return None
        host = ascii_host.casefold()
    else:
        if not address.is_global:
            return None
    if port is not None and not 1 <= port <= 65535:
        return None
    return parsed, host


def validate_url(url: str) -> bool:
    """Return whether the URL is syntactically valid and not a local target."""
    return _parsed_public_url(url) is not None


def inspect_url(url: str) -> dict[str, object]:
    """Score URL-only indicators; never resolve DNS or request the destination."""
    parsed_result = _parsed_public_url(url)
    if parsed_result is None:
        raise SafeRunError(
            "Enter a valid public HTTP or HTTPS URL; local and private network targets are refused."
        )
    parsed, host = parsed_result
    signals: list[dict[str, object]] = []

    def add_signal(name: str, weight: int, explanation: str) -> None:
        signals.append({"id": name, "weight": weight, "evidence": explanation})

    if parsed.username is not None or parsed.password is not None:
        add_signal("embedded-credentials", 30, "The URL embeds a username or password.")
    if parsed.scheme.casefold() == "http":
        add_signal("unencrypted-http", 10, "The link uses HTTP instead of encrypted HTTPS.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if any(label.startswith("xn--") for label in host.split(".")):
            add_signal("punycode-host", 25, "The hostname contains an encoded internationalized label.")
    else:
        add_signal("ip-address-host", 20, "The link uses a numeric IP address instead of a domain name.")
    if host in SHORTENERS:
        add_signal("url-shortener", 20, "The domain is a URL-shortening service that hides the destination.")
    if len(host.split(".")) >= 5:
        add_signal("deep-subdomains", 10, "The hostname has an unusually large number of subdomains.")
    if SUSPICIOUS_TERMS.search(f"{host}{parsed.path}"):
        add_signal(
            "sensitive-action-terms",
            15,
            "The hostname or path contains terms commonly used in account or credential lures.",
        )

    risk_score = min(100, sum(int(item["weight"]) for item in signals))
    display_host = f"[{host}]" if ":" in host else host
    if parsed.port is not None:
        display_host = f"{display_host}:{parsed.port}"
    sanitized_url = urlunsplit((parsed.scheme.casefold(), display_host, "/", "", ""))
    return {
        "url": sanitized_url,
        "host": host,
        "status": "suspicious" if risk_score >= 40 else "unverified",
        "risk_score": risk_score,
        "findings": signals,
        "opened": False,
        "network_contacted": False,
        "warning": (
            "This is a local heuristic check, not a complete reputation lookup. "
            "GuardSnitch did not open or contact the link; an unverified result is not proof of safety."
        ),
    }
